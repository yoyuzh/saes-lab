"""Local GUI server for the S-AES course laboratory. Python 3.10+, stdlib only."""

import argparse
import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from saes import (cbc_decrypt, cbc_encrypt, decrypt_bytes, double_decrypt,
                  double_encrypt, encrypt_bytes, expand_key, meet_in_the_middle,
                  parse_word, trace_block, triple_decrypt, triple_encrypt,
                  unpad_bytes)

STATIC = Path(__file__).resolve().parent / 'static'
ATTACK_LOCK = threading.Lock()
MAX_PLAINTEXT_BYTES = 8192
MAX_CIPHERTEXT_BYTES = MAX_PLAINTEXT_BYTES + 2
MAX_REQUEST_BYTES = 128 * 1024


def string_field(payload: dict, name: str, default: str = '', *, max_length: int = 8192) -> str:
    value = payload.get(name, default)
    if not isinstance(value, str):
        raise ValueError(f'{name} 必须是字符串')
    if len(value) > max_length:
        raise ValueError(f'{name} 最多允许 {max_length} 个字符')
    return value


def action_field(payload: dict) -> str:
    action = string_field(payload, 'action')
    if action not in ('encrypt', 'decrypt'):
        raise ValueError('action 必须为 encrypt 或 decrypt')
    return action


def key_parts(payload: dict, count: int) -> list[int]:
    fmt = string_field(payload, 'format', 'hex')
    text = ''.join(string_field(payload, 'key').split())
    width = 16 if fmt == 'bin' else 4
    if len(text) != count * width:
        raise ValueError(f'该模式需要 {count * 16} bits 密钥，即 {count * width} 位{fmt}字符')
    return [parse_word(text[i:i + width], fmt) for i in range(0, len(text), width)]


def cipher_bytes(payload: dict) -> bytes:
    data = string_field(payload, 'data', max_length=6 * MAX_CIPHERTEXT_BYTES + 2)
    representation = string_field(payload, 'representation', 'hex')
    if representation in ('latin1', 'escaped'):
        if representation == 'escaped':
            try:
                data = json.loads(data)
            except ValueError as error:
                raise ValueError('字节字符转义输入必须是完整 JSON 字符串，包含双引号') from error
            if not isinstance(data, str):
                raise ValueError('字节字符转义输入必须是 JSON 字符串')
        try:
            result = data.encode('latin1')
        except UnicodeEncodeError as error:
            raise ValueError('密文字符必须在 Latin-1 字节范围内') from error
    elif representation == 'hex':
        compact = ''.join(data.split())
        if not compact or len(compact) % 4 or any(c not in '0123456789abcdefABCDEF' for c in compact):
            raise ValueError('密文必须为完整的 16-bit 分组，每组 4 位十六进制字符')
        result = bytes.fromhex(compact)
    else:
        raise ValueError('密文格式必须是 hex、escaped 或 latin1')
    if not result or len(result) % 2:
        raise ValueError('密文必须非空，且长度是 2 字节的整数倍')
    if len(result) > MAX_CIPHERTEXT_BYTES:
        raise ValueError(f'密文最多允许 {MAX_CIPHERTEXT_BYTES} 字节')
    return result


def ascii_bytes(payload: dict) -> bytes:
    try:
        return string_field(payload, 'data').encode('ascii')
    except UnicodeEncodeError as error:
        raise ValueError('本实验的字符串输入采用 ASCII，请使用英文、数字或 ASCII 符号') from error


def byte_result(data: bytes) -> dict:
    return {'hex': data.hex().upper(), 'latin1': data.decode('latin1'),
            'escaped': json.dumps(data.decode('latin1'), ensure_ascii=True),
            'blocks': [data[i:i + 2].hex().upper() for i in range(0, len(data), 2)],
            'byte_length': len(data)}


def dispatch(path: str, payload: dict) -> dict:
    """Pure request-to-result layer, shared by real HTTP and automated tests."""
    if not isinstance(payload, dict):
        raise ValueError('请求 JSON 必须是对象')
    if path == '/api/iv':
        return {'iv': f'{secrets.randbits(16):04X}'}
    if path == '/api/block':
        decrypt = action_field(payload) == 'decrypt'
        fmt = string_field(payload, 'format', 'hex')
        value = parse_word(string_field(payload, 'data'), fmt)
        key = parse_word(string_field(payload, 'key'), fmt)
        trace = trace_block(value, key, decrypt)
        return {'hex': trace[-1]['value'], 'binary': trace[-1]['binary'], 'trace': trace,
                'round_keys': [f'{word:04X}' for word in expand_key(key)]}
    if path == '/api/cross':
        from saes import decrypt_block, encrypt_block
        vectors = payload.get('vectors')
        if not isinstance(vectors, list) or not 1 <= len(vectors) <= 100:
            raise ValueError('请提供 1 至 100 组测试向量')
        rows = []
        for vector in vectors:
            if not isinstance(vector, dict):
                raise ValueError('每组向量必须包含 plaintext、key、ciphertext')
            plain = parse_word(string_field(vector, 'plaintext'))
            key = parse_word(string_field(vector, 'key'))
            expected = parse_word(string_field(vector, 'ciphertext'))
            actual = encrypt_block(plain, key)
            restored = decrypt_block(expected, key)
            rows.append({'plaintext': f'{plain:04X}', 'key': f'{key:04X}',
                         'expected': f'{expected:04X}', 'actual': f'{actual:04X}',
                         'restored': f'{restored:04X}', 'passed': actual == expected and restored == plain})
        return {'rows': rows, 'passed': sum(row['passed'] for row in rows), 'total': len(rows)}
    if path == '/api/text':
        action = action_field(payload)
        key = parse_word(string_field(payload, 'key'))
        if action == 'encrypt':
            return byte_result(encrypt_bytes(ascii_bytes(payload), key))
        plain = decrypt_bytes(cipher_bytes(payload), key)
        try:
            text = plain.decode('ascii')
        except UnicodeDecodeError as error:
            raise ValueError('解密结果不是 ASCII，请核对密钥与密文') from error
        return {**byte_result(plain), 'text': text}
    if path == '/api/multiple':
        action = action_field(payload)
        mode = string_field(payload, 'mode')
        if mode not in ('double', 'triple32', 'triple48'):
            raise ValueError('请选择 double、triple32 或 triple48 模式')
        keys = key_parts(payload, 3 if mode == 'triple48' else 2)
        value = parse_word(string_field(payload, 'data'), string_field(payload, 'format', 'hex'))
        if mode == 'double':
            operation = double_decrypt if action == 'decrypt' else double_encrypt
        else:
            operation = triple_decrypt if action == 'decrypt' else triple_encrypt
        result = operation(value, *keys)
        return {'hex': f'{result:04X}', 'binary': f'{result:016b}',
                'keys': [f'{key:04X}' for key in keys], 'mode': mode}
    if path == '/api/pairs':
        keys = key_parts(payload, 2)
        return {'pairs': [{'plaintext': f'{p:04X}', 'ciphertext': f'{double_encrypt(p, *keys):04X}'}
                          for p in (0xD728, 0x1234, 0xFFFF)]}
    if path == '/api/mitm':
        pairs = payload.get('pairs')
        if not isinstance(pairs, list) or not 1 <= len(pairs) <= 8:
            raise ValueError('请提供 1 至 8 组明密文对')
        if any(not isinstance(pair, dict) for pair in pairs):
            raise ValueError('每组明密文对必须包含 plaintext、ciphertext')
        parsed = [(parse_word(string_field(pair, 'plaintext')), parse_word(string_field(pair, 'ciphertext')))
                  for pair in pairs]
        if not ATTACK_LOCK.acquire(blocking=False):
            raise ValueError('已有中间相遇攻击正在运行，请稍后重试')
        try:
            result = meet_in_the_middle(parsed)
        finally:
            ATTACK_LOCK.release()
        return {**result, 'keys': [f'{first:04X}{second:04X}' for first, second in result['keys']],
                'candidate_count': len(result['keys'])}
    if path == '/api/cbc':
        action = action_field(payload)
        key = parse_word(string_field(payload, 'key'))
        iv_text = string_field(payload, 'iv')
        iv = secrets.randbits(16) if action == 'encrypt' and not iv_text.strip() else parse_word(iv_text)
        if action == 'encrypt':
            return {**byte_result(cbc_encrypt(ascii_bytes(payload), key, iv)), 'iv': f'{iv:04X}'}
        plain = cbc_decrypt(cipher_bytes(payload), key, iv)
        try:
            text = plain.decode('ascii')
        except UnicodeDecodeError as error:
            raise ValueError('解密结果不是 ASCII，请核对密钥、IV 与密文') from error
        return {**byte_result(plain), 'text': text, 'iv': f'{iv:04X}'}
    if path == '/api/tamper':
        key, iv = parse_word(string_field(payload, 'key')), parse_word(string_field(payload, 'iv'))
        original_cipher = cipher_bytes(payload)
        index = payload.get('index')
        if type(index) is not int or not 0 <= index < len(original_cipher) // 2:
            raise ValueError('分组下标从 0 开始，必须位于现有密文分组范围内')
        change = parse_word(string_field(payload, 'change'))
        operation = string_field(payload, 'operation', 'xor')
        if operation not in ('xor', 'replace'):
            raise ValueError('篡改方式必须是 xor 或 replace')
        modified = bytearray(original_cipher)
        old_block = int.from_bytes(modified[index * 2:index * 2 + 2], 'big')
        modified[index * 2:index * 2 + 2] = (old_block ^ change if operation == 'xor' else change).to_bytes(2, 'big')
        original = cbc_decrypt(original_cipher, key, iv, unpad=False)
        changed = cbc_decrypt(bytes(modified), key, iv, unpad=False)
        blocks = []
        for offset in range(0, len(original), 2):
            first, second = original[offset:offset + 2], changed[offset:offset + 2]
            blocks.append({'index': offset // 2, 'before': first.hex().upper(), 'after': second.hex().upper(),
                           'before_text': json.dumps(first.decode('latin1'), ensure_ascii=True),
                           'after_text': json.dumps(second.decode('latin1'), ensure_ascii=True),
                           'xor': f'{int.from_bytes(first, "big") ^ int.from_bytes(second, "big"):04X}',
                           'changed': first != second})
        try:
            unpad_bytes(changed)
            padding_valid = True
        except ValueError:
            padding_valid = False
        return {'original_cipher': original_cipher.hex().upper(), 'modified_cipher': modified.hex().upper(),
                'blocks': blocks, 'padding_valid': padding_valid,
                'original_plain': byte_result(original)['escaped'], 'modified_plain': byte_result(changed)['escaped']}
    raise KeyError(path)


class LabHandler(BaseHTTPRequestHandler):
    """Serve only fixed assets. Source files and directories are never exposed."""

    def log_message(self, format, *args):
        # Do not log plaintext, keys, request bodies or access-bearing URLs.
        return

    def send_payload(self, status: int, data: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, status: int, data: dict) -> None:
        self.send_payload(status, json.dumps(data, ensure_ascii=True).encode('utf8'), 'application/json; charset=utf-8')

    def local_request(self) -> bool:
        port = self.server.server_address[1]
        hosts = (f'127.0.0.1:{port}', f'localhost:{port}')
        origin = self.headers.get('Origin')
        if self.headers.get('Host') not in hosts or (origin is not None and origin not in tuple('http://' + host for host in hosts)):
            self.send_json(403, {'error': '仅允许当前本地页面访问'})
            return False
        return True

    def do_GET(self) -> None:
        if not self.local_request():
            return
        assets = {'/': ('index.html', 'text/html; charset=utf-8'),
                  '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                  '/style.css': ('style.css', 'text/css; charset=utf-8'),
                  '/vectors.json': ('vectors.json', 'application/json; charset=utf-8')}
        asset = assets.get(self.path)
        if asset is None:
            self.send_json(404, {'error': '页面不存在'})
            return
        self.send_payload(200, (STATIC / asset[0]).read_bytes(), asset[1])

    def do_POST(self) -> None:
        if not self.local_request():
            return
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
            self.send_json(415, {'error': '请使用 application/json'})
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            self.send_json(400, {'error': 'Content-Length 无效'})
            return
        if not 0 < length <= MAX_REQUEST_BYTES:
            self.send_json(413, {'error': '请求必须非空且不超过 128 KiB'})
            return
        try:
            payload = json.loads(self.rfile.read(length))
            result = dispatch(self.path, payload)
        except (ValueError, UnicodeError) as error:
            self.send_json(400, {'error': str(error)})
        except KeyError:
            self.send_json(404, {'error': '接口不存在'})
        else:
            self.send_json(200, result)


def create_server(port: int = 8765) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(('127.0.0.1', port), LabHandler)
    server.daemon_threads = True
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description='S-AES 本地图形实验室')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    server = create_server(args.port)
    address = f'http://127.0.0.1:{server.server_address[1]}'
    print(f'S-AES 实验室已启动：{address}', flush=True)
    print('按 Ctrl+C 退出。所有计算均在本机完成。', flush=True)
    if not args.no_browser:
        webbrowser.open(address)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
