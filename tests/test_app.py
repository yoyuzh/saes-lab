import http.client
import json
import threading
import unittest

from app import create_server, dispatch


class ServiceTests(unittest.TestCase):
    def test_exchange_vectors_detect_mismatch(self):
        vectors = [{'plaintext': 'D728', 'key': '4AF5', 'ciphertext': '24EC'},
                   {'plaintext': 'D728', 'key': '4AF5', 'ciphertext': '0000'}]
        result = dispatch('/api/cross', {'vectors': vectors})
        self.assertEqual(result['passed'], 1)
        self.assertFalse(result['rows'][1]['passed'])
        for invalid in ([], [None], 'bad'):
            with self.assertRaises(ValueError):
                dispatch('/api/cross', {'vectors': invalid})

    def test_reject_invalid_cipher_representations(self):
        for representation, data in [('escaped', '[]'), ('escaped', '"\\u4f60"'),
                                     ('escaped', 'bad'), ('latin1', '你好'),
                                     ('latin1', 'a'), ('unknown', '0000')]:
            with self.subTest(representation=representation, data=data), self.assertRaises(ValueError):
                dispatch('/api/text', {'action':'decrypt', 'data':data, 'representation':representation, 'key':'2D55'})
        with self.assertRaises(ValueError):
            dispatch('/api/text', {'action':'encrypt','data':'A'*8193,'key':'2D55'})

    def test_binary_block_and_trace(self):
        result = dispatch('/api/block', {'action': 'encrypt', 'format': 'bin',
                         'data': '1101011100101000', 'key': '0100101011110101'})
        self.assertEqual(result['hex'], '24EC')
        self.assertEqual(result['binary'], '0010010011101100')
        self.assertEqual(result['round_keys'], ['4AF5', 'DD28', '87AF'])

    def test_text_and_latin1_cipher(self):
        result = dispatch('/api/text', {'action': 'encrypt', 'data': 'Hello', 'key': '2D55'})
        for representation, data in [('hex', result['hex']), ('latin1', result['latin1']), ('escaped', result['escaped'])]:
            restored = dispatch('/api/text', {'action': 'decrypt', 'data': data,
                               'representation': representation, 'key': '2D55'})
            self.assertEqual(restored['text'], 'Hello')
        with self.assertRaises(ValueError):
            dispatch('/api/text', {'action': 'encrypt', 'data': '你好', 'key': '2D55'})

    def test_maximum_messages_remain_decryptable(self):
        for path in ('/api/text', '/api/cbc'):
            payload = {'action': 'encrypt', 'data': 'A' * 8192, 'key': '2D55', 'iv': '1234'}
            result = dispatch(path, payload)
            for representation in ('hex', 'escaped'):
                restored = dispatch(path, {**payload, 'action': 'decrypt', 'representation': representation,
                                          'data': result[representation]})
                self.assertEqual(restored['text'], payload['data'])

    def test_byte_characters_preserve_carriage_return(self):
        cipher = dispatch('/api/text', {'action': 'encrypt', 'data': ' o', 'key': '2D55'})
        self.assertEqual(cipher['hex'], '0D2523DF')
        restored = dispatch('/api/text', {'action': 'decrypt', 'data': cipher['escaped'], 'key': '2D55',
                                         'representation': 'escaped'})
        self.assertEqual(restored['text'], ' o')

    def test_multiple_modes_and_demo(self):
        for mode, key in [('double', '1234ABCD'), ('triple32', '1234ABCD'), ('triple48', '1234ABCD5678')]:
            cipher = dispatch('/api/multiple', {'action': 'encrypt', 'mode': mode, 'data': 'D728', 'key': key})
            plain = dispatch('/api/multiple', {'action': 'decrypt', 'mode': mode, 'data': cipher['hex'], 'key': key})
            self.assertEqual(plain['hex'], 'D728')
        pairs = dispatch('/api/pairs', {'key': 'F123FE98'})['pairs']
        recovered = dispatch('/api/mitm', {'pairs': pairs})
        self.assertIn('F123FE98', recovered['keys'])

    def test_cbc_random_iv_and_tamper(self):
        cipher = dispatch('/api/cbc', {'action': 'encrypt', 'data': 'ABCDEFGH', 'key': '2D55', 'iv': ''})
        self.assertEqual(len(cipher['iv']), 4)
        plain = dispatch('/api/cbc', {'action': 'decrypt', 'data': cipher['hex'], 'key': '2D55', 'iv': cipher['iv']})
        self.assertEqual(plain['text'], 'ABCDEFGH')
        result = dispatch('/api/tamper', {'data': cipher['hex'], 'key': '2D55', 'iv': cipher['iv'],
                          'index': 0, 'change': '0001', 'operation': 'xor'})
        self.assertTrue(result['blocks'][0]['changed'])
        self.assertEqual(result['blocks'][1]['xor'], '0001')
        self.assertFalse(result['blocks'][2]['changed'])
        replaced = dispatch('/api/tamper', {'data': cipher['hex'], 'key': '2D55', 'iv': cipher['iv'],
                            'index': 0, 'change': '0000', 'operation': 'replace'})
        self.assertEqual(replaced['modified_cipher'][:4], '0000')

    def test_rejects_malformed_requests(self):
        cases = [('/api/block', {}), ('/api/block', {'action':'oops'}),
                 ('/api/multiple', {'action':'encrypt','data':'0000','key':'1234','mode':'double'}),
                 ('/api/text', {'action':'decrypt','data':'abc','key':'0000'}),
                 ('/api/mitm', {'pairs': []}), ('/api/mitm', {'pairs': ['bad']}),
                 ('/api/cbc', {'action':'decrypt','data':'0000','key':'0000','iv':''}),
                 ('/api/tamper', {'data':'0000','key':'0000','iv':'0000','index':-1,'change':'0001'}),
                 ('/api/tamper', {'data':'0000','key':'0000','iv':'0000','index':True,'change':'0001'}),
                 ('/api/tamper', {'data':'0000','key':'0000','iv':'0000','index':0,'change':'0001','operation':'oops'}),
                 ('/api/block', {'action':'encrypt','data':123,'key':'0000'}),
                 ('/api/text', {'action':'encrypt','data':[],'key':'0000'}),
                 ('/api/multiple', {'action':'encrypt','mode':[], 'key':'12345678','data':'0000'})]
        for path, payload in cases:
            with self.subTest(path=path, payload=payload), self.assertRaises(ValueError):
                dispatch(path, payload)


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = create_server(0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = response.status, response.read(), dict(response.getheaders())
        connection.close()
        return result

    def test_real_http_assets_and_encrypt(self):
        for path in ('/', '/app.js', '/style.css', '/vectors.json'):
            status, body, headers = self.request('GET', path)
            self.assertEqual(status, 200)
            self.assertTrue(body)
            self.assertIn('Content-Security-Policy', headers)
        status, body, _ = self.request('POST', '/api/block', json.dumps({'action':'encrypt', 'data':'D728', 'key':'4AF5'}),
                                       {'Content-Type':'application/json'})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['hex'], '24EC')

    def test_bad_json_size_origin_and_paths(self):
        for body in ('{', '[]', 'null', '"text"'):
            self.assertEqual(self.request('POST','/api/block',body,{'Content-Type':'application/json'})[0],400)
        self.assertEqual(self.request('POST','/api/block','{}',{'Content-Type':'text/plain'})[0],415)
        self.assertEqual(self.request('POST','/api/block','x'*131073,{'Content-Type':'application/json'})[0],413)
        self.assertEqual(self.request('POST','/api/block','{}',{'Content-Type':'application/json', 'Origin':'https://evil.example'})[0],403)
        self.assertEqual(self.request('GET','/',headers={'Host':'evil.example'})[0],403)
        for path in ('/../saes.py', '/.serena/project.yml', '/not-found'):
            self.assertEqual(self.request('GET',path)[0],404)
        self.assertEqual(self.request('POST','/api/nope','{}',{'Content-Type':'application/json'})[0],404)


if __name__ == '__main__':
    unittest.main()
