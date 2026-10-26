import random
import unittest

from saes import (cbc_decrypt, cbc_encrypt, decrypt_block, decrypt_bytes,
                  double_decrypt, double_encrypt, encrypt_block, encrypt_bytes,
                  expand_key, gf_multiply, meet_in_the_middle, mix_columns,
                  parse_word, shift_rows, substitute, trace_block,
                  triple_decrypt, triple_encrypt)
from tests.reference_cipher import reference_encrypt


class AppendixTests(unittest.TestCase):
    def test_appendix_key_expansion(self):
        self.assertEqual(expand_key(0x2D55), (0x2D55, 0xBCE9, 0xA34A))

    def test_appendix_transform_examples(self):
        self.assertEqual(substitute(0x8A1C), 0x604C)
        self.assertEqual(shift_rows(0x604C), 0x6C40)
        self.assertEqual(mix_columns(0x6C40), 0x3743)
        self.assertEqual(gf_multiply(4, 12), 5)

    def test_canonical_known_answer(self):
        self.assertEqual(encrypt_block(0xD728, 0x4AF5), 0x24EC)
        self.assertEqual(decrypt_block(0x24EC, 0x4AF5), 0xD728)

    def test_reference_cross_check(self):
        rng = random.Random(20261026)
        for _ in range(512):
            plaintext, key = rng.randrange(65536), rng.randrange(65536)
            cipher = reference_encrypt(plaintext, key)
            self.assertEqual(encrypt_block(plaintext, key), cipher)
            self.assertEqual(decrypt_block(cipher, key), plaintext)

    def test_entire_plaintext_space(self):
        for plaintext in range(65536):
            self.assertEqual(decrypt_block(encrypt_block(plaintext, 0x2D55), 0x2D55), plaintext)

    def test_inverse_transforms(self):
        for value in range(65536):
            self.assertEqual(substitute(substitute(value), inverse=True), value)
            self.assertEqual(mix_columns(mix_columns(value), inverse=True), value)

    def test_trace_has_real_round_states(self):
        trace = trace_block(0xD728, 0x4AF5)
        self.assertEqual(trace[-1]['value'], '24EC')
        self.assertEqual(len(trace), 9)
        self.assertEqual(trace_block(0x24EC, 0x4AF5, decrypt=True)[-1]['value'], 'D728')

    def test_strict_validation(self):
        for value in (-1, 65536, True, '1', None, 2.0):
            with self.assertRaises(ValueError):
                encrypt_block(value, 0)
        self.assertEqual(parse_word('0010 1101 0101 0101', 'bin'), 0x2D55)
        self.assertEqual(parse_word('2d55', 'hex'), 0x2D55)
        for value, fmt in [('10', 'bin'), ('FFFFF', 'hex'), ('xxxy', 'hex'), ('2D55', 'auto')]:
            with self.assertRaises(ValueError):
                parse_word(value, fmt)


class ExtensionTests(unittest.TestCase):
    def test_ascii_roundtrip_and_padding(self):
        for data in (b'', b'A', b'AB', b'ABC', b'A\0', bytes(range(128)), bytes(range(256))):
            cipher = encrypt_bytes(data, 0x2D55)
            self.assertEqual(len(cipher) % 2, 0)
            self.assertEqual(decrypt_bytes(cipher, 0x2D55), data)
        with self.assertRaises(ValueError):
            decrypt_bytes(b'\x01', 0)
        # Construct an invalid padded final block independently of the decoder.
        bad = encrypt_block(0x4100, 0).to_bytes(2, 'big')
        with self.assertRaises(ValueError):
            decrypt_bytes(bad, 0)

    def test_double_and_both_triple_variants(self):
        plaintext, key1, key2, key3 = 0xD728, 0x1234, 0xABCD, 0x5678
        cipher = double_encrypt(plaintext, key1, key2)
        self.assertEqual(cipher, reference_encrypt(reference_encrypt(plaintext, key1), key2))
        self.assertEqual(double_decrypt(cipher, key1, key2), plaintext)
        for keys in ((key1, key2), (key1, key2, key3)):
            self.assertEqual(triple_decrypt(triple_encrypt(plaintext, *keys), *keys), plaintext)
        self.assertEqual(triple_encrypt(plaintext, key1, key1), encrypt_block(plaintext, key1))

    def test_full_keyspace_mitm_recovers_and_keeps_collisions(self):
        key1, key2 = 0xF123, 0xFE98
        pairs = [(p, double_encrypt(p, key1, key2)) for p in (0xD728, 0x1234, 0xFFFF)]
        result = meet_in_the_middle(pairs)
        self.assertIn((key1, key2), result['keys'])
        self.assertEqual(result['searched_per_side'], 65536)
        # Every collision candidate must be checked against all supplied pairs.
        for first, second in result['keys']:
            self.assertTrue(all(double_encrypt(p, first, second) == c for p, c in pairs))
        self.assertGreater(result['first_pair_matches'], 1)
        with self.assertRaises(ValueError):
            meet_in_the_middle([])

    def test_cbc_known_composition_and_iv(self):
        data, key, iv = b'ABCD', 0x2D55, 0x1234
        cipher = cbc_encrypt(data, key, iv)
        first = reference_encrypt(0x4142 ^ iv, key)
        second = reference_encrypt(0x4344 ^ first, key)
        self.assertEqual(cipher[:4], first.to_bytes(2, 'big') + second.to_bytes(2, 'big'))
        self.assertEqual(cbc_decrypt(cipher, key, iv), data)
        self.assertNotEqual(cipher, cbc_encrypt(data, key, iv ^ 1))

    def test_cbc_tamper_propagation(self):
        data, key, iv = b'ABCDEFGH', 0x2D55, 0x1234
        cipher = cbc_encrypt(data, key, iv)
        modified = bytearray(cipher)
        modified[1] ^= 1
        original = cbc_decrypt(cipher, key, iv, unpad=False)
        changed = cbc_decrypt(bytes(modified), key, iv, unpad=False)
        self.assertNotEqual(original[:2], changed[:2])
        self.assertEqual(int.from_bytes(original[2:4], 'big') ^ int.from_bytes(changed[2:4], 'big'), 1)
        self.assertEqual(original[4:], changed[4:])
        iv_changed = cbc_decrypt(cipher, key, iv ^ 1, unpad=False)
        self.assertEqual(int.from_bytes(iv_changed[:2], 'big') ^ int.from_bytes(original[:2], 'big'), 1)
        self.assertEqual(iv_changed[2:], original[2:])


if __name__ == '__main__':
    unittest.main()
