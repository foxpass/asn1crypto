# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest

from asn1crypto import parser

from ._unittest_compat import patch

patch()


class ParserTests(unittest.TestCase):

    def test_parser(self):
        result = parser.parse(b'\x02\x01\x00')
        self.assertIsInstance(result, tuple)
        self.assertEqual(0, result[0])
        self.assertEqual(0, result[1])
        self.assertEqual(2, result[2])
        self.assertEqual(b'\x02\x01', result[3])
        self.assertEqual(b'\x00', result[4])
        self.assertEqual(b'', result[5])

    def test_parse_explicit_encrypted_content(self):
        # ref: https://github.com/wbond/asn1crypto/issues/264
        data = b'0\x82\x03\xf6\x06\t*\x86H\x86\xf7\r\x01\x07\x010\x11\x06\x05+\x0e\x03\x02\x07\x04\x08\x01\xd2}\xecl3\x98\x0b\xa0\x82\x03\xd4\x04\x82\x03\xd0\xed\xc8\x0cO\x89n!\x880\xad\xb3R\x0c\x16\x92\xc2\xca\xc4\x96\xc5u\x1d\xa0X\xd2\x13H\x9aM#\x9a\xd8\x1e\x88\xc9\x95-\xf8`\xf5\xa6\x1bP\xf9\x91\xb3\xe3\xd8g\xaa*P\x1e\x0cE{%\x11.\xb0\x19;\xea\xa7\x06\xae\xb9\xf2W\x7fx\x88FB>\xfa\x81\x80/$AGjM\x82\xe5\x0cI\xcc\x16c\x14}3*D87\xb9\xf5a\x04\x1c\xd6\xa6qDp\xe1\x1a\xe9\xb4R\xe9\xc5\xd7p\n\xdc7\x05\xbe\xcf\x88`\xdd\x92\xf7\xb1\x8aC\xd8\xab/~\xe6F\x02nTu\x0b\xf4\xfa\x13K\xa4\x10\xc5\x8e&\xe9H\xaf\xe2`\xf2\xe4zx|\x9a\xf3\xc5\x92C~\x90\xd7\x10\xc5\x91\x83Je2s\xea?\x83xC\x9a\xecB\xdb\xc4\xc2\xf0\x1aG\x05\n\x10\x949D\xfdLe\xbc`\x19\x81a\xd9v,T\xb4\xf9u\xd9\x8b Bh.\xed\x15\x7f\xdd\xec\x05\x95F\x81\xc5\xe9_\x91\xc1\x1c\x13\xff\x16+\xc6\xe7\x08oJ\x80?\xf48\x8b\x16\x07\x12$\x19\xd7`\n;\x07F\xb5E{\x19\x9dk\'\x89T;kr<\x13\xf1\x02&\x18LId\xf6\x0e\x0eEG\xcdT"K\xbbQ\xa6\x9f\xd6\xc8\x83\xe4\xd1\xbaD$\xe2\xb1\xdc\xae\xb6\x14\xbf\xa1\xd3\xe6\xc9\xd1\x15yY\x1a\xccc\xab_?c\x11\xf8\xca\xb4\x81o\x91\x1c\xa5I\xbeq\xacvI\xb3;\x03\xe0i\xff\xf6\x0f\x99\r\x16N\x0f\x1d\x11\x91\x8a\x0b\xfb\x83\xea)y\xf1A1\x19\xa0-s\x07\t\xa3\x0c\x18!\x8e\x04m(,;b\x8bS\xa7\xbd\xfbp\xeb\xc6m0\x02\xa2/\xcc&D\xcf\xfd#\xf0\x1e=\x04\xa5=\xe9P&\x95l\xdfl\xb6-=y9\x1bH\xfc\xbd\xd1p\x0f\xd3U\xe0C\xf7\xbd\xc8\xf8o\x87\xe5zM\xa6\x1a\x9c\x80\xd9\xd2\x11\xfb\x92\xb3\xd1\t\x014\xa9[D\x86\xea/\x13\xfe>1$\xe9\xd7T\x80B\x1d+\xb6[\xd6\xb1\xcb]\xd9<X\xc8\xe9\xb0\x84\x96\x87\xa0\x9a%\xd5\xaa\x05\xf8X\xbe\x04\x1d\x81\xbc$\xb3_\xc6\xa2\xe6\x11\x918\x88?M\xd7\xa6\x1b}\xd7J\x15\xf8`ks\x08&\xb6Q\xc3\x9a{\xb8o\xe1\x9f\\\x17\xdd\x17\x0e|<\x05\x89\x07\xd3\xb9mK sb\xb4$LjuQ\xe2\xdeZ#v\xfd~y^\xc4\x12`\xae\xa9\xed\xf3\xc9\xbaE\xdbM\xe0\xef\xd6\xc6\x18\x8b\xf3@\xbdb\x9e\xf1gne\xb8\x8b\x90/\xe8\x80\x07\x1d\xfe\x1d\xd8\xae]\x8b\xfb\x12\xb3\x13\xf8*bD\x87\x14\xe5\x0e^\xd2Wq_E\xb8qQ\x8c\xb7m\x85\x81c\r\x89r\xd6\x10\x91\x99\x91\xd8\x0bY\xd6$\xa2\x18\x0c\xa9]\xa8|\x18Cs0*\x9d_\xb3)\xbe\xc9\xa8\x00$\xa0\xda\x0e\x1d\x1f_\x8b\xb6\x1f@X)\x91"8\x89IK\xa5\xbc\xae\xbd;\x86\xf3&\x95It\xb7\xf0\x974)\xa3 \xe7\x1f\xf0\x0b9\xf2\r1u\x07\x92\x80\xe4\xda^\xaf\xc7\xc3\x910\xa17\xda\xe2\xa4\xf4\xd1\x12\xb0ym\x04\x04.u\xe9\xc9\x98\xbeW4\xa2\x9f\xff;\x9b\x82p\xaf\x8f\xaa\nDNL/C\x162q*p\xfd\xe2\xa1\xf8\xed\xd4\x81#\xf8Q\t\x8f*\x1d\xfb\xcd6x2\xb1%\x8f\x0b!\xbb{\x88_\xedO<\x94-5D\xd6\xc9\xd4B\xa4)\xdep\x8c\x01\xe5\xa1n\x97\\\x16\xc4\x1a\x11Q\x8c\x83\xaf\x911\x13X\xd4\x93\xef\x01\xb4\xef\x85N%\xaa\xa7\x8d\xa6!\\\xb2\xbbY\x80\xd8\xe2*i6\xeb\x89\x86\x84v\x85~\xdej\xba,x_\x13\xd7\xe7\xc4\xb1\xc5P\x0e\x9b\xf3\x92\x89\x84\xdbx\xbf\xe6\x05\x1cl\xcc\xec\x19H\xea\x11\xd8D\x08\xac>\x97\xd0\xebI\xeb\x9d\x1a\xfb\x1b\xfa^\x1f\xcc\t*T\xed\xbd\x91\xabxV\xec\xaf\xf2\x91\x0es\xc9\xeaw\xb2\x1f\xf9\xe1\x0b\xc2\x911\xc0\x7f\x9f\xc10\x03\xf7c\x1a\x9b6\x82\xef\xc5\xea\xd2[S\xb0d1\xec)\xf0U\xf8\x08\x92\t8\xdf\xcf9\xb6>\xdb\xca\xd6\x0b\r\xfc\xb4=j'
        parser.parse(data)

    def test_peek(self):
        self.assertEqual(3, parser.peek(b'\x02\x01\x00\x00'))

    def test_parse_indef_nested(self):
        data = b'\x24\x80\x24\x80\x24\x80\x04\x00\x00\x00\x00\x00\x00\x00'
        result = parser.parse(data)
        self.assertEqual(b'\x24\x80', result[3])
        self.assertEqual(b'\x24\x80\x24\x80\x04\x00\x00\x00\x00\x00', result[4])
        self.assertEqual(b'\x00\x00', result[5])

    def test_parser_strict(self):
        with self.assertRaises(ValueError):
            parser.parse(b'\x02\x01\x00\x00', strict=True)

    def test_emit(self):
        self.assertEqual(b'\x02\x01\x00', parser.emit(0, 0, 2, b'\x00'))

    def test_emit_type_errors(self):
        with self.assertRaises(TypeError):
            parser.emit('0', 0, 2, b'\x00')

        with self.assertRaises(ValueError):
            parser.emit(-1, 0, 2, b'\x00')

        with self.assertRaises(TypeError):
            parser.emit(0, '0', 2, b'\x00')

        with self.assertRaises(ValueError):
            parser.emit(0, 5, 2, b'\x00')

        with self.assertRaises(TypeError):
            parser.emit(0, 0, '2', b'\x00')

        with self.assertRaises(ValueError):
            parser.emit(0, 0, -1, b'\x00')

        with self.assertRaises(TypeError):
            parser.emit(0, 0, 2, '\x00')

    def test_parser_large_tag(self):
        # One extra byte
        result = parser.parse(b'\x7f\x49\x00')
        self.assertEqual(1, result[0])
        self.assertEqual(1, result[1])
        self.assertEqual(73, result[2])
        self.assertEqual(b'\x7f\x49\x00', result[3])
        self.assertEqual(b'', result[4])
        self.assertEqual(b'', result[5])

        # Two extra bytes
        result = parser.parse(b'\x7f\x81\x49\x00')
        self.assertEqual(1, result[0])
        self.assertEqual(1, result[1])
        self.assertEqual(201, result[2])
        self.assertEqual(b'\x7f\x81\x49\x00', result[3])
        self.assertEqual(b'', result[4])
        self.assertEqual(b'', result[5])

        # Three extra bytes
        result = parser.parse(b'\x7f\x81\x80\x00\x00')
        self.assertEqual(1, result[0])
        self.assertEqual(1, result[1])
        self.assertEqual(16384, result[2])
        self.assertEqual(b'\x7f\x81\x80\x00\x00', result[3])
        self.assertEqual(b'', result[4])
        self.assertEqual(b'', result[5])

    def test_parser_insufficient_data(self):
        # No tag
        with self.assertRaises(ValueError):
            parser.parse(b'')

        # Long-form tag is truncated
        with self.assertRaises(ValueError):
            parser.parse(b'\xbf')
        with self.assertRaises(ValueError):
            parser.parse(b'\xbf\x81')

        # No length
        with self.assertRaises(ValueError):
            parser.parse(b'\x04')
        with self.assertRaises(ValueError):
            parser.parse(b'\xbf\x1f')

        # Long-form length is truncated
        with self.assertRaises(ValueError):
            parser.parse(b'\x04\x81')
        with self.assertRaises(ValueError):
            parser.parse(b'\x04\x82\x01')

        # Contents are truncated
        with self.assertRaises(ValueError):
            parser.parse(b'\x04\x02\x00')
        with self.assertRaises(ValueError):
            parser.parse(b'\x04\x81\x80' + (b'\x00' * 127))

    def test_parser_bounded_recursion(self):
        with self.assertRaises(ValueError):
            parser.parse(b'\x30\x80' * 1000)

    def test_parser_indef_missing_eoc(self):
        with self.assertRaises(ValueError):
            parser.parse(b'\x30\x80')
        with self.assertRaises(ValueError):
            parser.parse(b'\x30\x80\x30\x80\x00\x00')

    def test_parser_indef_long_zero_length(self):
        # The parser should not confuse the long-form zero length for an EOC.
        result = parser.parse(b'\x30\x80\x30\x82\x00\x00\x00\x00')
        self.assertIsInstance(result, tuple)
        self.assertEqual(0, result[0])
        self.assertEqual(1, result[1])
        self.assertEqual(16, result[2])
        self.assertEqual(b'\x30\x80', result[3])
        self.assertEqual(b'\x30\x82\x00\x00', result[4])
        self.assertEqual(b'\x00\x00', result[5])

    def test_parser_indef_primitive(self):
        with self.assertRaises(ValueError):
            parser.parse(b'\x04\x80\x00\x00')

    def test_parse_nonminimal_tag(self):
        with self.assertRaises(ValueError):
            # Should be b'\x04\x00'
            parser.parse(b'\x1f\x04\x00')

        with self.assertRaises(ValueError):
            # Should be b'\xbf\x1f\x00'
            parser.parse(b'\xbf\x80\x1f\x00')
