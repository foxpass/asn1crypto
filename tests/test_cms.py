# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os
import zlib
import sys
from datetime import datetime

from asn1crypto import cms, util
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class ClearanceTests(unittest.TestCase):

    def test_clearance_decode_bad_tagging(self):
        rfc_3281_wrong_tagging = b'\x30\x08\x80\x02\x88\x37\x81\x02\x02\x4c'
        # This test documents the fact that we can't deal with the "wrong"
        # version of Clearance in RFC 3281
        self.assertRaises(
            ValueError,
            lambda: cms.Clearance.load(rfc_3281_wrong_tagging).native
        )

    def test_clearance_decode_correct_tagging(self):
        correct_tagging = b'\x30\x08\x06\x02\x88\x37\x03\x02\x02\x4c'
        clearance_obj = cms.Clearance.load(correct_tagging)
        self.assertEqual(
            util.OrderedDict([
                ('policy_id', '2.999'),
                ('class_list', set(['secret', 'top_secret', 'unclassified'])),
                ('security_categories', None)
            ]),
            clearance_obj.native
        )


class CMSTests(unittest.TestCase):

    def test_create_content_info_data(self):
        data = cms.SignedData({
            'version': 'v1',
            'encap_content_info': {
                'content_type': 'data',
                'content': b'Hello',
            }
        })
        info = data['encap_content_info']

        self.assertEqual('v1', data['version'].native)
        self.assertEqual(
            'data',
            info['content_type'].native
        )
        self.assertEqual(
            b'Hello',
            info['content'].native
        )
        self.assertIsInstance(info, cms.ContentInfo)

    def test_create_content_info_data_v2(self):
        data = cms.SignedData({
            'version': 'v2',
            'encap_content_info': {
                'content_type': 'data',
                'content': b'Hello',
            }
        })
        info = data['encap_content_info']

        self.assertEqual('v2', data['version'].native)
        self.assertEqual(
            'data',
            info['content_type'].native
        )
        self.assertEqual(
            b'Hello',
            info['content'].native
        )
        self.assertIsInstance(info, cms.EncapsulatedContentInfo)

    def test_parse_content_info_data(self):
        with open(os.path.join(fixtures_dir, 'message.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        self.assertEqual(
            'data',
            info['content_type'].native
        )
        self.assertEqual(
            b'This is the message to encapsulate in PKCS#7/CMS\r\n',
            info['content'].native
        )

    def test_parse_content_info_compressed_data(self):
        with open(os.path.join(fixtures_dir, 'cms-compressed.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        compressed_data = info['content']

        self.assertEqual(
            'compressed_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v0',
            compressed_data['version'].native
        )
        self.assertEqual(
            'zlib',
            compressed_data['compression_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            compressed_data['compression_algorithm']['parameters'].native
        )
        self.assertEqual(
            'data',
            compressed_data['encap_content_info']['content_type'].native
        )
        self.assertEqual(
            b'\x78\x9C\x0B\xC9\xC8\x2C\x56\x00\xA2\x92\x8C\x54\x85\xDC\xD4\xE2\xE2\xC4\xF4\x54\x85\x92\x7C\x85\xD4\xBC'
            b'\xE4\xC4\x82\xE2\xD2\x9C\xC4\x92\x54\x85\xCC\x3C\x85\x00\x6F\xE7\x60\x65\x73\x7D\x67\xDF\x60\x2E\x00\xB5'
            b'\xCF\x10\x71',
            compressed_data['encap_content_info']['content'].native
        )
        self.assertEqual(
            b'This is the message to encapsulate in PKCS#7/CMS\n',
            compressed_data.decompressed
        )

    def test_parse_content_info_indefinite(self):
        with open(os.path.join(fixtures_dir, 'meca2_compressed.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        compressed_data = info['content']

        self.assertEqual(
            'compressed_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v0',
            compressed_data['version'].native
        )
        self.assertEqual(
            'zlib',
            compressed_data['compression_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            compressed_data['compression_algorithm']['parameters'].native
        )
        self.assertEqual(
            'data',
            compressed_data['encap_content_info']['content_type'].native
        )
        data = compressed_data['encap_content_info']['content'].native
        self.assertIsInstance(zlib.decompress(data), byte_cls)

    def test_parse_content_info_digested_data(self):
        with open(os.path.join(fixtures_dir, 'cms-digested.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        digested_data = info['content']

        self.assertEqual(
            'digested_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v0',
            digested_data['version'].native
        )
        self.assertEqual(
            'sha1',
            digested_data['digest_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            digested_data['digest_algorithm']['parameters'].native
        )
        self.assertEqual(
            'data',
            digested_data['encap_content_info']['content_type'].native
        )
        self.assertEqual(
            b'This is the message to encapsulate in PKCS#7/CMS\n',
            digested_data['encap_content_info']['content'].native
        )
        self.assertEqual(
            b'\x53\xC9\xDB\xC1\x6D\xDB\x34\x3B\x28\x4E\xEF\xA6\x03\x0E\x02\x64\x79\x31\xAF\xFB',
            digested_data['digest'].native
        )

    def test_parse_content_info_encrypted_data(self):
        with open(os.path.join(fixtures_dir, 'cms-encrypted.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        encrypted_data = info['content']
        encrypted_content_info = encrypted_data['encrypted_content_info']

        self.assertEqual(
            'encrypted_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v0',
            encrypted_data['version'].native
        )
        self.assertEqual(
            'data',
            encrypted_content_info['content_type'].native
        )
        self.assertEqual(
            'aes128_cbc',
            encrypted_content_info['content_encryption_algorithm']['algorithm'].native
        )
        self.assertEqual(
            'aes',
            encrypted_content_info['content_encryption_algorithm'].encryption_cipher
        )
        self.assertEqual(
            'cbc',
            encrypted_content_info['content_encryption_algorithm'].encryption_mode
        )
        self.assertEqual(
            16,
            encrypted_content_info['content_encryption_algorithm'].key_length
        )
        self.assertEqual(
            16,
            encrypted_content_info['content_encryption_algorithm'].encryption_block_size
        )
        self.assertEqual(
            b'\x1F\x34\x54\x9F\x7F\xB7\x06\xBD\x81\x57\x68\x84\x79\xB5\x2F\x6F',
            encrypted_content_info['content_encryption_algorithm']['parameters'].native
        )
        self.assertEqual(
            b'\x80\xEE\x34\x8B\xFC\x04\x69\x4F\xBE\x15\x1C\x0C\x39\x2E\xF3\xEA\x8E\xEE\x17\x0D\x39\xC7\x4B\x6C\x4B'
            b'\x13\xEF\x17\x82\x0D\xED\xBA\x6D\x2F\x3B\xAB\x4E\xEB\xF0\xDB\xD9\x6E\x1C\xC2\x3C\x1C\x4C\xFA\xF3\x98'
            b'\x9B\x89\xBD\x48\x77\x07\xE2\x6B\x71\xCF\xB7\xFF\xCE\xA5',
            encrypted_content_info['encrypted_content'].native
        )

    def test_parse_encrypted_content_apple_data(self):
        with open(os.path.join(fixtures_dir, 'explicit_encrypted_content-apple.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        eci = info['content']['encrypted_content_info']

        self.assertEqual(
            b'A*\xcedt\xce\xa4\x99\xed\x16=\x12z1\x0e\x9d\x95\x88;KQ\x91\'\xc7\xf5\x86\xc4>\xea\x81\xea\xfe\x1c\xdad\xc1\xcd-aD\x98\x9b\xb4P\x9f\xa4q=\x08%\xf6o\xc5\xb5\t]\x94i-\xba\xc1J\x05\xc8LijB\xff\x87v\xbf\x19\xeb\x8c\x18\x8eR\xc8V@\x90~\xeeP5eJv\xd5S\xd6\x15m\x99\xb99\xd5C<\x97E\xcb\x9d\xeb\xce\xcf\xc7\xc3\xf0\xcc\xf8|\xe7\xf52D\xb0b\xe0\x18\xe9=[)t\x9f\xf7m\x12\xdc6*\xb0C\x81\xbe2\xc5<$\xe9k\xd9_\xe8\x9es)\x96\xa8\xbc\xbe\xe5U=!C\xa5\x8bF\x94\xd5\xd8\xcfp\xc8\\P\xc4\x9f\xf3\xb7\xd4\xa0\x04H\xa8\xd0\xc8\xdb\xf3\xce\x96mV\xf6\xfa\xa0+g\xae\xa3\xd5C<\xf1\x1c\xcb\x90\xe3\x7f\xccz8\xe6\x13\xfdA\xa6\xc0/g3[xQw\x06x\x1a\x94\x8fM\x0f\x8eV\x86\xf3\xa9O\x1b\xbc~|\xd6\xe2!\x1f\x08\x8au\xed@BI\x19\x9e|Z\'\x04\xd3\xca]\xbc\xbd\xe0,\x8fsP|\x16\x90\xeb[\x9dz\x92.\xd8\xaf\xda\xd1\xec18\x0b\'v\xb0\xda@\'\xf0\xb5g\xb3\xfb\xad\xbe\xd8\x15\xd4aM\xf2S\x922\x8d\xad\x0enN\xd2\x9f\xd3\x0ex\xf1[\xc4\x84s\xc7{\x0c<\x86nbY\xa6X\x8fEX\xf1\xa0\xc1~A\xc0.\\\xd2i\xcd\xda4\xfa\xfb`\x98\x8a\xe1"<\x1a8h\xc1\xf77O\xa0\x87\x80\x972`uP\xdc\xf0\x89\xb7\x8cM\xe9\x07\x97W\xb7Q\x96\x1bq\xaf\xf5}\x95-x\x04\x7f\xa5"\xa0\xe39\x81\xacTW\xe9\x9c\x9a\xcd\x8e\xc8\xf1/c^\xd18Gt\x9dn\xf5\xa0\xfb\x01\xcdG\x1f\x10\x8b\xbd\x0c\x84b\xe1\xb2\x89\xa7\xd4\xado\xad731\xe9l\x0c!\xb5\x01\xdf\x00//\xdaN\x8a\x16uQ\xc4\xd2\xff\x9fu[\xb6\x00\xf9\xd8N\x7f\x9b\x94\x16h\xc6t\xf9\x04\xdc80\xb4U\x822\xf1\xaf\xc8\x07F#\xe9\xf9$q:@\xf7B\xdbc\xe5k<\xa3\xf6\r\x913\x1abv\xe4\xb8B\xaa-\xac\xb5q\x9d\xac\xb3\xc7\xe4hs\x9fZ\x8cR\xda<\x8c\x89Y\x8e\x9a\x1a\xfa\xf9t\xf5\xf0\xd58,\xce@\xf3\xbd\xf6\xc1l\xcf\xd7\x90\xedYh!\xcb\x14\x9f\xbb\xa3\xab`\xbb4\x80\x0b\x82\x8e\xdb\x89\xe9\x10\xc5[U\xec\x14\x02\xb3\xc6^\x94\x14\x95\n\xacN\xff\xaf\xac\xb5\xc3\x18;\xe3i\x8ax\x94\xab=R=\x82"@\x15\xae\xac\xccp\x92\x965\x1c\xe4\xcd\xc9M\xb0\x90Qr\x94\x1d\n#\x938\xa5(r\x9c#\x0ek\xd1\xb3\x92`\xab\xbf8K\t\x1b\xd4\x13p\x00Q4\x8fj\xef,\xb4\xbddyy\xb6<\xbb\xabW\xa1\x92\xb9w\xef\xd0I\xa2\x99\xaa\x07\xb4\x19uX\xed\n*\xbc\x08\xd5/H\x82\xcb\xea\xd3=\xf5\xc3\xc8\\\x87\xc9\xbf\xa3\xaa,Y\xcc\xd65\x06\x13\xc5\xb1k\xc1\xfd9\xb0\x91Q\xa89\xa9\xe2yC\xfb\x06\x87O\x15\xf2%\xde|\x94R\xaa\xe5\xa21\xd5_d4e7\xb6\xed\xf2\x95\xd3\xac\x85*K\xc4\x8b\xf3R}+\xb2\n\x9d\xbdj\x8c\x07\xe1 \xb7\x90Z\x85\x10*~t\x0f\xe7\x06\x0b)`\x13\xa2W[\x1e\xbc\xa0\xda\x93\x99`\x9f\x91\xf0:\x8e`\xbe\xdc\xdb\xfa6\xd2\xcd\xf2\xec\xa7n\xa8l\xec\xa9\x1e\xa3k\x8b\x08\x18\'i\xbb1u\xd6\x84M\xee\x9ch\xc3\xf5\x83\xf3\xb3\x0e\xbe\xdcK6\xe5o\xbee\x952\xbd\xa6\xab@\xa0\xcf\xaa\x14\xa0\x970\xa0;<,\xbfc\xb7F\tLK\xf2\xdb\x90\xee\x8bf(\xc6\x04\x9d\x80\xc7\xd5PE_\x9e\x0c\xb1T\xd1\x8c\x1d\x83\xd4\\z\xdfZ\xef\x95z\xcb\xda)T\xadRi\x80\xe2e\xfb\xde\\\xaa\xdc\x97Md\x01\nS\x94\x8e2l\xc2\xff(R\xe0\xa4\x92o\x15?J>\xbb\xf4\xbc\x93i+\xd9\x8bH\x9a\xfc\x92\xa0\xcf\xd5Z\xa0\xe0g\x83\x84\x14;\x0e\x88\xb4\xa1A{\xc5A\x0e$gX\xf2\xdf\x94\xa9r>\x05t=\xab\xdd\x93\xa4\xf1\xac0\x19J\xcc\xd2\xfe\xe2\xe3K\xc6\x04\x97\x9cg\xbb\xe24\xfb\'\xc7y2\xc8\x0f\x12?[\xa9\x8d{8\xaa6\xc8\xac\xd2m\xaa\x1fi>\xff4\x04=%\x8f\xd6\x9d+X\xf8\xad\xcd-\xcfx\xa4\xc3o9\xce\x10jk\xb3\xab\xe0\xea\x9df\xde\x13T\xc1G\xf7\x94\xc0\xb5\xaba\x12\x1d\xbc,\x88\x9fu\xf2\x04k\x07\xc7\xac\x1a\xe2\x80i\xf4\xb9\xb3i!\tX7\\v\xca\xcb\x0b\x95\nxg\x16\xbd9\xbbA\x90G\x14!\x97\xfb\xa08\xb0\x13z\x9fP{\xdf\xcf\x156\xab4j\xa2\xd5\xd3.\xdd+\x95\xac\x10\xad>\xa8_F,J\x16\xf7\xd0\xed\xe1a\xcav\x92\xf2Gm\xe3v\xc0Ts\x05\x94KQ\xc4/(\xd4\x9c:\x08\xe8\xf34$\x19\xb5\x91\'I\xd23\x0c&;\xbd\x97\xf9\xc3\xc6R\xc65\xc95X\xccy\xe8\xd5o\xa9d\x18I\x1eY\xc6G\x94\xce\xdf8\xd5\xcb\xd0L\xa3\xf8\xce\xfd\x8f!\xff#\x01',
            eci['encrypted_content'].native
        )

    def test_parse_encrypted_content_enveloped_data(self):
        with open(os.path.join(fixtures_dir, 'explicit_encrypted_content.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        eci = info['content']['encrypted_content_info']

        self.assertEqual(
            b'\x1c\x1e\x9c\xed\x08N\xfd?0\x07\x15F\xd7\xad\x9ee=0\xa0g\x05\x019\x97\xfdI.s@o\xd1cZ3\xd2B\x1f\xc6M\xc2\xf0\xf1\xc2\xc5\xd9il\x86h>\xef\x95q\x03\xbc\xdc\x1a\x16\x8dR\xe65\x9b\x0f\xc5\x0cEH\x1cK\xb8q9\x9f\xeaOU\xfb:\xba\xdd\x84\x8fg\x14\xf9Co%\xc3\xb4$\xba\xd9\x96\xa9\x0c\x1f\x92\n\xd1as+z\x82t\xe1\t\x95\xc3.\'\xff\xfa\x85}:\x1f\xa1\x98\xfbG\x96\xe3i\xa2\xd5\xa1\xf2\r\xf9\x0c\xa5\x18\xfcA\x0b\xdb\x88\x85\x06k+\x01\xcf(wx\xf5\xf2\x86\x97\xbc|(\x06\x82\x9f\xaay\xf9!\xbf\xf5\xec\xa8\x16\xacB\xa7\xa7\\\xf7\x00\xbb;\xc9\xab\xe7\x06-)\xe2\x01\x93}0\xa7x\xeff\x01,_:\x92.\xf5?\x11\x17Qlr\x10\xc2 \xb3\x14Tj]\x0f\xebnM$A\\\xed\xc8 \x93\xa7\xefC\xaeN\xc5\x95^HPztClDI\x8ewX\x863\xd4\t\x00\xfe\x8a\x01\xd7Y\xe3J4=]\xcf\xb8\x84\x9aX\x92\x91\x95\xf9\xaf\xd7\xec\xc3\xd4\xd5+Z\x9a\x8a\xe2j\xd3xy\x19\xa1\xd0\xaa.4\xae\xc7,\x9d\n\xec\xb4\xefw\xe4\x89r\x9d\xaaFM\x01\xafz\xad\xcdOAu\x82\xa8F\x8a\x13\xc8l\x9a{\x1e\xfb\x1d\x02\x988\xb9_\xa8w\xbf\xb6p\xde\xb1\x9b\xe4B@u;\x14\x92;\xf6\x97\x1as\xa01\xffF\xec\x86\x98f\xcc>A\x02\xa4\x1d\xd6\x8e`\x16T\x8c)Mf!]\xba\x93\xb8\xfd\xe4*\xfeAf\x97\xe8\x1c\x05P\x01P\xf5Z\x80\x82i-\x13\x92\xf7U\xb4T?\\aS\xdd\xfe3\xff\x11\x9d\xb8\xc9\xaf\xfb\x92\x90\xd63\x97S\x83!<\x8d]H\x85\t\x9b\xd22{&\x11\xe1\x0f,\xe1{\xd5"Dl=\xdd\x8a/*\xbe1\xb9\xa5\xcdr\x85A\x8f\xd41\xda\xfa\xa5s\xea\xfd\'a\xb2\x9b\x17\x02Td-\xd8\xcdK*\xfem\x14\x00\x88\xe1pw&\xfap\x98\x86\x13\x87\x8f\x8dN\xa3\x91Jm\xf4-\x07\x16Qv\xf3\x06\x18\xb79b\x08\xd7U\xfcl\x93f\xb1\xc9\xff\xabe0s\x15\xa9\xd4\x88x0G\xfaj\xe3\xc2.\xba\x8b\x07\xe5\x13y\x1f\xa5\x9f\x1ea\xcfH\xfc\xf6\xcb\xccH[\x8f\xf6x~\x81O\xc0\xe1\xf3`\x02d\x0e\x91\x01\x9f\xbe\x12\xc3\x93\xc7K\xc0\xfc\xc8\xffK\xec\xa9%\x0b\x0b\xc1\xc9NL=$\xe7pZ\xf4\xab\xcb"\xa3\xc6^\x93\xdb\xd8tO\x07\xcfZ\x03w.\x85\x98F\xa0:\xbc!an\'J\x15\xca\xf7\xcc\x06\xf8\xf6\xe0=\xc1\xd2#\x1d\x0c\xfd\x186\xce\xad?\xf1h\xc6<|:x\x1c_R\xdb\x0c\x92\xee\x1aIy\x89T\xd3\xa4>J\xf5\xbcU\x00\xbamyn@\xe9\xb9u\x9ea\xd8CH\xeb\x9c\xed.:V\xab\xcc.]\x8f\xe0\x17\x9e/\x07\xfbi\xf5U\x8a\xa3T\xd9\x1e-9\xaa=\xf1\x84V\x84\x90\xd6\x08OE\x1f|~\xd8<\xf8\xdf\xa7|\xc3\xff\x0ctNw\x96\xb1\x84\xd17\xeeHW\xed\xd2\xf2_\xf7\xacVKm/\'\xd2\x0b"\xab\xf4\x1fW6uQ\xb2\xc9\x87(\xfe/\x0e\x16\xf0\xa7\xb7Q\xb7\x84\xd9\xba\xf0J\xf3\xe71(\x89j\x1b\xb5\xe7\xe7u\xba\xff\xc3\x83\xf2\x8c\x07\xf7\xb5\x83\x96\x7f\xb5\x98_u\xff\xc9\x0b\x12\xae\x06\x04^[\x16\xe6\xcag}eh\xfa\xf7\xefI.\x8aTU5\xb6\xcc\xc7a\x04W\xc5dJ\x9a\xee\x1ax\xff\x9f\xb4K\xd1G\x86\xb0\xae\xb5ps0/\x05`\xd6k\x0c\xd6\x83a\xac\xf2;*\xb4DY\xa4d\x7f{\x16~\x07a\xd6K@\x96\xd3',
            eci['encrypted_content'].native
        )

    def test_parse_content_info_enveloped_data(self):
        with open(os.path.join(fixtures_dir, 'cms-enveloped.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        enveloped_data = info['content']
        encrypted_content_info = enveloped_data['encrypted_content_info']
        recipient = enveloped_data['recipient_infos'][0].chosen

        self.assertEqual(
            'enveloped_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v0',
            enveloped_data['version'].native
        )
        self.assertEqual(
            None,
            enveloped_data['originator_info'].native
        )
        self.assertEqual(
            1,
            len(enveloped_data['recipient_infos'])
        )
        self.assertEqual(
            'v0',
            recipient['version'].native
        )
        self.assertEqual(
            util.OrderedDict([
                (
                    'issuer',
                    util.OrderedDict([
                        ('country_name', 'US'),
                        ('state_or_province_name', 'Massachusetts'),
                        ('locality_name', 'Newbury'),
                        ('organization_name', 'Codex Non Sufficit LC'),
                        ('organizational_unit_name', 'Testing'),
                        ('common_name', 'Will Bond'),
                        ('email_address', 'will@codexns.io'),
                    ])
                ),
                (
                    'serial_number',
                    13683582341504654466
                )
            ]),
            recipient['rid'].native
        )
        self.assertEqual(
            'rsaes_pkcs1v15',
            recipient['key_encryption_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            recipient['key_encryption_algorithm']['parameters'].native
        )
        self.assertEqual(
            b'\x97\x0A\xFD\x3B\x5C\x27\x45\x69\xCC\xDD\x45\x9E\xA7\x3C\x07\x27\x35\x16\x20\x21\xE4\x6E\x1D\xF8'
            b'\x5B\xE8\x7F\xD8\x40\x41\xE9\xF2\x92\xCD\xC8\xC5\x03\x95\xEC\x6C\x0B\x97\x71\x87\x86\x3C\xEB\x68'
            b'\x84\x06\x4E\xE6\xD0\xC4\x7D\x32\xFE\xA6\x06\xC9\xD5\xE1\x8B\xDA\xBF\x96\x5C\x20\x15\x49\x64\x7A'
            b'\xA2\x4C\xFF\x8B\x0D\xEA\x76\x35\x9B\x7C\x43\xF7\x21\x95\x26\xE7\x70\x30\x98\x5F\x0D\x5E\x4A\xCB'
            b'\xAD\x47\xDF\x46\xDA\x1F\x0E\xE2\xFE\x3A\x40\xD9\xF2\xDC\x0C\x97\xD9\x91\xED\x34\x8D\xF3\x73\xB0'
            b'\x90\xF9\xDD\x31\x4D\x37\x93\x81\xD3\x92\xCB\x72\x4A\xD6\x9D\x01\x82\x85\xD5\x1F\xE2\xAA\x32\x12'
            b'\x82\x4E\x17\xF6\xAA\x58\xDE\xBD\x1B\x80\xAF\x61\xF1\x8A\xD1\x7F\x9D\x41\x6A\xC0\xE4\xC7\x7E\x17'
            b'\xDC\x94\x33\xE9\x74\x7E\xE9\xF8\x5C\x30\x87\x9B\xD6\xF0\xE3\x4A\xB7\xE3\xCC\x51\x8A\xD4\x37\xF1'
            b'\xF9\x33\xB5\xD6\x1F\x36\xC1\x6F\x91\xA8\x5F\xE2\x6B\x08\xC7\x9D\xE8\xFD\xDC\xE8\x78\xE0\xC0\xC7'
            b'\xCF\xC5\xEE\x60\xEC\x54\xFF\x1A\x9C\xF7\x4E\x2C\xD0\x88\xDC\xC2\x1F\xDC\x8A\x37\x9B\x71\x20\xFF'
            b'\xFD\x6C\xE5\xBA\x8C\xDF\x0E\x3F\x20\xC6\xCB\x08\xA7\x07\xDB\x83',
            recipient['encrypted_key'].native
        )
        self.assertEqual(
            'data',
            encrypted_content_info['content_type'].native
        )
        self.assertEqual(
            'tripledes_3key',
            encrypted_content_info['content_encryption_algorithm']['algorithm'].native
        )
        self.assertEqual(
            'tripledes',
            encrypted_content_info['content_encryption_algorithm'].encryption_cipher
        )
        self.assertEqual(
            'cbc',
            encrypted_content_info['content_encryption_algorithm'].encryption_mode
        )
        self.assertEqual(
            24,
            encrypted_content_info['content_encryption_algorithm'].key_length
        )
        self.assertEqual(
            8,
            encrypted_content_info['content_encryption_algorithm'].encryption_block_size
        )
        self.assertEqual(
            b'\x52\x50\x98\xFA\x33\x88\xC7\x3C',
            encrypted_content_info['content_encryption_algorithm']['parameters'].native
        )
        self.assertEqual(
            b'\xDC\x88\x55\x08\xE5\x67\x70\x49\x99\x54\xFD\xF8\x40\x7C\x38\xD5\x78\x1D\x6A\x95\x6D\x1E\xC4\x12'
            b'\x39\xFE\xC0\x76\xDC\xF5\x79\x1A\x69\xA1\xB9\x40\x1E\xCF\xC8\x79\x3E\xF3\x38\xB4\x90\x00\x27\xD1'
            b'\xB5\x64\xAB\x99\x51\x13\xF1\x0A',
            encrypted_content_info['encrypted_content'].native
        )
        self.assertEqual(
            None,
            enveloped_data['unprotected_attrs'].native
        )

    def test_parse_content_info_cms_signed_data(self):
        with open(os.path.join(fixtures_dir, 'cms-signed.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        signed_data = info['content']
        encap_content_info = signed_data['encap_content_info']

        self.assertEqual(
            'signed_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v1',
            signed_data['version'].native
        )
        self.assertEqual(
            [
                util.OrderedDict([
                    ('algorithm', 'sha256'),
                    ('parameters', None),
                ])
            ],
            signed_data['digest_algorithms'].native
        )
        self.assertEqual(
            'data',
            encap_content_info['content_type'].native
        )
        self.assertEqual(
            b'This is the message to encapsulate in PKCS#7/CMS\r\n',
            encap_content_info['content'].native
        )

        self.assertEqual(
            1,
            len(signed_data['certificates'])
        )
        certificate = signed_data['certificates'][0]
        with open(os.path.join(fixtures_dir, 'keys/test-der.crt'), 'rb') as f:
            self.assertEqual(
                f.read(),
                certificate.dump()
            )

        self.assertEqual(
            1,
            len(signed_data['signer_infos'])
        )
        signer = signed_data['signer_infos'][0]

        self.assertEqual(
            'v1',
            signer['version'].native
        )
        self.assertEqual(
            util.OrderedDict([
                (
                    'issuer',
                    util.OrderedDict([
                        ('country_name', 'US'),
                        ('state_or_province_name', 'Massachusetts'),
                        ('locality_name', 'Newbury'),
                        ('organization_name', 'Codex Non Sufficit LC'),
                        ('organizational_unit_name', 'Testing'),
                        ('common_name', 'Will Bond'),
                        ('email_address', 'will@codexns.io'),
                    ])
                ),
                (
                    'serial_number',
                    13683582341504654466
                )
            ]),
            signer['sid'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'sha256'),
                ('parameters', None),
            ]),
            signer['digest_algorithm'].native
        )

        signed_attrs = signer['signed_attrs']

        self.assertEqual(
            3,
            len(signed_attrs)
        )
        self.assertEqual(
            'content_type',
            signed_attrs[0]['type'].native
        )
        self.assertEqual(
            'data',
            signed_attrs[0]['values'][0].native
        )
        self.assertEqual(
            'signing_time',
            signed_attrs[1]['type'].native
        )
        self.assertEqual(
            datetime(2015, 5, 30, 13, 12, 38, tzinfo=util.timezone.utc),
            signed_attrs[1]['values'][0].native
        )
        self.assertEqual(
            'message_digest',
            signed_attrs[2]['type'].native
        )
        self.assertEqual(
            b'\xA1\x30\xE2\x87\x90\x5A\x58\x15\x7A\x44\x54\x7A\xB9\xBC\xAE\xD3\x00\xF3\xEC\x3E\x97\xFF'
            b'\x03\x20\x79\x34\x9D\x62\xAA\x20\xA5\x1D',
            signed_attrs[2]['values'][0].native
        )

        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'rsassa_pkcs1v15'),
                ('parameters', None),
            ]),
            signer['signature_algorithm'].native
        )
        self.assertEqual(
            b'\xAC\x2F\xE3\x25\x39\x8F\xD3\xDF\x80\x4F\x0D\xBA\xB1\xEE\x99\x09\xA9\x21\xBB\xDF\x3C\x1E'
            b'\x70\xDA\xDF\xC4\x0F\x1D\x10\x29\xBC\x94\xBE\xF8\xA8\xC2\x2D\x2A\x1F\x14\xBC\x4A\x5B\x66'
            b'\x7F\x6F\xE4\xDF\x82\x4D\xD9\x3F\xEB\x89\xAA\x05\x1A\xE5\x58\xCE\xC4\x33\x53\x6E\xE4\x66'
            b'\xF9\x21\xCF\x80\x35\x46\x88\xB5\x6A\xEA\x5C\x54\x49\x40\x31\xD6\xDC\x20\xD8\xA0\x63\x8C'
            b'\xC1\xC3\xA1\x72\x5D\x0D\xCE\x43\xB1\x5C\xD8\x32\x3F\xA9\xE7\xBB\xD9\x56\xAE\xE7\xFB\x7C'
            b'\x37\x32\x8B\x93\xC2\xC4\x47\xDD\x00\xFB\x1C\xEF\xC3\x68\x32\xDC\x06\x26\x17\x45\xF5\xB3'
            b'\xDC\xD8\x5C\x2B\xC1\x8B\x97\x93\xB8\xF1\x85\xE2\x92\x3B\xC4\x6A\x6A\x89\xC5\x14\x51\x4A'
            b'\x06\x11\x54\xB0\x29\x07\x75\xD8\xDF\x6B\xFB\x21\xE4\xA4\x09\x17\xAF\xAC\xA0\xF5\xC0\xFE'
            b'\x7B\x03\x04\x40\x41\x57\xC4\xFD\x58\x1D\x10\x5E\xAC\x23\xAB\xAA\x80\x95\x96\x02\x71\x84'
            b'\x9C\x0A\xBD\x54\xC4\xA2\x47\xAA\xE7\xC3\x09\x13\x6E\x26\x7D\x72\xAA\xA9\x0B\xF3\xCC\xC4'
            b'\x48\xB4\x97\x14\x00\x47\x2A\x6B\xD3\x93\x3F\xD8\xFD\xAA\xB9\xFB\xFB\xD5\x09\x8D\x82\x8B'
            b'\xDE\x0F\xED\x39\x6D\x7B\xDC\x76\x8B\xA6\x4E\x9B\x7A\xBA',
            signer['signature'].native
        )

    def test_parse_content_info_pkcs7_signed_data(self):
        with open(os.path.join(fixtures_dir, 'pkcs7-signed.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        signed_data = info['content']
        encap_content_info = signed_data['encap_content_info']

        self.assertEqual(
            'signed_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v1',
            signed_data['version'].native
        )
        self.assertEqual(
            [
                util.OrderedDict([
                    ('algorithm', 'sha256'),
                    ('parameters', None),
                ])
            ],
            signed_data['digest_algorithms'].native
        )
        self.assertEqual(
            'data',
            encap_content_info['content_type'].native
        )
        self.assertEqual(
            b'This is the message to encapsulate in PKCS#7/CMS\n',
            encap_content_info['content'].native
        )

        self.assertEqual(
            1,
            len(signed_data['certificates'])
        )
        certificate = signed_data['certificates'][0]
        with open(os.path.join(fixtures_dir, 'keys/test-der.crt'), 'rb') as f:
            self.assertEqual(
                f.read(),
                certificate.dump()
            )

        self.assertEqual(
            1,
            len(signed_data['signer_infos'])
        )
        signer = signed_data['signer_infos'][0]

        self.assertEqual(
            'v1',
            signer['version'].native
        )
        self.assertEqual(
            util.OrderedDict([
                (
                    'issuer',
                    util.OrderedDict([
                        ('country_name', 'US'),
                        ('state_or_province_name', 'Massachusetts'),
                        ('locality_name', 'Newbury'),
                        ('organization_name', 'Codex Non Sufficit LC'),
                        ('organizational_unit_name', 'Testing'),
                        ('common_name', 'Will Bond'),
                        ('email_address', 'will@codexns.io'),
                    ])
                ),
                (
                    'serial_number',
                    13683582341504654466
                )
            ]),
            signer['sid'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'sha256'),
                ('parameters', None),
            ]),
            signer['digest_algorithm'].native
        )

        signed_attrs = signer['signed_attrs']

        self.assertEqual(
            4,
            len(signed_attrs)
        )
        self.assertEqual(
            'content_type',
            signed_attrs[0]['type'].native
        )
        self.assertEqual(
            'data',
            signed_attrs[0]['values'][0].native
        )
        self.assertEqual(
            'signing_time',
            signed_attrs[1]['type'].native
        )
        self.assertEqual(
            datetime(2015, 6, 3, 5, 55, 12, tzinfo=util.timezone.utc),
            signed_attrs[1]['values'][0].native
        )
        self.assertEqual(
            'message_digest',
            signed_attrs[2]['type'].native
        )
        self.assertEqual(
            b'\x52\x88\x25\x47\x15\x5B\x2D\x50\x44\x68\x05\x24\xC8\x71\x5A\xCC\x62\x28\x36\x17\xB7\x68'
            b'\xEE\xA1\x12\x90\x96\x4F\x94\xAE\xDB\x79',
            signed_attrs[2]['values'][0].native
        )

        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'rsassa_pkcs1v15'),
                ('parameters', None),
            ]),
            signer['signature_algorithm'].native
        )
        self.assertEqual(
            b'\x43\x66\xEE\xF4\x6A\x02\x6F\xFE\x0D\xAE\xE6\xF3\x7A\x8F\x2C\x8E\x26\xB6\x25\x68\xEF\x5B'
            b'\x4B\x4F\x9C\xE4\xE6\x71\x42\x22\xEC\x97\xFC\x53\xD9\xD6\x36\x1F\xA1\x32\x35\xFF\xA9\x95'
            b'\x45\x50\x36\x36\x0C\x9A\x10\x6F\x06\xB6\x9D\x25\x10\x08\xF5\xF4\xE1\x68\x62\x60\xE5\xBF'
            b'\xBD\xE2\x9F\xBD\x8A\x10\x29\x3B\xAF\xE7\xD6\x55\x7C\xEE\x3B\xFB\x93\x42\xE0\xB4\x4F\x89'
            b'\xD0\x7B\x18\x51\x85\x90\x47\xF0\x5E\xE1\x15\x2C\xC1\x9A\xF1\x49\xE8\x11\x29\x17\x2E\x77'
            b'\xD3\x35\x10\xAA\xCD\x32\x07\x32\x74\xCF\x2D\x89\xBD\xEF\xC7\xC9\xE7\xEC\x90\x44\xCE\x0B'
            b'\xC5\x97\x00\x26\x67\x8A\x89\x5B\xFA\x46\xB2\x92\xD5\xCB\xA3\x52\x16\xDC\xF0\xF0\x79\xCB'
            b'\x90\x93\x8E\x26\xB3\xEB\x8F\xBD\x54\x06\xD6\xB0\xA0\x04\x47\x7C\x63\xFC\x88\x5A\xE3\x81'
            b'\xDF\x1E\x4D\x39\xFD\xF5\xA0\xE2\xD3\xAB\x13\xC1\xCF\x50\xB2\x0B\xC9\x36\xD6\xCB\xEA\x55'
            b'\x39\x97\x8E\x34\x47\xE3\x6B\x44\x4A\x0E\x03\xAF\x41\xB2\x47\x2E\x26\xA3\x6B\x5F\xA1\x5C'
            b'\x86\xA1\x96\x37\x02\xD3\x7C\x5F\xC1\xAF\x81\xE4\x1A\xD9\x87\x44\xB5\xB3\x5C\x45\x6C\xFF'
            b'\x97\x4C\x3A\xB4\x2F\x5C\x2F\x86\x15\x51\x71\xA6\x27\x68',
            signer['signature'].native
        )

    def test_parse_cms_signed_date_indefinite_length(self):
        with open(os.path.join(fixtures_dir, 'cms-signed-indefinite-length.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())
            signed_data = info['content']
            self.assertIsInstance(signed_data.native, util.OrderedDict)

    def test_parse_content_info_cms_signed_digested_data(self):
        with open(os.path.join(fixtures_dir, 'cms-signed-digested.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        signed_data = info['content']
        encap_content_info = signed_data['encap_content_info']

        self.assertEqual(
            'signed_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v2',
            signed_data['version'].native
        )
        self.assertEqual(
            [
                util.OrderedDict([
                    ('algorithm', 'sha256'),
                    ('parameters', None),
                ])
            ],
            signed_data['digest_algorithms'].native
        )
        self.assertEqual(
            'digested_data',
            encap_content_info['content_type'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('version', 'v0'),
                (
                    'digest_algorithm',
                    util.OrderedDict([
                        ('algorithm', 'sha1'),
                        ('parameters', None),
                    ])
                ),
                (
                    'encap_content_info',
                    util.OrderedDict([
                        ('content_type', 'data'),
                        ('content', b'This is the message to encapsulate in PKCS#7/CMS\n'),
                    ])
                ),
                (
                    'digest',
                    b'\x53\xC9\xDB\xC1\x6D\xDB\x34\x3B\x28\x4E\xEF\xA6\x03\x0E\x02\x64\x79\x31\xAF\xFB'
                )
            ]),
            encap_content_info['content'].native
        )

        self.assertEqual(
            1,
            len(signed_data['certificates'])
        )
        certificate = signed_data['certificates'][0]
        with open(os.path.join(fixtures_dir, 'keys/test-der.crt'), 'rb') as f:
            self.assertEqual(
                f.read(),
                certificate.dump()
            )

        self.assertEqual(
            1,
            len(signed_data['signer_infos'])
        )
        signer = signed_data['signer_infos'][0]

        self.assertEqual(
            'v1',
            signer['version'].native
        )
        self.assertEqual(
            util.OrderedDict([
                (
                    'issuer',
                    util.OrderedDict([
                        ('country_name', 'US'),
                        ('state_or_province_name', 'Massachusetts'),
                        ('locality_name', 'Newbury'),
                        ('organization_name', 'Codex Non Sufficit LC'),
                        ('organizational_unit_name', 'Testing'),
                        ('common_name', 'Will Bond'),
                        ('email_address', 'will@codexns.io'),
                    ])
                ),
                (
                    'serial_number',
                    13683582341504654466
                )
            ]),
            signer['sid'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'sha256'),
                ('parameters', None),
            ]),
            signer['digest_algorithm'].native
        )

        signed_attrs = signer['signed_attrs']

        self.assertEqual(
            0,
            len(signed_attrs)
        )

        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'rsassa_pkcs1v15'),
                ('parameters', None),
            ]),
            signer['signature_algorithm'].native
        )
        self.assertEqual(
            b'\x70\xBC\x18\x82\x41\xD6\xD8\xE7\x5C\xDC\x42\x27\xA5\xA8\xAA\x8B\x16\x15\x61\x3A\xE5\x47'
            b'\x53\xFD\x8F\x45\xA3\x82\xE2\x72\x44\x07\xD1\xCB\xBF\xB4\x85\x4A\x2A\x16\x19\xDE\xDC\x53'
            b'\x15\xCF\x98\xEE\x5C\x0E\xDF\xDE\xC8\x79\xCE\x2B\x38\x61\x36\xB0\xA1\xCB\x94\xD6\x4F\xCD'
            b'\x83\xEF\x0C\xC9\x23\xA0\x7B\x8B\x65\x40\x5C\x3D\xA8\x3E\xCC\x0D\x1F\x17\x23\xF3\x74\x9F'
            b'\x7E\x88\xF8\xF3\xBE\x4E\x19\x95\x0F\xEB\x95\x55\x69\xB4\xAA\xC3\x2A\x36\x03\x93\x1C\xDC'
            b'\xE5\x65\x3F\x4E\x5E\x03\xC8\x56\xD8\x57\x8F\xE8\x2D\x85\x32\xDA\xFD\x79\xD4\xDD\x88\xCA'
            b'\xA3\x14\x41\xE4\x3B\x03\x88\x0E\x2B\x76\xDC\x44\x3D\x4D\xFF\xB2\xC8\xC3\x83\xB1\x33\x37'
            b'\x53\x51\x33\x4B\xCA\x1A\xAD\x7E\x6A\xBC\x61\x8B\x84\xDB\x7F\xCF\x61\xB2\x1D\x21\x83\xCF'
            b'\xB8\x3F\xC6\x98\xED\xD8\x66\x06\xCF\x03\x30\x96\x9D\xB4\x7A\x16\xDF\x6E\xA7\x30\xEB\x77'
            b'\xF7\x40\x13\xFB\xF2\xAC\x41\x79\x9D\xDC\xC0\xED\x4B\x8B\x19\xEE\x05\x3D\x61\x20\x39\x7E'
            b'\x80\x1D\x3A\x23\x69\x48\x43\x60\x8B\x3E\x63\xAD\x01\x7A\xDE\x6F\x01\xBA\x51\xF3\x4B\x14'
            b'\xBF\x6B\x77\x1A\x32\xC2\x0C\x93\xCC\x35\xBC\x66\xC6\x69',
            signer['signature'].native
        )

    def test_parse_content_info_pkcs7_signed_digested_data(self):
        with open(os.path.join(fixtures_dir, 'pkcs7-signed-digested.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        signed_data = info['content']
        encap_content_info = signed_data['encap_content_info']

        self.assertEqual(
            'signed_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v1',
            signed_data['version'].native
        )
        self.assertEqual(
            [
                util.OrderedDict([
                    ('algorithm', 'sha256'),
                    ('parameters', None),
                ])
            ],
            signed_data['digest_algorithms'].native
        )
        self.assertEqual(
            'digested_data',
            encap_content_info['content_type'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('version', 'v0'),
                (
                    'digest_algorithm',
                    util.OrderedDict([
                        ('algorithm', 'sha1'),
                        ('parameters', None),
                    ])
                ),
                (
                    'encap_content_info',
                    util.OrderedDict([
                        ('content_type', 'data'),
                        ('content', b'This is the message to encapsulate in PKCS#7/CMS\n'),
                    ])
                ),
                (
                    'digest',
                    b'\x53\xC9\xDB\xC1\x6D\xDB\x34\x3B\x28\x4E\xEF\xA6\x03\x0E\x02\x64\x79\x31\xAF\xFB'
                )
            ]),
            encap_content_info['content'].native
        )

        self.assertEqual(
            1,
            len(signed_data['certificates'])
        )
        certificate = signed_data['certificates'][0]
        with open(os.path.join(fixtures_dir, 'keys/test-der.crt'), 'rb') as f:
            self.assertEqual(
                f.read(),
                certificate.dump()
            )

        self.assertEqual(
            1,
            len(signed_data['signer_infos'])
        )
        signer = signed_data['signer_infos'][0]

        self.assertEqual(
            'v1',
            signer['version'].native
        )
        self.assertEqual(
            util.OrderedDict([
                (
                    'issuer',
                    util.OrderedDict([
                        ('country_name', 'US'),
                        ('state_or_province_name', 'Massachusetts'),
                        ('locality_name', 'Newbury'),
                        ('organization_name', 'Codex Non Sufficit LC'),
                        ('organizational_unit_name', 'Testing'),
                        ('common_name', 'Will Bond'),
                        ('email_address', 'will@codexns.io'),
                    ])
                ),
                (
                    'serial_number',
                    13683582341504654466
                )
            ]),
            signer['sid'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'sha256'),
                ('parameters', None),
            ]),
            signer['digest_algorithm'].native
        )

        signed_attrs = signer['signed_attrs']

        self.assertEqual(
            0,
            len(signed_attrs)
        )

        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'rsassa_pkcs1v15'),
                ('parameters', None),
            ]),
            signer['signature_algorithm'].native
        )
        self.assertEqual(
            b'\x70\xBC\x18\x82\x41\xD6\xD8\xE7\x5C\xDC\x42\x27\xA5\xA8\xAA\x8B\x16\x15\x61\x3A\xE5\x47'
            b'\x53\xFD\x8F\x45\xA3\x82\xE2\x72\x44\x07\xD1\xCB\xBF\xB4\x85\x4A\x2A\x16\x19\xDE\xDC\x53'
            b'\x15\xCF\x98\xEE\x5C\x0E\xDF\xDE\xC8\x79\xCE\x2B\x38\x61\x36\xB0\xA1\xCB\x94\xD6\x4F\xCD'
            b'\x83\xEF\x0C\xC9\x23\xA0\x7B\x8B\x65\x40\x5C\x3D\xA8\x3E\xCC\x0D\x1F\x17\x23\xF3\x74\x9F'
            b'\x7E\x88\xF8\xF3\xBE\x4E\x19\x95\x0F\xEB\x95\x55\x69\xB4\xAA\xC3\x2A\x36\x03\x93\x1C\xDC'
            b'\xE5\x65\x3F\x4E\x5E\x03\xC8\x56\xD8\x57\x8F\xE8\x2D\x85\x32\xDA\xFD\x79\xD4\xDD\x88\xCA'
            b'\xA3\x14\x41\xE4\x3B\x03\x88\x0E\x2B\x76\xDC\x44\x3D\x4D\xFF\xB2\xC8\xC3\x83\xB1\x33\x37'
            b'\x53\x51\x33\x4B\xCA\x1A\xAD\x7E\x6A\xBC\x61\x8B\x84\xDB\x7F\xCF\x61\xB2\x1D\x21\x83\xCF'
            b'\xB8\x3F\xC6\x98\xED\xD8\x66\x06\xCF\x03\x30\x96\x9D\xB4\x7A\x16\xDF\x6E\xA7\x30\xEB\x77'
            b'\xF7\x40\x13\xFB\xF2\xAC\x41\x79\x9D\xDC\xC0\xED\x4B\x8B\x19\xEE\x05\x3D\x61\x20\x39\x7E'
            b'\x80\x1D\x3A\x23\x69\x48\x43\x60\x8B\x3E\x63\xAD\x01\x7A\xDE\x6F\x01\xBA\x51\xF3\x4B\x14'
            b'\xBF\x6B\x77\x1A\x32\xC2\x0C\x93\xCC\x35\xBC\x66\xC6\x69',
            signer['signature'].native
        )

    def test_parse_content_info_smime_capabilities(self):
        with open(os.path.join(fixtures_dir, 'smime-signature-generated-by-thunderbird.p7s'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        signed_attrs = info['content']['signer_infos'][0]['signed_attrs']

        self.assertEqual(
            'smime_capabilities',
            signed_attrs[3]['type'].native
        )
        smime_capabilities = signed_attrs[3]

        self.assertEqual(
            1,
            len(smime_capabilities['values'])
        )
        self.assertEqual(
            7,
            len(smime_capabilities['values'][0])
        )
        self.assertEqual(
            [capability.native for capability in smime_capabilities['values'][0]],
            [
                util.OrderedDict([
                    ('capability_id', 'aes256_cbc'),
                    ('parameters', None),
                ]),
                util.OrderedDict([
                    ('capability_id', 'aes128_cbc'),
                    ('parameters', None),
                ]),
                util.OrderedDict([
                    ('capability_id', 'tripledes_3key'),
                    ('parameters', None),
                ]),
                util.OrderedDict([
                    ('capability_id', 'rc2'),
                    ('parameters', 128),
                ]),
                util.OrderedDict([
                    ('capability_id', 'rc2'),
                    ('parameters', 64),
                ]),
                util.OrderedDict([
                    ('capability_id', 'des'),
                    ('parameters', None),
                ]),
                util.OrderedDict([
                    ('capability_id', 'rc2'),
                    ('parameters', 40),
                ]),
            ]
        )

    def test_bad_teletex_inside_pkcs7(self):
        with open(os.path.join(fixtures_dir, 'mozilla-generated-by-openssl.pkcs7.der'), 'rb') as f:
            content = cms.ContentInfo.load(f.read())['content']
        self.assertEqual(
            util.OrderedDict([
                ('organizational_unit_name', 'Testing'),
                ('country_name', 'US'),
                ('locality_name', 'Mountain View'),
                ('organization_name', 'Addons Testing'),
                ('state_or_province_name', 'CA'),
                ('common_name', '{02b860db-e71f-48d2-a5a0-82072a93d33c}')
            ]),
            content['certificates'][0].chosen['tbs_certificate']['subject'].native
        )

    def test_parse_attribute_cert(self):
        # regression test for tagging issue in AttCertIssuer

        with open(os.path.join(fixtures_dir, 'example-attr-cert.der'), 'rb') as f:
            ac_bytes = f.read()
        ac_parsed = cms.AttributeCertificateV2.load(ac_bytes)
        self.assertEqual(ac_bytes, ac_parsed.dump(force=True))

        ac_info = ac_parsed['ac_info']
        self.assertIsInstance(ac_info['issuer'].chosen, cms.V2Form)
        self.assertEqual(1, len(ac_info['issuer'].chosen['issuer_name']))

    def test_create_role_syntax(self):
        rs = cms.RoleSyntax({'role_name': {'rfc822_name': 'test@example.com'}})
        self.assertEqual(
            util.OrderedDict([
                ('role_authority', None),
                ('role_name', 'test@example.com')
            ]),
            rs.native
        )
