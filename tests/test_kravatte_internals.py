import hashlib
import numpy as np
from kravatte import Kravatte


# Official Test Vectors
class TestKravatte_Internals:
    """
    Test Object Behaviors
    """

    def test_kravatte_scrub(self, test_workers):
        """Verify Scrub clear key and collector arrays """
        g = Kravatte(b'123456789ABCDEF0', workers=test_workers)
        g.collect_message(b"Alan Turing's Birthday is June 23rd")
        active_collector_state = np.array([[0x47f2a8301022502b, 0x175a0ba024f597e6, 0x9b4e04613147e6ef,
                                            0x1765b925c31c079e, 0x6ab67495fea87309],
                                           [0xa0e08cf91f6036e7, 0xbde524db485dd8c5, 0xd5bef8ec82ec546c,
                                            0x1d5d5bb702ecd106, 0xd2859d853decd0ba],
                                           [0x933a7ae8cbc00112, 0x9670141bc39379b4, 0x8592eca8ed33d40a,
                                            0x633024eb4c392d43, 0x68832b65ee7815f6],
                                           [0xfbd578b54286aacb, 0x77d40e7b2453f93a, 0x97650682ed2063aa,
                                            0x10247404d7916fb, 0x2c1aa50e5985f0d7],
                                           [0xf8c6c899ee338b89, 0xad3149bd7cd30c52, 0x5ca8af3af0a6095f,
                                            0x29c8b966c76d3ab2, 0x897804d9e8d92c88]], dtype=np.uint64)
        active_key_state = np.array([[0xfd3dc5a634820be2, 0xda84238d059df308, 0xe1273a75cbe9ca79,
                                      0xb42c26e0142eb005, 0xe408e6c3432721ae],
                                     [0xfda5f1b13312de28, 0x8550cb0da540eb36, 0xe659e72afb21d426,
                                      0xa8a129c543ba8cfe, 0x9e4f929e6a3ab546],
                                     [0x491282fd4e25cf37, 0xf2d80d06aad4c4d7, 0xcb26fbbba4611f6b,
                                      0xd5326fcd86c85641, 0x51cb367bf84cbf1],
                                     [0xdce9402ead58c081, 0x41d58bb12faa6eb3, 0x84bf1457dc9a9002,
                                      0xe3eb07702cb8d973, 0xf6cf479fbee020de],
                                     [0xb877c006a804f95d, 0xf8fa17134fd29bee, 0x4270ff5f591d0054,
                                      0x3662557cd15143f4, 0x21aad09eda854b56]], dtype=np.uint64)
        np.testing.assert_array_equal(g.kra_key, active_key_state)
        np.testing.assert_array_equal(g.collector, active_collector_state)
        # Clear collector and key state
        g.scrub()

        zero_keccak_array = np.array([[0x0, 0x0, 0x0, 0x0, 0x0],
                                      [0x0, 0x0, 0x0, 0x0, 0x0],
                                      [0x0, 0x0, 0x0, 0x0, 0x0],
                                      [0x0, 0x0, 0x0, 0x0, 0x0],
                                      [0x0, 0x0, 0x0, 0x0, 0x0]], dtype=np.uint64)
        np.testing.assert_array_equal(g.kra_key, zero_keccak_array)
        np.testing.assert_array_equal(g.collector, zero_keccak_array)
        np.testing.assert_array_equal(g.roll_key, zero_keccak_array)

    def test_kravatte_async_workers_input_only(self, test_workers):
        """Enable Multiprocessing only for Input Message Collection"""
        my_key = bytes([0xdf, 0x34, 0xa8, 0xb5, 0x87, 0xd8, 0x94, 0xce, 0xbd, 0x00, 0x63, 0x93,
                        0x19, 0xf4, 0xee, 0x15, 0x4c, 0x06, 0xe3, 0x78, 0x14, 0x00, 0x24, 0x0e,
                        0x27, 0x9a, 0x52, 0xf6, 0x4f, 0x9b, 0x11, 0x70, 0xd6, 0x9f, 0xa9, 0x61,
                        0x61, 0x1f, 0x80, 0xbf, 0x34, 0x6c, 0x00, 0x13, 0x0b, 0x13, 0x26, 0x89,
                        0x1d, 0x01, 0x6e, 0x14, 0x1a, 0xcd, 0xaa, 0xe4, 0x4e, 0xe4, 0x78, 0xf7,
                        0xfa, 0xbe, 0xfd, 0x06])
        my_message = bytes([0x06, 0x7f, 0xee, 0x21, 0xb3, 0xe2, 0x8d, 0x8c, 0xd8, 0xe2, 0x42, 0x00,
                            0xb0, 0xd5, 0xc5, 0xb4, 0x2e, 0xe8, 0x13, 0xbc, 0xa1, 0x26, 0x5f, 0x5a,
                            0x35, 0x83, 0x51, 0x64, 0x64, 0x86, 0x4b, 0x97, 0x0b, 0x0a, 0x0d, 0xb4,
                            0x32, 0x54, 0x72, 0x4c, 0xc0, 0x91, 0xf5, 0x57, 0x6f, 0x3a, 0xd6, 0xd4,
                            0x4f, 0x41, 0x10, 0x33, 0x22, 0xbe, 0xff, 0xbf, 0xf6, 0x2b, 0x0e, 0x45,
                            0x16, 0x27, 0x41, 0x38])
        real_collector = np.array([[0x54e0ec264ca8c59a, 0x4b6fc50546a0bc21, 0x1bfbdb05b9f59286, 0xd5c9326c207f5be4, 0x375cc6860a942eaa],
                                  [0x2fdce82332ae82f4, 0xf3514f8ccda98eca, 0x8787fc911658feea, 0xc804a1d21acbc2c0, 0xe0ab88818ece9ec8],
                                  [0xf0c286ae557896d3, 0xa106537a749842d3, 0xd6460164c12e5a0b, 0xa746ff01fa0f191f, 0x89189a584c857048],
                                  [0x5313e654653eac3c, 0x6cc4088ba50d88c7, 0x1486c2621e7b6c66, 0x678cb5aa64372917, 0x36fba87d0ec90c52],
                                  [0x4490c47365118d8f, 0xa3be17e62f3c241a, 0x6cc90d7d5d8e3cc4, 0x5dce0aea4a2c95c1, 0x3b1574b2476f1cfc]], dtype=np.uint64)
        real_digest = bytes([0x3f, 0xe1, 0xcd, 0x75, 0x18, 0x89, 0x32, 0x90, 0xaa, 0x8d, 0x97,
                             0xab, 0x7f, 0x86, 0xa8, 0x60, 0xcb, 0x88, 0x54, 0x32, 0xa0, 0x4a,
                             0x85, 0x46, 0xf9, 0x87, 0xce, 0xd8, 0x07, 0x85, 0xa4, 0x00, 0x34,
                             0x47, 0x69, 0xf7, 0x08, 0x53, 0xff, 0x04, 0xf6, 0xa4, 0xe5, 0x2c,
                             0xba, 0x14, 0xe9, 0xef, 0xcb, 0x1f, 0xa2, 0x6f, 0x23, 0xa8, 0x1f,
                             0x3b, 0x53, 0xdb, 0xfb, 0x8a, 0x5d, 0x9d, 0x9e, 0xd8, 0x6b, 0xde,
                             0x2e, 0x19, 0x26, 0xa7, 0xb4, 0x25, 0xf5, 0xad, 0x77, 0x61, 0xd5,
                             0xe7, 0x12, 0x47, 0x52, 0x20, 0x5b, 0x93, 0x46, 0xe9, 0xb4, 0xf5,
                             0x52, 0xfe, 0x87, 0x32, 0x0a, 0x7a, 0x49, 0x28, 0xef, 0x1f, 0x04,
                             0xd3, 0x5b, 0xa2, 0xa5, 0xff, 0x02, 0xd7, 0x23, 0x4f, 0xb5, 0x7b,
                             0x88, 0xf7, 0xe5, 0xd4, 0x74, 0x5c, 0x80, 0x8e, 0x78, 0xe5, 0x9d,
                             0xae, 0x9b, 0x4b, 0x82, 0x86, 0x47, 0xb4, 0x00, 0xca, 0x81, 0x8c,
                             0xc8, 0xcc, 0xba, 0xb3, 0x06, 0xfd, 0xaf, 0x0d, 0x66, 0x8c, 0x8f,
                             0xe1, 0x8e, 0xdc, 0xff, 0xe5, 0x8a, 0x6b, 0xcd, 0xf2, 0x94, 0x20,
                             0xd3, 0xe2, 0x31, 0x5e, 0x9a, 0xa4, 0xe1, 0xa9, 0x66, 0xae, 0x07,
                             0x31, 0x56, 0xe9, 0x29, 0x80, 0x7f, 0xd8, 0x5b, 0xcf, 0x7d, 0x23,
                             0x26, 0x37, 0x7b, 0x3d, 0x59, 0x2f, 0xaf, 0x99, 0x9f, 0x17, 0xce,
                             0x50, 0x7f, 0x3b, 0x99, 0x29, 0x44, 0xce, 0xe6, 0xea, 0xef, 0x67,
                             0xc2, 0x2e])
        g = Kravatte(my_key, workers=test_workers, mp_input=True, mp_output=False)
        if test_workers:
            assert g.collect_message == g._collect_message_mp
            assert g.generate_digest == g._generate_digest_sp
        else:
            assert g.collect_message == g._collect_message_sp
            assert g.generate_digest == g._generate_digest_sp
        g.collect_message(my_message)
        assert (real_collector == g.collector).all()
        g.generate_digest(200)
        assert real_digest == g.digest

    def test_kravatte_async_workers_output_only(self, test_workers):
        """Enable Multiprocessing only for Output Digest Generation"""
        my_key = bytes([0x4e, 0x69, 0x25, 0x47, 0xce, 0x01, 0x7b, 0xd0, 0x53, 0xe1, 0x0d, 0x0b,
                        0xd2, 0xb2, 0x89, 0x9f, 0x6d, 0xce, 0xa0, 0xfa, 0x98, 0x74, 0x97, 0x53,
                        0xdf, 0xa2, 0xa8, 0xb4, 0x0e, 0x04, 0x3e, 0xf2, 0xc3, 0x3f, 0x45, 0xf3,
                        0x99, 0x51, 0xf1, 0xd2, 0xda, 0xe0, 0xee, 0xcb, 0xd1, 0x8d, 0x77, 0xed,
                        0x71, 0xe0, 0xc7, 0x75, 0xe9, 0x41, 0x78, 0x6e, 0x19, 0x6f, 0x97, 0x59,
                        0x54, 0x5e, 0xaf, 0xa5])
        my_message = bytes([0x06, 0x25, 0xf8, 0x40, 0x6f, 0x74, 0x1d, 0xa3, 0x69, 0x13, 0x24, 0x06,
                            0x02, 0xea, 0xfb, 0xc2, 0xdd, 0xd8, 0xd0, 0x99, 0x4a, 0x58, 0xa6, 0xbc,
                            0x9d, 0x8a, 0xb1, 0x7f, 0xa2, 0x03, 0x4a, 0x53, 0xf1, 0xf2, 0xc3, 0x7b,
                            0x20, 0x81, 0x8a, 0x6b, 0x8b, 0x40, 0xf9, 0xe2, 0x7e, 0x9d, 0x61, 0xcc,
                            0xfd, 0xe7, 0x7f, 0xb3, 0x41, 0x6e, 0x82, 0x6b, 0x0e, 0x38, 0xa5, 0x59,
                            0x81, 0x0c, 0xb4, 0x37])
        real_collector = np.array([[0x49382d1a6d6333ba, 0x1edd2f81e2d73d9d, 0x8805834ab4925a46, 0xfffe59f67acb272, 0xe45a3f77eb2b27a5],
                                   [0xe98356c0405bd2a, 0x4c4e36ee9fd7140, 0xc4ad304253621be4, 0x3413a5e4697b34cc, 0xc492d9f80be73c74],
                                   [0x4f305b758c030696, 0x855c85b4addd25d2, 0xe62415f70809e980, 0x708724adb6c442f3, 0xf074992dbf26076e],
                                   [0xe5857abfa46ff189, 0xee3add1524bb5d32, 0x8edb25f78ff42d1, 0xd79f1a4149960ac6, 0x4c217455991f2bf7],
                                   [0xd4e81912604d468b, 0xc1789f3967dc427f, 0xab20b23fab6d4c9a, 0xbd8f0a52b83f6e5f, 0x465859be99a6ebff]], dtype=np.uint64)
        real_digest = bytes([0xc5, 0x65, 0x5b, 0x1c, 0x58, 0x54, 0xb7, 0xf2, 0x0f, 0x53, 0x80, 0x8f,
                             0xf4, 0xfa, 0x42, 0x24, 0x7d, 0xb7, 0x6b, 0xd6, 0x7c, 0x15, 0x2f, 0x7f,
                             0xdb, 0x8f, 0x37, 0xfe, 0x08, 0xa7, 0x73, 0xf2, 0x4e, 0xcd, 0x71, 0xf8,
                             0x03, 0xdd, 0xe1, 0xb2, 0xbb, 0x49, 0xde, 0x79, 0xb8, 0x07, 0xbe, 0x13,
                             0x26, 0x9d, 0x7d, 0x36, 0x92, 0x51, 0xa3, 0x5a, 0xb1, 0xb9, 0xff, 0x9e,
                             0x16, 0xa0, 0x57, 0xc4, 0x9b, 0x91, 0xd6, 0x63, 0x11, 0x1d, 0xaf, 0x84,
                             0x0c, 0x50, 0x36, 0xac, 0x9d, 0x9f, 0xff, 0x50, 0xba, 0x32, 0x39, 0x19,
                             0x18, 0xef, 0xb5, 0x6a, 0x90, 0xf4, 0x40, 0x6e, 0x71, 0xa6, 0x4e, 0x96,
                             0xf2, 0xab, 0x25, 0x96, 0xea, 0x66, 0xf5, 0xe2, 0xd9, 0x84, 0x69, 0xce,
                             0xfd, 0x20, 0xa1, 0x24, 0xf8, 0x97, 0x9f, 0x52, 0xce, 0x7d, 0x0a, 0x3a,
                             0xdd, 0xb4, 0x5a, 0x99, 0x12, 0x1d, 0x9b, 0x44, 0x1f, 0x5b, 0x71, 0x50,
                             0x7e, 0xea, 0x15, 0xd2, 0x63, 0x16, 0x91, 0xa3, 0xb4, 0xe7, 0x57, 0x2f,
                             0x39, 0xdf, 0xe1, 0x59, 0x4d, 0x73, 0x06, 0x53, 0xff, 0x47, 0xb0, 0x03,
                             0x8a, 0xa8, 0xf8, 0x68, 0x8d, 0xc0, 0x21, 0x88, 0x35, 0x91, 0x0e, 0x4d,
                             0x99, 0xeb, 0x7f, 0xd9, 0x7f, 0xf6, 0x78, 0xfd, 0x4e, 0xdf, 0xc6, 0xb6,
                             0x30, 0x95, 0xb0, 0x0d, 0x6b, 0x5a, 0x56, 0xaf, 0xf5, 0xd6, 0x9e, 0xce,
                             0xf6, 0x36, 0xb9, 0xe2, 0x9b, 0x75, 0xb9, 0x0b])
        g = Kravatte(my_key, workers=test_workers, mp_input=False, mp_output=True)
        if test_workers:
            assert g.collect_message == g._collect_message_sp
            assert g.generate_digest == g._generate_digest_mp
        else:
            assert g.collect_message == g._collect_message_sp
            assert g.generate_digest == g._generate_digest_sp
        g.collect_message(my_message)
        assert (real_collector == g.collector).all()
        g.generate_digest(200)
        assert real_digest == g.digest