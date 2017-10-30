import pytest
import numpy as np
from random import randint
from keccak import Keccak


# Official Test Vectors
class TestOfficialTestVectors:
    """
    Official Test Vector From
    """
    def test_sha3_224_0_bit_absorb(self):
        test = Keccak()
        g = np.zeros((5,5), dtype=np.uint64) 
        end_state = np.zeros((5,5), dtype=np.uint64)
        g[0, 0] = 0x0000000000000006
        g[1, 0] = 0x0000000000000000
        g[2, 0] = 0x0000000000000000
        g[3, 0] = 0x0000000000000000
        g[4, 0] = 0x0000000000000000
        g[0, 1] = 0x0000000000000000
        g[1, 1] = 0x0000000000000000
        g[2, 1] = 0x0000000000000000
        g[3, 1] = 0x0000000000000000
        g[4, 1] = 0x0000000000000000
        g[0, 2] = 0x0000000000000000
        g[1, 2] = 0x0000000000000000
        g[2, 2] = 0x0000000000000000
        g[3, 2] = 0x0000000000000000
        g[4, 2] = 0x0000000000000000
        g[0, 3] = 0x0000000000000000
        g[1, 3] = 0x0000000000000000
        g[2, 3] = 0x8000000000000000
        g[3, 3] = 0x0000000000000000
        g[4, 3] = 0x0000000000000000
        g[0, 4] = 0x0000000000000000
        g[1, 4] = 0x0000000000000000
        g[2, 4] = 0x0000000000000000
        g[3, 4] = 0x0000000000000000
        g[4, 4] = 0x0000000000000000
        end_state[0, 0] = 0xb7db673642034e6b
        end_state[1, 0] = 0xabb10e4f45156e3b
        end_state[2, 0] = 0x3f8e071b9a7f59d4
        end_state[3, 0] = 0x4fcdb16dc76b5a5b
        end_state[4, 0] = 0xe011a2336eeb55a5
        end_state[0, 1] = 0x03f518c65b20fc40
        end_state[1, 1] = 0x5ae4c6e7f23591ea
        end_state[2, 1] = 0xa84c31d557b3ad5a
        end_state[3, 1] = 0xf38a0916d223c8fd
        end_state[4, 1] = 0x259dc1df559ac0d2
        end_state[0, 2] = 0x7015c428a3c2c778
        end_state[1, 2] = 0x06cccc283ebb3601
        end_state[2, 2] = 0x87415fe98f278b7c
        end_state[3, 2] = 0x51cdfb7b08b526d9
        end_state[4, 2] = 0xa0b3aef7fd755f2f
        end_state[0, 3] = 0xe85273208360b782
        end_state[1, 3] = 0x3788fee8e85da9cc
        end_state[2, 3] = 0x22e612a3a389fd9d
        end_state[3, 3] = 0x7d0670de3b871820
        end_state[4, 3] = 0x5877f8698f8547fe
        end_state[0, 4] = 0x6e3f7a8aed5e7f7e
        end_state[1, 4] = 0xf9b1eb6bc83441d2
        end_state[2, 4] = 0xea5613f47968cf26
        end_state[3, 4] = 0xfbe73810bf404de4
        end_state[4, 4] = 0xe182468c695662e4

        test._absorb(g)
        assert np.equal(test.state, end_state).all()

    def test_sha3_256_0_bit_absorb(self):
        test = Keccak()
        g = np.zeros((5,5), dtype=np.uint64) 
        end_state = np.zeros((5,5), dtype=np.uint64)
        g[0, 0] = 0x0000000000000006
        g[1, 0] = 0x0000000000000000
        g[2, 0] = 0x0000000000000000
        g[3, 0] = 0x0000000000000000
        g[4, 0] = 0x0000000000000000
        g[0, 1] = 0x0000000000000000
        g[1, 1] = 0x0000000000000000
        g[2, 1] = 0x0000000000000000
        g[3, 1] = 0x0000000000000000
        g[4, 1] = 0x0000000000000000
        g[0, 2] = 0x0000000000000000
        g[1, 2] = 0x0000000000000000
        g[2, 2] = 0x0000000000000000
        g[3, 2] = 0x0000000000000000
        g[4, 2] = 0x0000000000000000
        g[0, 3] = 0x0000000000000000
        g[1, 3] = 0x8000000000000000
        g[2, 3] = 0x0000000000000000
        g[3, 3] = 0x0000000000000000
        g[4, 3] = 0x0000000000000000
        g[0, 4] = 0x0000000000000000
        g[1, 4] = 0x0000000000000000
        g[2, 4] = 0x0000000000000000
        g[3, 4] = 0x0000000000000000
        g[4, 4] = 0x0000000000000000
        end_state[0, 0] = 0x66d71ebff8c6ffa7
        end_state[1, 0] = 0x62d661a05647c151
        end_state[2, 0] = 0xfa493be44dff80f5
        end_state[3, 0] = 0x4a43f8804b0ad882
        end_state[4, 0] = 0xe2f36b34b7be6652
        end_state[0, 1] = 0xff875921cacc9566
        end_state[1, 1] = 0x80d97b5776b3ba89
        end_state[2, 1] = 0x28debd55fc6a313b
        end_state[3, 1] = 0x03ac3d19f1e48ecc
        end_state[4, 1] = 0x78193aecc1e434e9
        end_state[0, 2] = 0xc287a923afe81e79
        end_state[1, 2] = 0x21684ae301601f33
        end_state[2, 2] = 0x282e7e469e09e75f
        end_state[3, 2] = 0xd17d1ed2c282b6b8
        end_state[4, 2] = 0xf050e0d2adaf434e
        end_state[0, 3] = 0x5375f6fb6aa989b0
        end_state[1, 3] = 0xc2c6b96032faf11e
        end_state[2, 3] = 0x63684dd3f055a1b2
        end_state[3, 3] = 0xd908398b988ec2b2
        end_state[4, 3] = 0x913f10903e0bd326
        end_state[0, 4] = 0x33fc34664d479817
        end_state[1, 4] = 0x2b715c1a078fde58
        end_state[2, 4] = 0x140b7c9251369779
        end_state[3, 4] = 0x857343a7aabdeb5e
        end_state[4, 4] = 0x92136e0efb7b70e5

        test._absorb(g)
        assert np.equal(test.state, end_state).all()


    def test_sha3_384_0_bit_absorb(self):
        test = Keccak()
        g = np.zeros((5,5), dtype=np.uint64) 
        end_state = np.zeros((5,5), dtype=np.uint64)
        g[0, 0] = 0x0000000000000006
        g[1, 0] = 0x0000000000000000
        g[2, 0] = 0x0000000000000000
        g[3, 0] = 0x0000000000000000
        g[4, 0] = 0x0000000000000000
        g[0, 1] = 0x0000000000000000
        g[1, 1] = 0x0000000000000000
        g[2, 1] = 0x0000000000000000
        g[3, 1] = 0x0000000000000000
        g[4, 1] = 0x0000000000000000
        g[0, 2] = 0x0000000000000000
        g[1, 2] = 0x0000000000000000
        g[2, 2] = 0x8000000000000000
        g[3, 2] = 0x0000000000000000
        g[4, 2] = 0x0000000000000000
        g[0, 3] = 0x0000000000000000
        g[1, 3] = 0x0000000000000000
        g[2, 3] = 0x0000000000000000
        g[3, 3] = 0x0000000000000000
        g[4, 3] = 0x0000000000000000
        g[0, 4] = 0x0000000000000000
        g[1, 4] = 0x0000000000000000
        g[2, 4] = 0x0000000000000000
        g[3, 4] = 0x0000000000000000
        g[4, 4] = 0x0000000000000000
        end_state[0, 0] = 0x7d4f5e845ba7630c
        end_state[1, 0] = 0x85244c2e857d1001
        end_state[2, 0] = 0x61fc94aaaa501ac5
        end_state[3, 0] = 0x2a3a98eebb715e99
        end_state[4, 0] = 0x47db4a26313871c3
        end_state[0, 1] = 0x04f0d558e0d16bfb
        end_state[1, 1] = 0x6896f540229c8523
        end_state[2, 1] = 0xc6c00965c5b45d1e
        end_state[3, 1] = 0xcc4fd85750fc4915
        end_state[4, 1] = 0xb0370f9ef89af029
        end_state[0, 2] = 0x0dc31e17c7666765
        end_state[1, 2] = 0xbf7cb917aa1f6137
        end_state[2, 2] = 0xbab4565ea390c7d1
        end_state[3, 2] = 0xca8ce3a302662537
        end_state[4, 2] = 0xd926482ee173ada3
        end_state[0, 3] = 0x8b11c6829ee29ecc
        end_state[1, 3] = 0xe253411c4947b1b0
        end_state[2, 3] = 0xabbc9b90bb69555b
        end_state[3, 3] = 0xe3997ccd5005ee4f
        end_state[4, 3] = 0x8018f784e68b7475
        end_state[0, 4] = 0x2cccea45cdde443e
        end_state[1, 4] = 0xa962dd46e9cb0bbc
        end_state[2, 4] = 0x7e806b1d7fffb524
        end_state[3, 4] = 0x7c15c32c0995a07e
        end_state[4, 4] = 0x1c8e91f7051dc2bf

        test._absorb(g)
        assert np.equal(test.state, end_state).all()


    def test_sha3_512_0_bit_absorb(self):
        test = Keccak()
        g = np.zeros((5,5), dtype=np.uint64) 
        end_state = np.zeros((5,5), dtype=np.uint64)
        g[0, 0] = 0x0000000000000006
        g[1, 0] = 0x0000000000000000
        g[2, 0] = 0x0000000000000000
        g[3, 0] = 0x0000000000000000
        g[4, 0] = 0x0000000000000000
        g[0, 1] = 0x0000000000000000
        g[1, 1] = 0x0000000000000000
        g[2, 1] = 0x0000000000000000
        g[3, 1] = 0x8000000000000000
        g[4, 1] = 0x0000000000000000
        g[0, 2] = 0x0000000000000000
        g[1, 2] = 0x0000000000000000
        g[2, 2] = 0x0000000000000000
        g[3, 2] = 0x0000000000000000
        g[4, 2] = 0x0000000000000000
        g[0, 3] = 0x0000000000000000
        g[1, 3] = 0x0000000000000000
        g[2, 3] = 0x0000000000000000
        g[3, 3] = 0x0000000000000000
        g[4, 3] = 0x0000000000000000
        g[0, 4] = 0x0000000000000000
        g[1, 4] = 0x0000000000000000
        g[2, 4] = 0x0000000000000000
        g[3, 4] = 0x0000000000000000
        g[4, 4] = 0x0000000000000000
        end_state[0, 0] = 0xc59a3aa2cc739fa6
        end_state[1, 0] = 0x6e755a18dc67b5c8
        end_state[2, 0] = 0x5958e24f1682c997
        end_state[3, 0] = 0xa6805c47c1dcd1e0
        end_state[4, 0] = 0x4cf9f5f13a12b215
        end_state[0, 1] = 0x58c53a2c40e9e311
        end_state[1, 1] = 0xe3d3b6959d1900f5
        end_state[2, 1] = 0x26cd1d2886857501
        end_state[3, 1] = 0xb8538fe7b8c54b36
        end_state[4, 1] = 0x00ad9fdef4a7dd23
        end_state[0, 2] = 0x0cea9f9f2fb77de6
        end_state[1, 2] = 0xc5ad765af1fec9e3
        end_state[2, 2] = 0x65fb8711fd2eeb85
        end_state[3, 2] = 0xe367513173a2c9f9
        end_state[4, 2] = 0x07d422a3b668fa14
        end_state[0, 3] = 0x888ceccd2a505d01
        end_state[1, 3] = 0x0946d0ce84774f5c
        end_state[2, 3] = 0x564b48964a1535bb
        end_state[3, 3] = 0xcd7a60887c41d325
        end_state[4, 3] = 0x9edf5eae9bc9c2e4
        end_state[0, 4] = 0x1826a255fbd02aea
        end_state[1, 4] = 0x2b3e436049d2119e
        end_state[2, 4] = 0x76970973a445e00e
        end_state[3, 4] = 0x19a89bdb39e75ddd
        end_state[4, 4] = 0xeed7a5a703b94cd5

        test._absorb(g)
        assert np.equal(test.state, end_state).all()

    def test_sha3_512_5_bit_absorb(self):
        test = Keccak()
        g = np.zeros((5,5), dtype=np.uint64) 
        end_state = np.zeros((5,5), dtype=np.uint64)
        g[0, 0] = 0x00000000000000d3
        g[1, 0] = 0x0000000000000000
        g[2, 0] = 0x0000000000000000
        g[3, 0] = 0x0000000000000000
        g[4, 0] = 0x0000000000000000
        g[0, 1] = 0x0000000000000000
        g[1, 1] = 0x0000000000000000
        g[2, 1] = 0x0000000000000000
        g[3, 1] = 0x8000000000000000
        g[4, 1] = 0x0000000000000000
        g[0, 2] = 0x0000000000000000
        g[1, 2] = 0x0000000000000000
        g[2, 2] = 0x0000000000000000
        g[3, 2] = 0x0000000000000000
        g[4, 2] = 0x0000000000000000
        g[0, 3] = 0x0000000000000000
        g[1, 3] = 0x0000000000000000
        g[2, 3] = 0x0000000000000000
        g[3, 3] = 0x0000000000000000
        g[4, 3] = 0x0000000000000000
        g[0, 4] = 0x0000000000000000
        g[1, 4] = 0x0000000000000000
        g[2, 4] = 0x0000000000000000
        g[3, 4] = 0x0000000000000000
        g[4, 4] = 0x0000000000000000
        end_state[0, 0] = 0x98c0144149013ea1
        end_state[1, 0] = 0x21438c28702a6200
        end_state[2, 0] = 0xad3c759d0370ce21
        end_state[3, 0] = 0x27cb61d9e406e0d2
        end_state[4, 0] = 0xdc4b81e581144c54
        end_state[0, 1] = 0x99e0d53367be53eb
        end_state[1, 1] = 0xb0dd8a91815e5e79
        end_state[2, 1] = 0x373f88249f2ae258
        end_state[3, 1] = 0xb2f7581270e08b33
        end_state[4, 1] = 0x7ac67698ddc6e3c8
        end_state[0, 2] = 0xaf40037d94a3e47a
        end_state[1, 2] = 0x75059af31238ef51
        end_state[2, 2] = 0x03a7ef903142c0c5
        end_state[3, 2] = 0x3297e214dc1e351b
        end_state[4, 2] = 0xe4ba0e42b0e14f45
        end_state[0, 3] = 0x43afa9563e85aed0
        end_state[1, 3] = 0xb1f4530d1b708874
        end_state[2, 3] = 0xe9cd14b82dd31777
        end_state[3, 3] = 0x701c5b00ed1f3c33
        end_state[4, 3] = 0x317b8fdd73695dec
        end_state[0, 4] = 0x6f264800047206bf
        end_state[1, 4] = 0x3a3fa165fb06f46b
        end_state[2, 4] = 0xaa18d586d4609dd8
        end_state[3, 4] = 0xcc38582047edb939
        end_state[4, 4] = 0x14c805742d72fa02

        test._absorb(g)
        assert np.equal(test.state, end_state).all()


    def test_sha3_512_30_bit_absorb(self):
        test = Keccak()
        g = np.zeros((5,5), dtype=np.uint64) 
        end_state = np.zeros((5,5), dtype=np.uint64)
        g[0, 0] = 0x00000001997b5853
        g[1, 0] = 0x0000000000000000
        g[2, 0] = 0x0000000000000000
        g[3, 0] = 0x0000000000000000
        g[4, 0] = 0x0000000000000000
        g[0, 1] = 0x0000000000000000
        g[1, 1] = 0x0000000000000000
        g[2, 1] = 0x0000000000000000
        g[3, 1] = 0x8000000000000000
        g[4, 1] = 0x0000000000000000
        g[0, 2] = 0x0000000000000000
        g[1, 2] = 0x0000000000000000
        g[2, 2] = 0x0000000000000000
        g[3, 2] = 0x0000000000000000
        g[4, 2] = 0x0000000000000000
        g[0, 3] = 0x0000000000000000
        g[1, 3] = 0x0000000000000000
        g[2, 3] = 0x0000000000000000
        g[3, 3] = 0x0000000000000000
        g[4, 3] = 0x0000000000000000
        g[0, 4] = 0x0000000000000000
        g[1, 4] = 0x0000000000000000
        g[2, 4] = 0x0000000000000000
        g[3, 4] = 0x0000000000000000
        g[4, 4] = 0x0000000000000000
        end_state[0, 0] = 0xd3c5e1115ac03498
        end_state[1, 0] = 0x9e6d101c0e749cda
        end_state[2, 0] = 0xaa6a6f0b530e0a59
        end_state[3, 0] = 0xdba55c075d523078
        end_state[4, 0] = 0x61281a98aaa6d81b
        end_state[0, 1] = 0x3c82014a9334c33a
        end_state[1, 1] = 0x697e6d9be4455fd4
        end_state[2, 1] = 0xab7b067867f1f217
        end_state[3, 1] = 0xf40150575690978b
        end_state[4, 1] = 0x404043fb1c75265a
        end_state[0, 2] = 0x969f87e437a937f6
        end_state[1, 2] = 0x50198be7f83f6e28
        end_state[2, 2] = 0xb2ea264228331b25
        end_state[3, 2] = 0x6dfd04eb9639d413
        end_state[4, 2] = 0x95efbb416373fd35
        end_state[0, 3] = 0x5f187a1723baf8e7
        end_state[1, 3] = 0x491d62d055a7293a
        end_state[2, 3] = 0x2df1a19ea83e6305
        end_state[3, 3] = 0x43e6451a508a141d
        end_state[4, 3] = 0x8978081409b48c72
        end_state[0, 4] = 0xb64fdb5807ea63e7
        end_state[1, 4] = 0x582a659483f1680f
        end_state[2, 4] = 0x26fbdcfd72f1f8d3
        end_state[3, 4] = 0x5ecd24f021afc453
        end_state[4, 4] = 0x8dc196c6d9ebc8a6

        test._absorb(g)
        assert np.equal(test.state, end_state).all()


    def test_sha3_512_1600_bit_absorb(self):
        test = Keccak()
        g = np.zeros((5,5), dtype=np.uint64) 
        end_state = np.zeros((5,5), dtype=np.uint64)
        g[0, 0] = 0xa3a3a3a3a3a3a3a3
        g[1, 0] = 0xa3a3a3a3a3a3a3a3
        g[2, 0] = 0xa3a3a3a3a3a3a3a3
        g[3, 0] = 0xa3a3a3a3a3a3a3a3
        g[4, 0] = 0xa3a3a3a3a3a3a3a3
        g[0, 1] = 0xa3a3a3a3a3a3a3a3
        g[1, 1] = 0xa3a3a3a3a3a3a3a3
        g[2, 1] = 0xa3a3a3a3a3a3a3a3
        g[3, 1] = 0xa3a3a3a3a3a3a3a3
        g[4, 1] = 0x0000000000000000
        g[0, 2] = 0x0000000000000000
        g[1, 2] = 0x0000000000000000
        g[2, 2] = 0x0000000000000000
        g[3, 2] = 0x0000000000000000
        g[4, 2] = 0x0000000000000000
        g[0, 3] = 0x0000000000000000
        g[1, 3] = 0x0000000000000000
        g[2, 3] = 0x0000000000000000
        g[3, 3] = 0x0000000000000000
        g[4, 3] = 0x0000000000000000
        g[0, 4] = 0x0000000000000000
        g[1, 4] = 0x0000000000000000
        g[2, 4] = 0x0000000000000000
        g[3, 4] = 0x0000000000000000
        g[4, 4] = 0x0000000000000000

        end_state[0, 0] = 0x05fee7b35cdf5553
        end_state[1, 0] = 0x694f0f744b9445c1
        end_state[2, 0] = 0xf723d697a25f40d2
        end_state[3, 0] = 0xcd785e4b50dcb172
        end_state[4, 0] = 0x406a228495a81bbf
        end_state[0, 1] = 0x99583d2b77e5b4e0
        end_state[1, 1] = 0xd5b3e85a4032b516
        end_state[2, 1] = 0x3ca2f36b5667ca3f
        end_state[3, 1] = 0x5f5f5616ad3a6c37
        end_state[4, 1] = 0xbbe5974f6d28f002
        end_state[0, 2] = 0x6bd68e8fb142c895
        end_state[1, 2] = 0x69f6682c901d1e20
        end_state[2, 2] = 0x5b759e2d9a3767d3
        end_state[3, 2] = 0xec1ad1f5cb283f24
        end_state[4, 2] = 0xbae2a4b773cd35a9
        end_state[0, 3] = 0xfc92bfee888f06f0
        end_state[1, 3] = 0x76ff6cf358c8c045
        end_state[2, 3] = 0x3eae92a49d040f24
        end_state[3, 3] = 0xc3f569ddf01931a0
        end_state[4, 3] = 0x2709e2f8f2976373
        end_state[0, 4] = 0x58d18798166d45f2
        end_state[1, 4] = 0xc78ccb0b13a32fbe
        end_state[2, 4] = 0xbbd1835ff259b1bd
        end_state[3, 4] = 0xbe3989d6e2d560a0
        end_state[4, 4] = 0xae7c97478945323c
        
        assert np.not_equal(test.state, end_state).all()
        test._absorb(g)
        assert np.equal(test.state, end_state).all()

        end_state[0, 0] = 0x9afd7d64e0e2074d
        end_state[1, 0] = 0xc25332097b1a6a32
        end_state[2, 0] = 0xa75498c40c18e02f
        end_state[3, 0] = 0xc96c1c6e96e9cf55
        end_state[4, 0] = 0x8fbc52dbf93c1f98
        end_state[0, 1] = 0x90576192fe57b53e
        end_state[1, 1] = 0x32feaf4a580a19a5
        end_state[2, 1] = 0x7651253f1f524f01
        end_state[3, 1] = 0x6e66126388d2e7ad
        end_state[4, 1] = 0x33a78dce191c0f5e
        end_state[0, 2] = 0x14489384a0e0eb68
        end_state[1, 2] = 0x6828ac88e0b5c8ee
        end_state[2, 2] = 0x176b5004f680c180
        end_state[3, 2] = 0xa160a572fa703837
        end_state[4, 2] = 0x4203e3406573b08a
        end_state[0, 3] = 0x35487abbb94ec283
        end_state[1, 3] = 0xd0608067c0f3239f
        end_state[2, 3] = 0x6bec7cabc148de7c
        end_state[3, 3] = 0x48cdc4e7d3de2582
        end_state[4, 3] = 0xc5fcaf2392d1e64f
        end_state[0, 4] = 0x2722fea7cf16a3eb
        end_state[1, 4] = 0xa995e7229d88999a
        end_state[2, 4] = 0xd8cf897d66badc58
        end_state[3, 4] = 0xfce11acc69584984
        end_state[4, 4] = 0x6cd837710be3c3fd

        test._absorb(g)
        assert np.equal(test.state, end_state).all()

        g[0, 0] = 0xa3a3a3a3a3a3a3a3
        g[1, 0] = 0xa3a3a3a3a3a3a3a3
        g[2, 0] = 0xa3a3a3a3a3a3a3a3
        g[3, 0] = 0xa3a3a3a3a3a3a3a3
        g[4, 0] = 0xa3a3a3a3a3a3a3a3
        g[0, 1] = 0xa3a3a3a3a3a3a3a3
        g[1, 1] = 0xa3a3a3a3a3a3a3a3
        g[2, 1] = 0x0000000000000006
        g[3, 1] = 0x8000000000000000
        g[4, 1] = 0x0000000000000000
        g[0, 2] = 0x0000000000000000
        g[1, 2] = 0x0000000000000000
        g[2, 2] = 0x0000000000000000
        g[3, 2] = 0x0000000000000000
        g[4, 2] = 0x0000000000000000
        g[0, 3] = 0x0000000000000000
        g[1, 3] = 0x0000000000000000
        g[2, 3] = 0x0000000000000000
        g[3, 3] = 0x0000000000000000
        g[4, 3] = 0x0000000000000000
        g[0, 4] = 0x0000000000000000
        g[1, 4] = 0x0000000000000000
        g[2, 4] = 0x0000000000000000
        g[3, 4] = 0x0000000000000000
        g[4, 4] = 0x0000000000000000
            
        end_state[0, 0] = 0xb1a88420d2fa6de7
        end_state[1, 0] = 0x1b3658fa2fcf7f46
        end_state[2, 0] = 0xc0fdf3f5ed2876ec
        end_state[3, 0] = 0xa8ecae8cc45d80e4
        end_state[4, 0] = 0xa352df0ac3137c1b
        end_state[0, 1] = 0x6bf42d9a73849565
        end_state[1, 1] = 0x41a8a4a11cc589e5
        end_state[2, 1] = 0x00bae81c5a54f66d
        end_state[3, 1] = 0x89a5446c2b6d1586
        end_state[4, 1] = 0xcf4bfdac6988edca
        end_state[0, 2] = 0xaaec261f9d6e28ea
        end_state[1, 2] = 0xc8855866496eeb39
        end_state[2, 2] = 0x5eaa2033b2916e95
        end_state[3, 2] = 0x5c77e7a6fb6303d0
        end_state[4, 2] = 0xa9955b447982e170
        end_state[0, 3] = 0x6b9948935ec4c58e
        end_state[1, 3] = 0x3ecac2175a46b9bc
        end_state[2, 3] = 0xadf1d9af0e2ba9fb
        end_state[3, 3] = 0xe6e813208c7d3ccc
        end_state[4, 3] = 0x588aa0556aab16a2
        end_state[0, 4] = 0x1a7bb8b1e24a7cd9
        end_state[1, 4] = 0x9152129384fe9d59
        end_state[2, 4] = 0xced720728337769f
        end_state[3, 4] = 0x8a5573f39620a04d
        end_state[4, 4] = 0x9269a79dfaa39946

        test._absorb(g)
        assert np.equal(test.state, end_state).all()

    def test_sha3_512_1605_bit_absorb(self):
        test = Keccak()
        g = np.zeros((5,5), dtype=np.uint64) 
        end_state = np.zeros((5,5), dtype=np.uint64)
        g[0, 0] = 0xa3a3a3a3a3a3a3a3
        g[1, 0] = 0xa3a3a3a3a3a3a3a3
        g[2, 0] = 0xa3a3a3a3a3a3a3a3
        g[3, 0] = 0xa3a3a3a3a3a3a3a3
        g[4, 0] = 0xa3a3a3a3a3a3a3a3
        g[0, 1] = 0xa3a3a3a3a3a3a3a3
        g[1, 1] = 0xa3a3a3a3a3a3a3a3
        g[2, 1] = 0xa3a3a3a3a3a3a3a3
        g[3, 1] = 0xa3a3a3a3a3a3a3a3
        g[4, 1] = 0x0000000000000000
        g[0, 2] = 0x0000000000000000
        g[1, 2] = 0x0000000000000000
        g[2, 2] = 0x0000000000000000
        g[3, 2] = 0x0000000000000000
        g[4, 2] = 0x0000000000000000
        g[0, 3] = 0x0000000000000000
        g[1, 3] = 0x0000000000000000
        g[2, 3] = 0x0000000000000000
        g[3, 3] = 0x0000000000000000
        g[4, 3] = 0x0000000000000000
        g[0, 4] = 0x0000000000000000
        g[1, 4] = 0x0000000000000000
        g[2, 4] = 0x0000000000000000
        g[3, 4] = 0x0000000000000000
        g[4, 4] = 0x0000000000000000

        end_state[0, 0] = 0x05fee7b35cdf5553
        end_state[1, 0] = 0x694f0f744b9445c1
        end_state[2, 0] = 0xf723d697a25f40d2
        end_state[3, 0] = 0xcd785e4b50dcb172
        end_state[4, 0] = 0x406a228495a81bbf
        end_state[0, 1] = 0x99583d2b77e5b4e0
        end_state[1, 1] = 0xd5b3e85a4032b516
        end_state[2, 1] = 0x3ca2f36b5667ca3f
        end_state[3, 1] = 0x5f5f5616ad3a6c37
        end_state[4, 1] = 0xbbe5974f6d28f002
        end_state[0, 2] = 0x6bd68e8fb142c895
        end_state[1, 2] = 0x69f6682c901d1e20
        end_state[2, 2] = 0x5b759e2d9a3767d3
        end_state[3, 2] = 0xec1ad1f5cb283f24
        end_state[4, 2] = 0xbae2a4b773cd35a9
        end_state[0, 3] = 0xfc92bfee888f06f0
        end_state[1, 3] = 0x76ff6cf358c8c045
        end_state[2, 3] = 0x3eae92a49d040f24
        end_state[3, 3] = 0xc3f569ddf01931a0
        end_state[4, 3] = 0x2709e2f8f2976373
        end_state[0, 4] = 0x58d18798166d45f2
        end_state[1, 4] = 0xc78ccb0b13a32fbe
        end_state[2, 4] = 0xbbd1835ff259b1bd
        end_state[3, 4] = 0xbe3989d6e2d560a0
        end_state[4, 4] = 0xae7c97478945323c
        
        assert np.not_equal(test.state, end_state).all()
        test._absorb(g)
        assert np.equal(test.state, end_state).all()

        end_state[0, 0] = 0x9afd7d64e0e2074d
        end_state[1, 0] = 0xc25332097b1a6a32
        end_state[2, 0] = 0xa75498c40c18e02f
        end_state[3, 0] = 0xc96c1c6e96e9cf55
        end_state[4, 0] = 0x8fbc52dbf93c1f98
        end_state[0, 1] = 0x90576192fe57b53e
        end_state[1, 1] = 0x32feaf4a580a19a5
        end_state[2, 1] = 0x7651253f1f524f01
        end_state[3, 1] = 0x6e66126388d2e7ad
        end_state[4, 1] = 0x33a78dce191c0f5e
        end_state[0, 2] = 0x14489384a0e0eb68
        end_state[1, 2] = 0x6828ac88e0b5c8ee
        end_state[2, 2] = 0x176b5004f680c180
        end_state[3, 2] = 0xa160a572fa703837
        end_state[4, 2] = 0x4203e3406573b08a
        end_state[0, 3] = 0x35487abbb94ec283
        end_state[1, 3] = 0xd0608067c0f3239f
        end_state[2, 3] = 0x6bec7cabc148de7c
        end_state[3, 3] = 0x48cdc4e7d3de2582
        end_state[4, 3] = 0xc5fcaf2392d1e64f
        end_state[0, 4] = 0x2722fea7cf16a3eb
        end_state[1, 4] = 0xa995e7229d88999a
        end_state[2, 4] = 0xd8cf897d66badc58
        end_state[3, 4] = 0xfce11acc69584984
        end_state[4, 4] = 0x6cd837710be3c3fd

        test._absorb(g)
        assert np.equal(test.state, end_state).all()

        g[0, 0] = 0xa3a3a3a3a3a3a3a3
        g[1, 0] = 0xa3a3a3a3a3a3a3a3
        g[2, 0] = 0xa3a3a3a3a3a3a3a3
        g[3, 0] = 0xa3a3a3a3a3a3a3a3
        g[4, 0] = 0xa3a3a3a3a3a3a3a3
        g[0, 1] = 0xa3a3a3a3a3a3a3a3
        g[1, 1] = 0xa3a3a3a3a3a3a3a3
        g[2, 1] = 0x00000000000000c3
        g[3, 1] = 0x8000000000000000
        g[4, 1] = 0x0000000000000000
        g[0, 2] = 0x0000000000000000
        g[1, 2] = 0x0000000000000000
        g[2, 2] = 0x0000000000000000
        g[3, 2] = 0x0000000000000000
        g[4, 2] = 0x0000000000000000
        g[0, 3] = 0x0000000000000000
        g[1, 3] = 0x0000000000000000
        g[2, 3] = 0x0000000000000000
        g[3, 3] = 0x0000000000000000
        g[4, 3] = 0x0000000000000000
        g[0, 4] = 0x0000000000000000
        g[1, 4] = 0x0000000000000000
        g[2, 4] = 0x0000000000000000
        g[3, 4] = 0x0000000000000000
        g[4, 4] = 0x0000000000000000
            
        end_state[0, 0] = 0x37a931cb7c164afc
        end_state[1, 0] = 0x8c34042be8fd98d6
        end_state[2, 0] = 0x453b9d0c8fb23995
        end_state[3, 0] = 0xe4502381039c7005
        end_state[4, 0] = 0x576e4f9722960e99
        end_state[0, 1] = 0x8c632e0d1c86475c
        end_state[1, 1] = 0x0ab65b363c02c2cf
        end_state[2, 1] = 0x6b7898065528f593
        end_state[3, 1] = 0x56ba69b6170ec418
        end_state[4, 1] = 0x20fad2841a70ae60
        end_state[0, 2] = 0xe00babf21f7b4bc5
        end_state[1, 2] = 0xef903290b2e33ff9
        end_state[2, 2] = 0x8b75f3907850dea5
        end_state[3, 2] = 0x34fd6b59aa12f848
        end_state[4, 2] = 0x3dddcf00a4db5683
        end_state[0, 3] = 0x8325bc21134542ee
        end_state[1, 3] = 0x22c1a5788bb5a8c1
        end_state[2, 3] = 0x4ce8ccbfd95c3c8b
        end_state[3, 3] = 0x85348fd7b17ae2c5
        end_state[4, 3] = 0x43512da35101ec65
        end_state[0, 4] = 0xe46b3fe4337cc441
        end_state[1, 4] = 0xb57c0bba7b631258
        end_state[2, 4] = 0xd23d3f639db4e36e
        end_state[3, 4] = 0xbd3e653f313ce82b
        end_state[4, 4] = 0x3dc9175552aa7835

        test._absorb(g)
        assert np.equal(test.state, end_state).all()



    def test_sha3_512_1630_bit_absorb(self):
        test = Keccak()
        g = np.zeros((5,5), dtype=np.uint64) 
        end_state = np.zeros((5,5), dtype=np.uint64)
        g[0, 0] = 0xa3a3a3a3a3a3a3a3
        g[1, 0] = 0xa3a3a3a3a3a3a3a3
        g[2, 0] = 0xa3a3a3a3a3a3a3a3
        g[3, 0] = 0xa3a3a3a3a3a3a3a3
        g[4, 0] = 0xa3a3a3a3a3a3a3a3
        g[0, 1] = 0xa3a3a3a3a3a3a3a3
        g[1, 1] = 0xa3a3a3a3a3a3a3a3
        g[2, 1] = 0xa3a3a3a3a3a3a3a3
        g[3, 1] = 0xa3a3a3a3a3a3a3a3
        g[4, 1] = 0x0000000000000000
        g[0, 2] = 0x0000000000000000
        g[1, 2] = 0x0000000000000000
        g[2, 2] = 0x0000000000000000
        g[3, 2] = 0x0000000000000000
        g[4, 2] = 0x0000000000000000
        g[0, 3] = 0x0000000000000000
        g[1, 3] = 0x0000000000000000
        g[2, 3] = 0x0000000000000000
        g[3, 3] = 0x0000000000000000
        g[4, 3] = 0x0000000000000000
        g[0, 4] = 0x0000000000000000
        g[1, 4] = 0x0000000000000000
        g[2, 4] = 0x0000000000000000
        g[3, 4] = 0x0000000000000000
        g[4, 4] = 0x0000000000000000

        end_state[0, 0] = 0x05fee7b35cdf5553
        end_state[1, 0] = 0x694f0f744b9445c1
        end_state[2, 0] = 0xf723d697a25f40d2
        end_state[3, 0] = 0xcd785e4b50dcb172
        end_state[4, 0] = 0x406a228495a81bbf
        end_state[0, 1] = 0x99583d2b77e5b4e0
        end_state[1, 1] = 0xd5b3e85a4032b516
        end_state[2, 1] = 0x3ca2f36b5667ca3f
        end_state[3, 1] = 0x5f5f5616ad3a6c37
        end_state[4, 1] = 0xbbe5974f6d28f002
        end_state[0, 2] = 0x6bd68e8fb142c895
        end_state[1, 2] = 0x69f6682c901d1e20
        end_state[2, 2] = 0x5b759e2d9a3767d3
        end_state[3, 2] = 0xec1ad1f5cb283f24
        end_state[4, 2] = 0xbae2a4b773cd35a9
        end_state[0, 3] = 0xfc92bfee888f06f0
        end_state[1, 3] = 0x76ff6cf358c8c045
        end_state[2, 3] = 0x3eae92a49d040f24
        end_state[3, 3] = 0xc3f569ddf01931a0
        end_state[4, 3] = 0x2709e2f8f2976373
        end_state[0, 4] = 0x58d18798166d45f2
        end_state[1, 4] = 0xc78ccb0b13a32fbe
        end_state[2, 4] = 0xbbd1835ff259b1bd
        end_state[3, 4] = 0xbe3989d6e2d560a0
        end_state[4, 4] = 0xae7c97478945323c
        
        assert np.not_equal(test.state, end_state).all()
        test._absorb(g)
        assert np.equal(test.state, end_state).all()

        end_state[0, 0] = 0x9afd7d64e0e2074d
        end_state[1, 0] = 0xc25332097b1a6a32
        end_state[2, 0] = 0xa75498c40c18e02f
        end_state[3, 0] = 0xc96c1c6e96e9cf55
        end_state[4, 0] = 0x8fbc52dbf93c1f98
        end_state[0, 1] = 0x90576192fe57b53e
        end_state[1, 1] = 0x32feaf4a580a19a5
        end_state[2, 1] = 0x7651253f1f524f01
        end_state[3, 1] = 0x6e66126388d2e7ad
        end_state[4, 1] = 0x33a78dce191c0f5e
        end_state[0, 2] = 0x14489384a0e0eb68
        end_state[1, 2] = 0x6828ac88e0b5c8ee
        end_state[2, 2] = 0x176b5004f680c180
        end_state[3, 2] = 0xa160a572fa703837
        end_state[4, 2] = 0x4203e3406573b08a
        end_state[0, 3] = 0x35487abbb94ec283
        end_state[1, 3] = 0xd0608067c0f3239f
        end_state[2, 3] = 0x6bec7cabc148de7c
        end_state[3, 3] = 0x48cdc4e7d3de2582
        end_state[4, 3] = 0xc5fcaf2392d1e64f
        end_state[0, 4] = 0x2722fea7cf16a3eb
        end_state[1, 4] = 0xa995e7229d88999a
        end_state[2, 4] = 0xd8cf897d66badc58
        end_state[3, 4] = 0xfce11acc69584984
        end_state[4, 4] = 0x6cd837710be3c3fd

        test._absorb(g)
        assert np.equal(test.state, end_state).all()

        g[0, 0] = 0xa3a3a3a3a3a3a3a3
        g[1, 0] = 0xa3a3a3a3a3a3a3a3
        g[2, 0] = 0xa3a3a3a3a3a3a3a3
        g[3, 0] = 0xa3a3a3a3a3a3a3a3
        g[4, 0] = 0xa3a3a3a3a3a3a3a3
        g[0, 1] = 0xa3a3a3a3a3a3a3a3
        g[1, 1] = 0xa3a3a3a3a3a3a3a3
        g[2, 1] = 0x00000001a3a3a3a3
        g[3, 1] = 0x8000000000000000
        g[4, 1] = 0x0000000000000000
        g[0, 2] = 0x0000000000000000
        g[1, 2] = 0x0000000000000000
        g[2, 2] = 0x0000000000000000
        g[3, 2] = 0x0000000000000000
        g[4, 2] = 0x0000000000000000
        g[0, 3] = 0x0000000000000000
        g[1, 3] = 0x0000000000000000
        g[2, 3] = 0x0000000000000000
        g[3, 3] = 0x0000000000000000
        g[4, 3] = 0x0000000000000000
        g[0, 4] = 0x0000000000000000
        g[1, 4] = 0x0000000000000000
        g[2, 4] = 0x0000000000000000
        g[3, 4] = 0x0000000000000000
        g[4, 4] = 0x0000000000000000
            
        end_state[0, 0] = 0xc06a1f1fac309acf
        end_state[1, 0] = 0x95c51919ef9f6f91
        end_state[2, 0] = 0x1242850ce82ebede
        end_state[3, 0] = 0x3af76a1c5ff0fd10
        end_state[4, 0] = 0xb61df9d081c8caa9
        end_state[0, 1] = 0x7fcfc1adbba234d0
        end_state[1, 1] = 0x3a1d199dfaecb2bc
        end_state[2, 1] = 0xc90987ad3ffb1650
        end_state[3, 1] = 0xcc02c05dbe8af4af
        end_state[4, 1] = 0xcf128e22f9071313
        end_state[0, 2] = 0x5d8fdcb1cfafede9
        end_state[1, 2] = 0x0e7ca49e715cb201
        end_state[2, 2] = 0x485e462e7de383b2
        end_state[3, 2] = 0x6a5ffcefb4ced1e6
        end_state[4, 2] = 0x25c945eab2a6cfb9
        end_state[0, 3] = 0xcd34ef58258121cf
        end_state[1, 3] = 0x9059cbe73ed23a22
        end_state[2, 3] = 0x56270df83ddb6899
        end_state[3, 3] = 0x92195956ba3c284a
        end_state[4, 3] = 0x02ac52cf84ebcdad
        end_state[0, 4] = 0x823dcdcf899a4321
        end_state[1, 4] = 0x5135ee0a224cbd37
        end_state[2, 4] = 0x6a33c35f116b16c1
        end_state[3, 4] = 0x4b12a6bb7d12753a
        end_state[4, 4] = 0xcf5dd477c8b5b750

        test._absorb(g)
        assert np.equal(test.state, end_state).all()