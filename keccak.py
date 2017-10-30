import numpy as np


class Keccak(object):
    ROUND_CONSTANTS = np.array([0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
                                0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
                                0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
                                0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
                                0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
                                0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
                                0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
                                0x8000000000008080, 0x0000000080000001, 0x8000000080008008],
                                dtype=np.uint64)

    def __init__(self):

        #TODO 
        self.width = 1600 / 8
        # SHA3-512 
        self.capacity = 1024 / 8
        self.rate = (self.width - self.capacity)
        self.lane = np.uint64
        self.state = np.zeros((5, 5), dtype=self.lane) 
 
    def _absorb(self, input_array):

        self.state = np.bitwise_xor(self.state, input_array)

        for round_num in range(24):

            #theta_step:
            tmp_array = np.copy(self.state)
            array_shift = np.left_shift(self.state, 1) + np.right_shift(self.state, 63)
            for x in range(5):
                c1 = tmp_array[(x-1)%5, 0] ^ tmp_array[(x-1)%5, 1] ^ tmp_array[(x-1)%5,2] ^ tmp_array[(x-1)%5,3] ^ tmp_array[(x-1)%5, 4]
                c2 = array_shift[(x+1)%5, 0] ^ array_shift[(x+1)%5, 1] ^ array_shift[(x+1)%5, 2] ^ array_shift[(x+1)%5, 3] ^ array_shift[(x+1)%5, 4]
                d = c1 ^ c2
                for y in range(5):
                    self.state[x, y] = self.state[x, y] ^ d

            #rho_step:
            tmp_array = np.copy(self.state)
            tracking_index = (1,0)
            for t in range(24):
                t_shift = ((t+1)*(t+2) >> 1)
                t_mod = t_shift % 64
                target_lane = np.array([tmp_array[tracking_index]], dtype=np.uint64)
                target_lane = np.left_shift([tmp_array[tracking_index]], t_mod) + np.right_shift([tmp_array[tracking_index]], 64-t_mod)
                self.state[tracking_index] = target_lane
                tracking_index = (tracking_index[1], ((2*tracking_index[0])+(3*tracking_index[1])) % 5)    

            #pi_step:
            tmp_array = np.copy(self.state)
            it = np.nditer(tmp_array, flags=['multi_index'])
            while not it.finished:
                new_index = (it.multi_index[1], ((2*it.multi_index[0])+(3*it.multi_index[1])) % 5)
                self.state[new_index] = it[0]
                it.iternext()
        
            #chi_step:
            tmp_array = np.copy(self.state)
            it = np.nditer(tmp_array, flags=['multi_index'])
            while not it.finished:
                invert_lane = ~tmp_array[(it.multi_index[0] + 1) % 5, it.multi_index[1]]
                and_lane = tmp_array[(it.multi_index[0] + 2) % 5, it.multi_index[1]]
                new_value = (invert_lane & and_lane) ^ it[0]
                self.state[it.multi_index] = new_value
                it.iternext()

            #iota_step:
            self.state[0, 0] ^= self.ROUND_CONSTANTS[round_num]



















def theta_step(input_array):
    # j = np.zeros((5), dtype=np.uint64)
    # k = np.zeros((5), dtype=np.uint64)
    # m = np.zeros((5), dtype=np.uint64)
    array_out = np.zeros((5, 5), dtype=np.uint64) 
    array_shift = np.left_shift(input_array, 1) + np.right_shift(input_array, 63)
    for x in range(5):
        c1= input_array[(x-1)%5, 0] ^ input_array[(x-1)%5, 1] ^ input_array[(x-1)%5,2] ^ input_array[(x-1)%5,3] ^ input_array[(x-1)%5,4]
        c2 = array_shift[(x+1)%5, 0] ^ array_shift[(x+1)%5, 1] ^ array_shift[(x+1)%5,2] ^ array_shift[(x+1)%5,3] ^ array_shift[(x+1)%5,4]
        d = c1 ^ c2
        for y in range(5):
            array_out[x, y] = input_array[x, y] ^ d
        # k = g_shift[h,0] ^ g_shift[(h,1] ^ g_shift[(h,2] ^ g_shift[(h,3] ^ g_shift[(h,4]
        # j = g[(h-1)%5,0] ^ g[(h-1)%5,1] ^ g[(h-1)%5,2] ^ g[(h-1)%5,3] ^ g[(h-1)%5,4]
        # print(hex(j))
    return array_out

def rho_step(input_array):
    out_array = np.zeros((5, 5), dtype=np.uint64)
    out_array[0, 0] = input_array[0, 0]
    tracking_index = (1,0)
    for t in range(24):
        t_shift = ((t+1)*(t+2) >> 1)
        t_mod = t_shift % 64
        target_lane = np.array([input_array[tracking_index]], dtype=np.uint64)
        target_lane = np.left_shift([input_array[tracking_index]], t_mod) + np.right_shift([input_array[tracking_index]], 64-t_mod)
        out_array[tracking_index] = target_lane
        tracking_index = (tracking_index[1], ((2*tracking_index[0])+(3*tracking_index[1])) % 5)    
    return out_array


def pi_step(input_array):
    out_array = np.zeros((5, 5), dtype=np.uint64)
    it = np.nditer(input_array, flags=['multi_index'])
    while not it.finished:
        new_index = (it.multi_index[1], ((2*it.multi_index[0])+(3*it.multi_index[1])) % 5)
        # out_array[new_index] = input_array[it.multi_index]
        out_array[new_index] = it[0]
        it.iternext()
    return out_array


def chi_step(input_array):
    out_array = np.zeros((5, 5), dtype=np.uint64)
    it = np.nditer(input_array, flags=['multi_index'])
    while not it.finished:
        invert_lane = ~input_array[(it.multi_index[0] + 1) % 5, it.multi_index[1]]
        and_lane = input_array[(it.multi_index[0] + 2) % 5, it.multi_index[1]]
        new_value = (invert_lane & and_lane) ^ it[0]
        out_array[it.multi_index] = new_value
        it.iternext()
    return out_array

def iota_step(input_array, round_num):
    out_array = input_array
    out_array[0, 0] ^= ROUND_CONSTANTS[round_num] 
    return out_array

if __name__ == '__main__':

    # h = bytes([x for x in range(200)])
    # g = np.array([5,5])
    test = Keccak()
    g = np.zeros((5,5), dtype=np.uint64) 
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

    end_state = np.zeros((5,5), dtype=np.uint64)
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


    np.set_printoptions(formatter={'int':hex})
    print(g)

    # for b in range(5):
    #     for v in range(5):
    #         print('state[%d,%d] = %016X' % (v, b, test.state[v, b]))


    # g = np.zeros((5,5), dtype=np.uint64) 
    # g[0, 0] = 0xa3a3a3a3a3a3a3a3
    # g[1, 0] = 0xa3a3a3a3a3a3a3a3
    # g[2, 0] = 0xa3a3a3a3a3a3a3a3
    # g[3, 0] = 0xa3a3a3a3a3a3a3a3
    # g[4, 0] = 0xa3a3a3a3a3a3a3a3
    # g[0, 1] = 0xa3a3a3a3a3a3a3a3
    # g[1, 1] = 0xa3a3a3a3a3a3a3a3
    # g[2, 1] = 0xa3a3a3a3a3a3a3a3
    # g[3, 1] = 0xa3a3a3a3a3a3a3a3
    # g[4, 1] = 0x0000000000000000
    # g[0, 2] = 0x0000000000000000
    # g[1, 2] = 0x0000000000000000
    # g[2, 2] = 0x0000000000000000
    # g[3, 2] = 0x0000000000000000
    # g[4, 2] = 0x0000000000000000
    # g[0, 3] = 0x0000000000000000
    # g[1, 3] = 0x0000000000000000
    # g[2, 3] = 0x0000000000000000
    # g[3, 3] = 0x0000000000000000
    # g[4, 3] = 0x0000000000000000
    # g[0, 4] = 0x0000000000000000
    # g[1, 4] = 0x0000000000000000
    # g[2, 4] = 0x0000000000000000
    # g[3, 4] = 0x0000000000000000
    # g[4, 4] = 0x0000000000000000

    # for r in range(24):
    #     print("Round: ", r)
    #     g = theta_step(g)
    #     print("Output of Theta")
    #     for b in range(5):
    #         for v in range(5):
    #             print('g[%d,%d] = %X' % (v, b, g[v,b]))

    #     g = rho_step(g)
    #     print("Output of Rho")
    #     for b in range(5):
    #         for v in range(5):
    #             print('g[%d,%d] = %X' % (v, b, g[v,b]))

    #     g = pi_step(g)
    #     print("Output of Pi")
    #     for b in range(5):
    #         for v in range(5):
    #             print('g[%d,%d] = %X' % (v, b, g[v, b]))

    #     g = chi_step(g)
    #     print("Output of Chi")
    #     for b in range(5):
    #         for v in range(5):
    #             print('g[%d,%d] = %X' % (v, b, g[v, b]))

    #     g = iota_step(g, r)
    #     print("Output of Iota")
    #     for b in range(5):
    #         for v in range(5):
    #             print('g[%d,%d] = %016X' % (v, b, g[v, b]))






# it = np.nditer(input_array, flags=['multi_index'])
    # print(dir(it))
    # while not it.finished:
    #     print(it.iterindex)
    #     t = it.iterindex
    #     t_shift = ((t+1)*(t+2) >> 1)
    #     t_mod = t_shift % 64
    #     print("%s  %s  %s" % (t, t_shift, t_mod))
    #     array_shift = np.left_shift(input_array, 1) + np.right_shift(input_array, 63)

        
    #     new_index = (it.multi_index[1], ((2*it.multi_index[0])+(3*it.multi_index[1])) % 5)
    #     # print("new index: %d %d " % (it.multi_index[1],((2*it.multi_index[0])+(3*it.multi_index[1])) % 5))

    #     print("%d,%d: %X -> %s: %X " % (it.multi_index[0],
    #                                     it.multi_index[1],
    #                                     it[0],
    #                                     new_index,
    #                                     out_array[it.multi_index[0],it.multi_index[1]]))
    #     print('')
    #     it.iternext()
    # array_out = input_array