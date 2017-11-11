import numpy as np


class KeccakCfg:
    sha3_224, sha3_256, sha3_384, sha3_512, kravatte_pb, kravatte_pc, kravatte_pd, kravatte_pe = range(8)


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

    def __init__(self, mode, rounds=24):

        #TODO 
        self.width = 1600 / 8
        # SHA3-512 
        self.capacity = 1024 / 8
        self.rate = (self.width - self.capacity)
        self.lane = np.uint64
        self.state = np.zeros((5, 5), dtype=self.lane)
        
        if mode <= KeccakCfg.sha3_512:
            self.rounds = 24
        elif mode <= KeccakCfg.kravatte_pc:
            self.rounds = 6
        elif mode <= KeccakCfg.kravatte_pc:
            self.rounds = 4
        else:
            self.rounds = rounds
 
    def _absorb(self, input_array):

        self.state = np.bitwise_xor(self.state, input_array)

        for round_num in range(self.rounds):

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

if __name__ == '__main__':
    test = Keccak()