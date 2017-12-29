# kravatte.py
import numpy as np


class Kravatte(object):
    KECCACK_BYTES = 200
    KECCAK_LANES = 25
    KECCAK_PLANES_SLICES = 5

    KECCAK_ROUND_CONSTANTS = np.array([0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
                                       0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
                                       0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
                                       0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
                                       0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
                                       0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
                                       0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
                                       0x8000000000008080, 0x0000000080000001, 0x8000000080008008],
                                       dtype=np.uint64)
    def __init__(self, key=b''):
        self.update_key(key)
        self.reset_state()

    def update_key(self, key):
        """ Pad/Compute Key """
        key_pad = self._pad_10(key, self.KECCACK_BYTES)
        key_array = np.frombuffer(key_pad, dtype=np.uint64, count=self.KECCAK_LANES, offset=0).reshape([self.KECCAK_PLANES_SLICES, self.KECCAK_PLANES_SLICES], order='F')
        self.kra_key = self._keecak(key_array, 6)

    def reset_state(self):
        self.roll_key = np.copy(self.kra_key)
        self.collector = np.zeros([5, 5], dtype=np.uint64)
        self.digest = b''
        self.digest_active = False
        self.new_collector = True

    def collect_message(self, message):
        """ 
        Pad and Process Blocks of Message into collector block 

        Inputs:
            message (bytes)
        """
        if self.digest_active:
            self.reset_state()
        
        if self.new_collector:
            self.new_collector = False
        else:    
            self.roll_key = self._kravatte_roll(self.roll_key)

        # Pad Message
        msg_len = len(message)
        kra_msg = self._pad_10(message, msg_len + (200 - (msg_len % 200)))
        absorb_steps = len(kra_msg) // 200

        # Absorb into Collector
        for msg_block in range(absorb_steps):
            m = np.frombuffer(kra_msg, dtype=np.uint64, count=25, offset=msg_block * 200).reshape([5, 5], order='F')
            m_k = m ^ self.roll_key
            self.roll_key = self._kravatte_roll(self.roll_key)
            self.collector = self.collector ^ self._keecak(m_k, 6)

    def generate_digest(self, output_size):

        """ Squeeze Collector """
        if not self.digest_active:
            self.collector = self._keecak(self.collector, 4)
            self.roll_key = self._kravatte_roll(self.roll_key)
            self.digest_active = True

        full_output_size = output_size + (200 - (output_size % 200)) if output_size % 200 else output_size
        generate_steps = full_output_size // 200

        for _ in range(generate_steps):
            collector_squeeze = self._keecak(self.collector, 4)
            self.collector = self._kravatte_roll(self.collector)
            self.digest += (collector_squeeze ^ self.roll_key).swapaxes(0, 1).tobytes()

        self.digest = self.digest[:output_size]

    def _keecak(self, input_array, rounds_limit):

        # print('Running Keccak %s' % rounds_limit)
        state = np.copy(input_array)

        for round_num in range(24 - rounds_limit, 24):

            #theta_step:
            tmp_array = np.copy(state)
            array_shift = np.left_shift(state, 1) | np.right_shift(state, 63)
            for out_slice, (norm_slice, shift_slice) in enumerate([(4, 1), (0, 2), (1, 3), (2, 4), (3, 0)]):
                c1 = tmp_array[norm_slice, 0] ^ tmp_array[norm_slice, 1] ^ tmp_array[norm_slice, 2] ^ tmp_array[norm_slice, 3] ^ tmp_array[norm_slice, 4]
                c2 = array_shift[shift_slice, 0] ^ array_shift[shift_slice, 1] ^ array_shift[shift_slice, 2] ^ array_shift[shift_slice, 3] ^ array_shift[shift_slice, 4]
                d = c1 ^ c2
                state[out_slice] = state[out_slice] ^ d

            #rho_step:
            tmp_array = np.copy(state)
            tracking_index = (1, 0)
            for t in range(24):
                t_shift = ((t + 1) * (t + 2) >> 1)
                t_mod = t_shift % 64
                target_lane = tmp_array[tracking_index] << np.uint64(
                    t_mod) | tmp_array[tracking_index] >> np.uint64(64 - t_mod)
                state[tracking_index] = target_lane
                tracking_index = (tracking_index[1], ((
                    2 * tracking_index[0]) + (3 * tracking_index[1])) % 5)

            #pi_step:
            tmp_array = np.copy(state)
            it = np.nditer(tmp_array, flags=['multi_index'])
            while not it.finished:
                new_index = (it.multi_index[1], ((
                    2 * it.multi_index[0]) + (3 * it.multi_index[1])) % 5)
                state[new_index] = it[0]
                it.iternext()

            #chi_step:
            tmp_array = np.copy(state)
            it = np.nditer(tmp_array, flags=['multi_index'])
            while not it.finished:
                invert_lane = ~tmp_array[(it.multi_index[0] + 1) % 5, it.multi_index[1]]
                and_lane = tmp_array[(it.multi_index[0] + 2) % 5, it.multi_index[1]]
                new_value = (invert_lane & and_lane) ^ it[0]
                state[it.multi_index] = new_value
                it.iternext()

            #iota_step:
            state[0, 0] ^= self.KECCAK_ROUND_CONSTANTS[round_num]

        return state

    @staticmethod
    def _kravatte_roll(input_array):
        state = np.copy(input_array)
        tmp_plane = state[0:5, 4]
        lane_0 = tmp_plane[0]
        tmp_plane[0] = tmp_plane[1]
        tmp_plane[1] = tmp_plane[2]
        tmp_plane[2] = tmp_plane[3]
        tmp_plane[3] = tmp_plane[4]
        rotate_lane = ((lane_0 << np.uint64(7)) | (lane_0 >> np.uint64(57)))
        tmp_plane[4] = rotate_lane ^ tmp_plane[0] ^ (tmp_plane[0] >> np.uint64(3))
        state[0:5, 4] = tmp_plane
        return state

    @staticmethod
    def _pad_10(input_bytes, desired_length):
        start_len = len(input_bytes)
        if start_len == desired_length:
            return input_bytes
        pad_len = desired_length - (start_len % desired_length)
        padded_bytes = input_bytes + b'\x01' + (b'\x00' * (pad_len - 1))
        return padded_bytes


def mac(key, message, output_size):
    kravatte_mac_gen = Kravatte(key)
    kravatte_mac_gen.collect_message(message)
    kravatte_mac_gen.generate_digest(output_size)
    return kravatte_mac_gen.digest


if __name__ == "__main__":
    from time import monotonic
    my_key = b'\xFF' * 32
    my_messge = bytes([x % 256 for x in range(120000)])
    start = monotonic()
    my_kra = mac(my_key, my_messge, 2*1024*1024)
    stop = monotonic()
    print("Process Time:", stop-start)
    # print(' '.join('{:02x}'.format(x) for x in my_kra))
    print(len(my_kra))
