# kravatte.py
import numpy as np
from operator import xor
from functools import reduce

KECCAK_ROUND_CONSTANTS = np.array([0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
                                   0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
                                   0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
                                   0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
                                   0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
                                   0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
                                   0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
                                   0x8000000000008080, 0x0000000080000001, 0x8000000080008008],
                                   dtype=np.uint64)

class Kravatte (object):
    KECCAK_ROUND_CONSTANTS = np.array([0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
                                   0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
                                   0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
                                   0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
                                   0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
                                   0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
                                   0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
                                   0x8000000000008080, 0x0000000080000001, 0x8000000080008008],
                                   dtype=np.uint64)
    def __init__(self):
        pass
    
    @staticmethod
    def mac(key, message, output_size):

        """ Pad/Compute Key """
        key_pad = pad_10(key, 200)
        key_array = np.frombuffer(key_pad, dtype=np.uint64, count=25, offset=0).reshape([5, 5], order='F')
        kra_key = keecak(key_array, 6)

        """ Pad Message """
        msg_len = len(message)
        kra_msg = pad_10(message, msg_len + (200 - (msg_len % 200)))
        collector = np.zeros([5, 5], dtype=np.uint64)
        absorb_steps = len(kra_msg) // 200

        """ Absorb into Collector """
        for x in range(absorb_steps):
            m = np.frombuffer(kra_msg, dtype=np.uint64, count=25, offset=x * 200).reshape([5, 5], order='F')
            m_k = m ^ kra_key
            kra_key = kravatte_roll_single(kra_key)
            collector = collector ^ keecak(m_k, 6)

        """ Squeeze Collector """
        collector = keecak(collector, 4)
        kra_key = kravatte_roll_single(kra_key)

        full_output_size = output_size + \
            (200 - (output_size % 200)) if output_size % 200 else output_size
        squeeze_steps = full_output_size // 200
        output_buffer = b''

        for x in range(squeeze_steps):
            collector_squeeze = keecak(collector, 4)
            collector = kravatte_roll_single(collector)
            output_buffer += (collector_squeeze ^ kra_key).swapaxes(0, 1).tobytes()

        return output_buffer[:output_size]

    # def keecak(self, input_array, rounds_limit):

    #     # print('Running Keccak %s' % rounds_limit)
    #     state = np.copy(input_array)

    #     for round_num in range(24 - rounds_limit, 24):

    #         #theta_step:
    #         tmp_array = np.copy(state)
    #         array_shift = np.left_shift(state, 1) | np.right_shift(state, 63)
    #         for x in range(5):
    #             c1 = tmp_array[(x - 1) % 5, 0] ^
    #                  tmp_array[(x - 1) % 5, 1] ^
    #                  tmp_array[(x - 1) % 5, 2] ^
    #                  tmp_array[(x - 1) % 5, 3] ^
    #                  tmp_array[(x - 1) % 5, 4]
    #             c2 = array_shift[(x + 1) % 5, 0] ^
    #                  array_shift[(x + 1) % 5, 1] ^ 
    #                  array_shift[(x + 1) % 5, 2] ^ 
    #                  array_shift[(x + 1) % 5, 3] ^
    #                  array_shift[(x + 1) % 5, 4]
    #             d = c1 ^ c2
    #             for y in range(5):
    #                 state[x, y] = state[x, y] ^ d

    #         #rho_step:
    #         tmp_array = np.copy(state)
    #         tracking_index = (1, 0)
    #         for t in range(24):
    #             t_shift = ((t + 1) * (t + 2) >> 1)
    #             t_mod = t_shift % 64
    #             target_lane = tmp_array[tracking_index] << np.uint64(
    #                 t_mod) | tmp_array[tracking_index] >> np.uint64(64 - t_mod)
    #             state[tracking_index] = target_lane
    #             tracking_index = (tracking_index[1], ((
    #                 2 * tracking_index[0]) + (3 * tracking_index[1])) % 5)

    #         #pi_step:
    #         tmp_array = np.copy(state)
    #         it = np.nditer(tmp_array, flags=['multi_index'])
    #         while not it.finished:
    #             new_index = (it.multi_index[1], ((
    #                 2 * it.multi_index[0]) + (3 * it.multi_index[1])) % 5)
    #             state[new_index] = it[0]
    #             it.iternext()

    #         #chi_step:
    #         tmp_array = np.copy(state)
    #         it = np.nditer(tmp_array, flags=['multi_index'])
    #         while not it.finished:
    #             invert_lane = ~tmp_array[(it.multi_index[0] + 1) %
    #                                     5, it.multi_index[1]]
    #             and_lane = tmp_array[(it.multi_index[0] + 2) %
    #                                 5, it.multi_index[1]]
    #             new_value = (invert_lane & and_lane) ^ it[0]
    #             state[it.multi_index] = new_value
    #             it.iternext()

    #         #iota_step:
    #         state[0, 0] ^= KECCAK_ROUND_CONSTANTS[round_num]

    #     return state






############################### OLD ############################



def keecak(input_array, rounds_limit):

    # print('Running Keccak %s' % rounds_limit)
    state = np.copy(input_array)

    for round_num in range(24-rounds_limit, 24):

        #theta_step:
        tmp_array = np.copy(state)
        array_shift = np.left_shift(state, 1) | np.right_shift(state, 63)
        for wut, (foo, huf) in enumerate([(4,1),(0,2),(1,3),(2,4),(3,0)]):
            c1 = reduce(lambda x, y: np.uint64(x) ^ np.uint64(y), tmp_array[foo], 0)
            c2 = reduce(lambda x, y: np.uint64(x) ^ np.uint64(y), array_shift[huf], 0)
            # np.bitwise_xor(casting='unsafe'), tmp_array[foo[0]], 0)
            # c1 = tmp_array[foo[0] , 0] ^ tmp_array[foo[0], 1] ^ tmp_array[foo[0], 2] ^ tmp_array[foo[0], 3] ^ tmp_array[foo[0], 4]
            # c2 = array_shift[foo[1], 0] ^ array_shift[foo[1], 1] ^ array_shift[foo[1],2] ^ array_shift[foo[1], 3] ^ array_shift[foo[1], 4]
            # c1 = reduce(xor, tmp_array[foo[0]], 0)
            # c2 = reduce(xor, tmp_array[foo[1]], 0)
            
            d = c1 ^ c2
            # for elements in range(5):
            #     state[wut, elements] = state[wut, elements] ^ d
            state[wut] = state[wut] ^ d

        #rho_step:
        tmp_array = np.copy(state)
        tracking_index = (1, 0)
        for t in range(24):
            t_shift = ((t + 1) * (t + 2) >> 1)
            t_mod = t_shift % 64
            target_lane = tmp_array[tracking_index] << np.uint64(t_mod) | tmp_array[tracking_index] >> np.uint64(64 - t_mod)
            state[tracking_index] = target_lane
            tracking_index = (tracking_index[1], ((2 * tracking_index[0]) + (3 * tracking_index[1])) % 5)

        #pi_step:
        tmp_array = np.copy(state)
        it = np.nditer(tmp_array, flags=['multi_index'])
        while not it.finished:
            new_index = (it.multi_index[1], ((2 * it.multi_index[0]) + (3 * it.multi_index[1])) % 5)
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
        state[0, 0] ^= KECCAK_ROUND_CONSTANTS[round_num]

    return state

def kravatte_roll(input_array, roll_count):
    state = np.copy(input_array)
    tmp_plane = state[0:5, 4]
    for _ in range(roll_count):
        lane_0 = tmp_plane[0]
        # for x in range(4):
        #     tmp_plane[x] = tmp_plane[x + 1]
        tmp_plane[0] = tmp_plane[1]
        tmp_plane[1] = tmp_plane[2]
        tmp_plane[2] = tmp_plane[3]
        tmp_plane[3] = tmp_plane[4]
        rotate_lane = ((lane_0 << np.uint64(7)) | (lane_0 >> np.uint64(57)))
        tmp_plane[4] = rotate_lane ^ tmp_plane[0] ^ (tmp_plane[0] >> np.uint64(3))
    state[0:5, 4] = tmp_plane
    return state


def kravatte_roll_single(input_array):
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


def pad_10(input_bytes, desired_length):
    start_len = len(input_bytes)
    if start_len == desired_length:
        return input_bytes
    pad_len = desired_length - (start_len % desired_length)
    padded_bytes = input_bytes + b'\x01' + (b'\x00' * (pad_len - 1))
    return padded_bytes

def compute_kravatte(key, message, output_size):

    # Compute Key
    key_pad = pad_10(key, 200)
    # key_array = np.frombuffer(key_pad, dtype=np.uint64, count=25, offset=0).reshape(5,5).swapaxes(0,1)
    key_array = np.frombuffer(key_pad, dtype=np.uint64, count=25, offset=0).reshape([5, 5], order='F')
    kra_key = keecak(key_array, 6)

    # Absorb
    ## Pad Message
    msg_len = len(message)
    kra_msg = pad_10(message, msg_len + (200 - (msg_len % 200)))

    collector = np.zeros([5, 5], dtype=np.uint64)
    absorb_steps = len(kra_msg) // 200

    for x in range(absorb_steps):
        m = np.frombuffer(kra_msg, dtype=np.uint64, count=25, offset=x * 200).reshape([5, 5], order='F')
        m_k = m ^ kra_key
        kra_key = kravatte_roll_single(kra_key)
        collector = collector ^ keecak(m_k, 6)

    # Squeeze
    collector = keecak(collector, 4)
    kra_key = kravatte_roll_single(kra_key)

    full_output_size = output_size + (200 - (output_size % 200)) if output_size % 200 else output_size
    squeeze_steps = full_output_size // 200
    output_buffer = b''

    for x in range(squeeze_steps):
        collector_squeeze = keecak(collector, 4)
        collector = kravatte_roll_single(collector)
        output_buffer += (collector_squeeze ^ kra_key).swapaxes(0,1).tobytes()

    return output_buffer[:output_size]


if __name__ == "__main__":
    my_key = b'\xFF' * 32
    my_messge = bytes([x % 256 for x in range(120000)])
    my_kra = compute_kravatte(my_key, my_messge, 2*1024*1024)
    # print(' '.join('{:02x}'.format(x) for x in my_kra))
    print(len(my_kra))

    # my_key = bytes([0xa9, 0xa8, 0xa7, 0xa6, 0xa5, 0xa4, 0xa3, 0xa2, 0xa1, 0xa0, 0x9f, 0x9e, 0x9d, 0x9c, 0x9b, 0x9a, 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90, 0x8f, 0x8e, 0x8d, 0x8c, 0x8b, 0x8a])
    # my_message = bytes([0x7d, 0x5e, 0x3f, 0x20, 0x01, 0xe2, 0xc3, 0xa4, 0x84, 0x65, 0x46, 0x27, 0x08, 0xe9, 0xca, 0xab, 0x8b, 0x6c, 0x4d, 0x2e, 0x0f, 0xf0, 0xd1, 0xb2, 0x92, 0x73, 0x54, 0x35, 0x16, 0xf7, 0xd8, 0xb9, 0x99, 0x7a, 0x5b, 0x3c, 0x1d, 0xfe, 0xdf, 0xc0, 0xa0, 0x81, 0x62, 0x43, 0x24, 0x05, 0xe6, 0xc7, 0xa7, 0x88, 0x69, 0x4a, 0x2b, 0x0c, 0xed, 0xce, 0xae, 0x8f, 0x70, 0x51, 0x32, 0x13, 0xf4, 0xd5, 0xb5, 0x96, 0x77, 0x58, 0x39, 0x1a, 0xfb, 0xdc, 0xbc, 0x9d, 0x7e, 0x5f, 0x40, 0x21, 0x02, 0xe3, 0xc3, 0xa4, 0x85, 0x66, 0x47, 0x28, 0x09, 0xea, 0xca, 0xab, 0x8c, 0x6d, 0x4e, 0x2f, 0x10, 0xf1, 0xd1, 0xb2, 0x93, 0x74, 0x55, 0x36, 0x17, 0xf8, 0xd8, 0xb9, 0x9a, 0x7b, 0x5c, 0x3d, 0x1e, 0xff, 0xdf, 0xc0, 0xa1, 0x82, 0x63, 0x44, 0x25, 0x06, 0xe6, 0xc7, 0xa8, 0x89, 0x6a, 0x4b, 0x2c, 0x0d, 0xed, 0xce, 0xaf, 0x90, 0x71, 0x52, 0x33, 0x14, 0xf4, 0xd5, 0xb6, 0x97, 0x78, 0x59, 0x3a, 0x1b, 0xfb, 0xdc, 0xbd, 0x9e, 0x7f, 0x60, 0x41, 0x22, 0x02, 0xe3, 0xc4, 0xa5, 0x86, 0x67, 0x48, 0x29, 0x09, 0xea, 0xcb, 0xac, 0x8d, 0x6e, 0x4f, 0x30, 0x10, 0xf1, 0xd2, 0xb3, 0x94, 0x75, 0x56, 0x37, 0x17, 0xf8, 0xd9, 0xba, 0x9b, 0x7c, 0x5d, 0x3e, 0x1e, 0xff, 0xe0, 0xc1, 0xa2, 0x83, 0x64, 0x45, 0x25, 0x06, 0xe7, 0xc8, 0xa9, 0x8a, 0x6b, 0x4c, 0x2c, 0x0d, 0xee, 0xcf, 0xb0, 0x91, 0x72, 0x53, 0x33, 0x14, 0xf5, 0xd6, 0xb7, 0x98, 0x79, 0x5a, 0x3a, 0x1b, 0xfc, 0xdd, 0xbe, 0x9f, 0x80, 0x61, 0x41, 0x22, 0x03, 0xe4, 0xc5, 0xa6, 0x87, 0x68, 0x48, 0x29, 0x0a, 0xeb, 0xcc, 0xad, 0x8e, 0x6f, 0x4f, 0x30, 0x11, 0xf2, 0xd3, 0xb4, 0x95, 0x76, 0x56, 0x37, 0x18, 0xf9, 0xda, 0xbb, 0x9c, 0x7d, 0x7d, 0x5e, 0x3f, 0x20, 0x01, 0xe2, 0xc3, 0xa4, 0x84, 0x65, 0x46, 0x27, 0x08, 0xe9, 0xca, 0xab, 0x8b, 0x6c, 0x4d, 0x2e, 0x0f, 0xf0, 0xd1, 0xb2, 0x92, 0x73, 0x54, 0x35, 0x16, 0xf7, 0xd8, 0xb9, 0x99, 0x7a, 0x5b, 0x3c, 0x1d, 0xfe, 0xdf, 0xc0, 0xa0, 0x81, 0x62, 0x43, 0x24, 0x05, 0xe6, 0xc7, 0xa7, 0x88, 0x69, 0x4a, 0x2b, 0x0c, 0xed, 0xce, 0xae, 0x8f, 0x70, 0x51, 0x32, 0x13, 0xf4, 0xd5, 0xb5, 0x96, 0x77, 0x58, 0x39, 0x1a, 0xfb, 0xdc, 0xbc, 0x9d, 0x7e, 0x5f, 0x40, 0x21, 0x02, 0xe3, 0xc3, 0xa4, 0x85, 0x66, 0x47, 0x28, 0x09, 0xea, 0xca, 0xab, 0x8c, 0x6d, 0x4e, 0x2f, 0x10, 0xf1, 0xd1, 0xb2, 0x93, 0x74, 0x55, 0x36, 0x17, 0xf8, 0xd8, 0xb9, 0x9a, 0x7b, 0x5c, 0x3d, 0x1e, 0xff, 0xdf, 0xc0, 0xa1, 0x82, 0x63, 0x44, 0x25, 0x06, 0xe6, 0xc7, 0xa8, 0x89, 0x6a, 0x4b, 0x2c, 0x0d, 0xed, 0xce, 0xaf, 0x90, 0x71, 0x52, 0x33, 0x14, 0xf4, 0xd5, 0xb6, 0x97, 0x78, 0x59, 0x3a, 0x1b])
    # my_kra = compute_kravatte(my_key, my_message, 400)
    # print(' '.join('{:02x}'.format(x) for x in my_kra))


