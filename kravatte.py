"""
Kravatte Cipher Suite: Encryption, Decryption, and Authenication Tools based on the Farfalle modes
Copyright 2018 Michael Calvin McCoy
"""
import numpy as np


class Kravatte(object):
    """Implementation of the Farfalle Psuedo-Random Function (PRF) construct utilizing the 
    Keccak-1600 permutation.
    """
    KECCACK_BYTES = 200
    '''Number of Bytes in Keccak-1600 state'''
    KECCAK_LANES = 25
    '''Number of 8-Byte lanes in Keccak-1600 state'''

    KECCAK_PLANES_SLICES = 5
    ''' Size of x/y dimensions of Keccak lane array  '''

    IOTA_CONSTANTS = np.array([0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
                               0x8000000000008080, 0x0000000080000001, 0x8000000080008008],
                              dtype=np.uint64)
    '''Iota Step Round Constants For Keecak-p(1600, 4) and Keecak-p(1600, 6)'''

    RHO_SHIFTS = np.array([[0, 36, 3, 41, 18],
                           [1, 44, 10, 45, 2],
                           [62, 6, 43, 15, 61],
                           [28, 55, 25, 21, 56],
                           [27, 20, 39, 8, 14]], dtype=np.uint64)
    '''Lane Shifts for Rho Step'''

    CHI_REORDER = [(0, 1, 2),
                   (1, 2, 3),
                   (2, 3, 4),
                   (3, 4, 0),
                   (4, 0, 1)]
    '''Lane Re-order Mapping for Chi Step'''
    
    PI_ROW_REORDER = np.array([[0, 3, 1, 4, 2],
                               [1, 4, 2, 0, 3],
                               [2, 0, 3, 1, 4],
                               [3, 1, 4, 2, 0],
                               [4, 2, 0, 3, 1]])
    '''Row Re-order Mapping for Pi Step'''

    PI_COLUMN_REORDER = np.array([[0, 0, 0, 0, 0],
                                  [1, 1, 1, 1, 1],
                                  [2, 2, 2, 2, 2],
                                  [3, 3, 3, 3, 3],
                                  [4, 4, 4, 4, 4]])
    '''Column Re-order Mapping for Pi Step'''

    def __init__(self, key=b''):
        """
        Initialize Kravatte with user key

        Inputs:
            key (bytes)
        """
        self.update_key(key)
        self.reset_state()

    def update_key(self, key):
        """
        Pad and compute new Kravatte base key from bytes source.

        Inputs:
            key (bytes): user provided bytes to be padded (if nesscessary) and computed into Kravatte base key 
        """
        key_pad = self._pad_10(key, self.KECCACK_BYTES)
        key_array = np.frombuffer(key_pad, dtype=np.uint64, count=self.KECCAK_LANES, offset=0).reshape([self.KECCAK_PLANES_SLICES, self.KECCAK_PLANES_SLICES], order='F')
        self.kra_key = self._keecak(key_array, 6)

    def reset_state(self):
        """
        Clear existing Farfalle/Kravatte state and prepares for new input message collection.
        Elements reset include:
            - Message block collector
            - Rolling key
            - Currently stored output digest
            - Digest Active and New Collector Flags

        Inputs:
            None 
        """
        self.roll_key = np.copy(self.kra_key)
        self.collector = np.zeros([5, 5], dtype=np.uint64)
        self.digest = bytearray(b'')
        self.digest_active = False
        self.new_collector = True

    def collect_message(self, message):
        """
        Pad and Process Blocks of Message into collector state

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
        kra_msg = self._pad_10(message, msg_len + (self.KECCACK_BYTES - (msg_len % self.KECCACK_BYTES)))
        absorb_steps = len(kra_msg) // self.KECCACK_BYTES

        # Absorb into Collector
        for msg_block in range(absorb_steps):
            m = np.frombuffer(kra_msg, dtype=np.uint64, count=25, offset=msg_block * self.KECCACK_BYTES).reshape([5, 5], order='F')
            m_k = m ^ self.roll_key
            self.roll_key = self._kravatte_roll(self.roll_key)
            self.collector = self.collector ^ self._keecak(m_k, 6)

    def generate_digest(self, output_size):
        """
        Squeeze an arbitrary number of bytes from collector state
        
        Inputs:
            output_size (int): Number of bytes to generate and store in Kravatte digest parameter
        """
        if not self.digest_active:
            self.collector = self._keecak(self.collector, 4)
            self.roll_key = self._kravatte_roll(self.roll_key)
            self.digest_active = True

        full_output_size = output_size + (200 - (output_size % 200)) if output_size % 200 else output_size
        generate_steps = full_output_size // 200

        for _ in range(generate_steps):
            collector_squeeze = self._keecak(self.collector, 4)
            self.collector = self._kravatte_roll(self.collector)
            self.digest.extend((collector_squeeze ^ self.roll_key).tobytes('F'))

        self.digest = self.digest[:output_size]
    
    def _keecak(self, input_array, rounds_limit):
        """
        Implementation of Keccak-1600 PRF defined in FIPS 202

        Inputs:
            input_array (numpy array): Keccak compatiable state array: 200-byte as 5x5 64-bit lanes
            round_limit (int): number of rounds to apply Keccak function (6 or 4 for Kravatte)
        Return:
            numpy array: Keccak compatiable state array: 200-byte as 5x5 64-bit lanes
        """

        state = np.copy(input_array)

        for round_num in range(6 - rounds_limit, 6):

            # theta_step:
            # Exclusive-or each slice-lane by state based permuatative value
            tmp_array = np.copy(state)
            array_shift = np.left_shift(state, 1) | np.right_shift(state, 63)
            for out_slice, norm_slice, shift_slice in [(0, 4, 1), (1, 0, 2), (2, 1, 3), (3, 2, 4), (4, 3, 0)]:
                c1 = tmp_array[norm_slice, 0] ^ tmp_array[norm_slice, 1] ^ tmp_array[norm_slice, 2] ^ tmp_array[norm_slice, 3] ^ tmp_array[norm_slice, 4]
                c2 = array_shift[shift_slice, 0] ^ array_shift[shift_slice, 1] ^ array_shift[shift_slice, 2] ^ array_shift[shift_slice, 3] ^ array_shift[shift_slice, 4]
                state[out_slice] ^= c1 ^ c2

            # rho_step:
            # Left Rotate each lane by pre-calculated value
            for state_lane, t_mod in np.nditer([state, self.RHO_SHIFTS], flags=['external_loop'], op_flags=[['readwrite'], ['readonly']]):
                state_lane[...] = state_lane << t_mod | state_lane >> 64 - t_mod

            #pi_step:
            # Shuffle lanes to pre-calculated positions
            state = state[self.PI_ROW_REORDER, self.PI_COLUMN_REORDER]

            # chi_step:
            # Exclusive-or each individual lane based on and/invert permutation  
            tmp_array = np.copy(state)
            for w, x, y in self.CHI_REORDER:
                state[w] ^= ~tmp_array[x] & tmp_array[y]

            #iota_step:
            # Exlusive-or first lane of state with round constant 
            state[0, 0] ^= self.IOTA_CONSTANTS[round_num]
        return state

    @staticmethod
    def _kravatte_roll(input_array):
        """
        Kravatte defined upper plane permutation functions

        Inputs:
            input_array (numpy array): Keccak compatiable state array: 200-byte as 5x5 64-bit lanes
        Return:
            numpy array: Keccak compatiable state array: 200-byte as 5x5 64-bit lanes
        """
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
        """
        Farfalle defined padding function. Limited to byte divisible inputs only

        Inputs:
            input_bytes (bytes): Collection of bytes
            desired_length (int): Number of bytes to pad input len out to
        Return:
            bytes: input bytes with padding applied
        """
        start_len = len(input_bytes)
        if start_len == desired_length:
            return input_bytes
        pad_len = desired_length - (start_len % desired_length)
        padded_bytes = input_bytes + b'\x01' + (b'\x00' * (pad_len - 1))
        return padded_bytes

    @staticmethod    
    def compare_bytes(a, b):
        """
        Time Constant Byte Comparison Function
        Inputs:
            a (bytes): first set of bytes 
            b (bytes): second set of bytes 
        Return:
            boolean
        """
        compare = True
        if len(a) != len(b):
            return False
        for (element_a, element_b) in zip(a, b):
            compare = compare and (element_a == element_b)
        return compare
        

def mac(key, message, output_size):
    """
    Kravatte Message Authenication Code Generation of given length from a message
    based on a user provided key 

    Args:
        key (bytes): User authenication key (0 - 200 bytes)
        message (bytes): User message
        output_size (int): Size of authenicated digest in bytes 

    Returns:
        bytes    
    
    """
    kravatte_mac_gen = Kravatte(key)
    kravatte_mac_gen.collect_message(message)
    kravatte_mac_gen.generate_digest(output_size)
    return kravatte_mac_gen.digest

def siv_wrap(key, message, metadata, tag_size=32):
    """
    Authenticated Encryption with Associated Data (AEAD) of a provided plaintext using a key and 
    metadata using the Synthetic Intialization Vector method described in the Farfalle/Kravatte 
    spec. Generates ciphertext (of equivalent length to the plaintext) and verification tag. Inverse
    of siv_unwrap function.
    
    Args:
        key (bytes): Encryption key; 0-200 bytes in length
        message (bytes): Plaintext message for 
        metadata (bytes): The first parameter.
        tag_size (int, optional): The tag size in bytes. Defaults to 32 bytes as defined in the 
            Kravatte spec

    Returns:
        tuple (bytes, bytes): Bytes of ciphertext and tag
    """
    # Initialize Kravatte 
    kravatte_siv_wrap = Kravatte(key)
    
    # Generate Tag From Metadata and Plaintext
    kravatte_siv_wrap.collect_message(metadata)
    kravatte_siv_wrap.collect_message(message)
    kravatte_siv_wrap.generate_digest(tag_size)
    siv_tag = kravatte_siv_wrap.digest

    # Generate Key Stream 
    kravatte_siv_wrap.collect_message(metadata)
    kravatte_siv_wrap.collect_message(siv_tag)
    kravatte_siv_wrap.generate_digest(len(message))
    ciphertext = bytes([p_text^key_stream for p_text, key_stream in zip(message, kravatte_siv_wrap.digest)])
    return ciphertext, siv_tag

def siv_unwrap(key, ciphertext, siv_tag, metadata):
    """
    Decryption of Synthetic Intialization Vector method described in the Farfalle/Kravatte 
    spec. Given a key, metadata, and validation tag, generates plaintext (of equivalent length to 
    the ciphertext) and validates message based on included tag, metadata, and key. Inverse of
    siv_wrap function.
    
    Args:
        key (bytes): Encryption key; 0-200 bytes in length
        message (bytes): Plaintext message for 
        siv_tag (bytes): The first parameter.
        metadata (bytes): The first parameter.

    Returns:
        tuple (bytes, boolean): Bytes of plaintext and message validation boolean
    """
    
    # Initialize Kravatte
    kravatte_siv_unwrap = Kravatte(key)

    # Re-Generate Key Stream 
    kravatte_siv_unwrap.collect_message(metadata)
    kravatte_siv_unwrap.collect_message(siv_tag)
    kravatte_siv_unwrap.generate_digest(len(ciphertext))
    siv_plaintext = bytes([p_text^key_stream for p_text, key_stream in zip(ciphertext, kravatte_siv_unwrap.digest)])

    # Re-Generate Tag From Metadata and Recovered Plaintext
    kravatte_siv_unwrap.collect_message(metadata)
    kravatte_siv_unwrap.collect_message(siv_plaintext)
    kravatte_siv_unwrap.generate_digest(len(siv_tag))
    generated_tag = kravatte_siv_unwrap.digest

    # Check if tag matches provided tag matches reconstituted tag
    valid_tag = kravatte_siv_unwrap.compare_bytes(siv_tag, generated_tag)
    return siv_plaintext, valid_tag


if __name__ == "__main__":
    from time import perf_counter
    my_key = b'\xFF' * 32
    my_messge = bytes([x % 256 for x in range(120000)])
    start = perf_counter()
    my_kra = mac(my_key, my_messge, 4*1024*1024)
    stop = perf_counter()
    print("Process Time:", stop-start)
    # print(' '.join('{:02x}'.format(x) for x in my_kra))
    print(len(my_kra))
