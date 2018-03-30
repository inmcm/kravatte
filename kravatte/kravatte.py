"""
Kravatte Achouffe Cipher Suite: Encryption, Decryption, and Authenication Tools based on the Farfalle modes
Copyright 2018 Michael Calvin McCoy
"""
from math import floor, ceil, log2
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
        key_pad = self._pad_10_append(key, self.KECCACK_BYTES)
        key_array = np.frombuffer(key_pad, dtype=np.uint64, count=self.KECCAK_LANES, offset=0).reshape([self.KECCAK_PLANES_SLICES, self.KECCAK_PLANES_SLICES], order='F')
        self.kra_key = self._keecak(key_array)

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

    def collect_message(self, message, append_bit=None):
        """
        Pad and Process Blocks of Message into Kravatte collector state

        Inputs:
            message (bytes): arbitary number of bytes to be padded into Keccak blocks and absorbed into the collector
            append_bit (int): Either 1 or 0 to append to the message before padding. Required for more advanced Kravatte modes.
        """
        if self.digest_active:
            self.reset_state()

        if self.new_collector:
            self.new_collector = False
        else:
            self.roll_key = self._kravatte_roll_compress(self.roll_key)

        # Pad Message
        msg_len = len(message)
        kra_msg = self._pad_10_append(message, msg_len + (self.KECCACK_BYTES - (msg_len % self.KECCACK_BYTES)), append_bit)
        absorb_steps = len(kra_msg) // self.KECCACK_BYTES

        # Absorb into Collector
        for msg_block in range(absorb_steps):
            m = np.frombuffer(kra_msg, dtype=np.uint64, count=25, offset=msg_block * self.KECCACK_BYTES).reshape([5, 5], order='F')
            m_k = m ^ self.roll_key
            self.roll_key = self._kravatte_roll_compress(self.roll_key)
            self.collector = self.collector ^ self._keecak(m_k)

    def generate_digest(self, output_size, short_kravatte=False):
        """
        Squeeze an arbitrary number of bytes from collector state

        Inputs:
            output_size (int): Number of bytes to generate and store in Kravatte digest parameter
            short_kravatte (bool): Enable disable short kravatte required for other Kravatte modes
        """
        if not self.digest_active:
            self.collector = self.collector if short_kravatte else self._keecak(self.collector)
            self.roll_key = self._kravatte_roll_compress(self.roll_key)
            self.digest_active = True

        full_output_size = output_size + (200 - (output_size % 200)) if output_size % 200 else output_size
        generate_steps = full_output_size // 200

        for _ in range(generate_steps):
            collector_squeeze = self._keecak(self.collector)
            self.collector = self._kravatte_roll_expand(self.collector)
            self.digest.extend((collector_squeeze ^ self.roll_key).tobytes('F'))

        self.digest = self.digest[:output_size]

    def _keecak(self, input_array):
        """
        Implementation of Keccak-1600 PRF defined in FIPS 202

        Inputs:
            input_array (numpy array): Keccak compatiable state array: 200-byte as 5x5 64-bit lanes
        Return:
            numpy array: Keccak compatiable state array: 200-byte as 5x5 64-bit lanes
        """

        state = np.copy(input_array)

        for round_num in range(6):

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

            # pi_step:
            # Shuffle lanes to pre-calculated positions
            state = state[self.PI_ROW_REORDER, self.PI_COLUMN_REORDER]

            # chi_step:
            # Exclusive-or each individual lane based on and/invert permutation
            tmp_array = np.copy(state)
            for w, x, y in self.CHI_REORDER:
                state[w] ^= ~tmp_array[x] & tmp_array[y]

            # iota_step:
            # Exlusive-or first lane of state with round constant
            state[0, 0] ^= self.IOTA_CONSTANTS[round_num]
        return state

    @staticmethod
    def _kravatte_roll_compress(input_array):
        """
        Kravatte defined roll function for compression side of Farfalle PRF

        Inputs:
            input_array (numpy array): Keccak compatiable state array: 200-byte as 5x5 64-bit lanes
        Return:
            numpy array: Keccak compatiable state array: 200-byte as 5x5 64-bit lanes
        """
        state = np.copy(input_array)
        tmp_plane = state[0:5, 4]
        tmp_plane[0] = tmp_plane[1]
        tmp_plane[1] = tmp_plane[2]
        tmp_plane[2] = tmp_plane[3]
        tmp_plane[3] = tmp_plane[4]
        rotate_lane = ((input_array[0][4] << np.uint64(7)) | (input_array[0][4] >> np.uint64(57)))
        tmp_plane[4] = rotate_lane ^ input_array[1][4] ^ (input_array[1][4] >> np.uint64(3))
        state[0:5, 4] = tmp_plane
        return state

    @staticmethod
    def _kravatte_roll_expand(input_array):
        """
        Kravatte defined roll function for expansion side of Farfalle PRF

        Inputs:
            input_array (numpy array): Keccak compatiable state array: 200-byte as 5x5 64-bit lanes
        Return:
            numpy array: Keccak compatiable state array: 200-byte as 5x5 64-bit lanes
        """
        state = np.copy(input_array)
        tmp_plane_3 = state[0:5, 3]
        tmp_plane_4 = state[0:5, 4]

        tmp_plane_3[0] = tmp_plane_3[1]
        tmp_plane_3[1] = tmp_plane_3[2]
        tmp_plane_3[2] = tmp_plane_3[3]
        tmp_plane_3[3] = tmp_plane_3[4]
        tmp_plane_3[4] = tmp_plane_4[0]

        tmp_plane_4[0] = tmp_plane_4[1]
        tmp_plane_4[1] = tmp_plane_4[2]
        tmp_plane_4[2] = tmp_plane_4[3]
        tmp_plane_4[3] = tmp_plane_4[4]

        rotate_lane_7 = ((input_array[0][3] << np.uint64(7)) | (input_array[0][3] >> np.uint64(57)))
        rotate_lane_18 = ((input_array[1][3] << np.uint64(18)) | (input_array[1][3] >> np.uint64(46)))
        tmp_plane_4[4] = rotate_lane_7 ^ rotate_lane_18 ^ ((input_array[1][3] >> np.uint64(1)) & input_array[2][3])
        state[0:5, 3] = tmp_plane_3
        state[0:5, 4] = tmp_plane_4
        return state

    @staticmethod
    def _pad_10_append(input_bytes, desired_length, append_bit=None):
        """
        Farfalle defined padding function. Limited to byte divisible inputs only

        Inputs:
            input_bytes (bytes): Collection of bytes
            desired_length (int): Number of bytes to pad input len out to
            append_bit (int): a single bit represented by 1 or 0 to be inserted before the padding
                              starts. Allows "appending" a bit as required by several Kravatte modes
        Return:
            bytes: input bytes with padding applied
        """
        start_len = len(input_bytes)
        if start_len == desired_length:
            return input_bytes

        if append_bit is not None:
            head_pad_byte = b'\x03' if append_bit == 1 else b'\x02'
        else:
            head_pad_byte = b'\x01'

        pad_len = desired_length - (start_len % desired_length)
        padded_bytes = input_bytes + head_pad_byte + (b'\x00' * (pad_len - 1))
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
        bytes: message authentication bytes of length output_size
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
        message (bytes): Plaintext message for encryption
        metadata (bytes): Nonce/Seed value for authenicated encryption
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
    ciphertext = bytes([p_text ^ key_stream for p_text, key_stream in zip(message, kravatte_siv_wrap.digest)])
    return ciphertext, siv_tag


def siv_unwrap(key, ciphertext, siv_tag, metadata):
    """
    Decryption of Synthetic Intialization Vector method described in the Farfalle/Kravatte
    spec. Given a key, metadata, and validation tag, generates plaintext (of equivalent length to
    the ciphertext) and validates message based on included tag, metadata, and key. Inverse of
    siv_wrap function.

    Args:
        key (bytes): Encryption key; 0-200 bytes in length
        ciphertext (bytes): Ciphertext SIV Message
        siv_tag (bytes): Authenicating byte string
        metadata (bytes): Metadata used to encrpt message and generate tag

    Returns:
        tuple (bytes, boolean): Bytes of plaintext and message validation boolean
    """

    # Initialize Kravatte
    kravatte_siv_unwrap = Kravatte(key)

    # Re-Generate Key Stream
    kravatte_siv_unwrap.collect_message(metadata)
    kravatte_siv_unwrap.collect_message(siv_tag)
    kravatte_siv_unwrap.generate_digest(len(ciphertext))
    siv_plaintext = bytes([p_text ^ key_stream for p_text, key_stream in zip(ciphertext, kravatte_siv_unwrap.digest)])

    # Re-Generate Tag From Metadata and Recovered Plaintext
    kravatte_siv_unwrap.collect_message(metadata)
    kravatte_siv_unwrap.collect_message(siv_plaintext)
    kravatte_siv_unwrap.generate_digest(len(siv_tag))
    generated_tag = kravatte_siv_unwrap.digest

    # Check if tag matches provided tag matches reconstituted tag
    valid_tag = kravatte_siv_unwrap.compare_bytes(siv_tag, generated_tag)
    return siv_plaintext, valid_tag


class KravatteSAE(Kravatte):
    TAG_SIZE = 16
    OFFSET = TAG_SIZE

    def __init__(self, nonce, key=b''):
        """
        Initialize KravatteSAE with user key and nonce

        Inputs:
            nonce (bytes) - random unique value to initalize the session with
            key (bytes) - secret key for encrypting session messages
        """
        super(KravatteSAE, self).__init__(key)
        self.initialize_history(nonce)

    def initialize_history(self, nonce):
        """
        Pad and compute new Kravatte base key from bytes source.

        Inputs:
            key (bytes): user provided bytes to be padded (if nesscessary) and computed into Kravatte base key
        """
        self.collect_message(nonce)
        self.history_collector = np.copy(self.collector)
        self.history_key = np.copy(self.roll_key)
        self.generate_digest(self.TAG_SIZE)
        self.tag = self.digest.copy()

    def sae_wrap(self, plaintext, metadata):
        """
        Encrypt an arbitrary plaintext message using the included metdata as part of an on-going
        session. Creates authenication tag for validation during decryption.

        Inputs:
            plaintext (bytes): user plaintext of arbitrary length
            metadata (bytes): associated data to ensure a unique encryption permutation

        Returns:
            (bytes, bytes): encrypted cipher text and authenication tag
        """
        # Restore Kravatte State to When Latest History was Absorbed
        self.collector = np.copy(self.history_collector)
        self.roll_key = np.copy(self.history_key)
        self.digest = bytearray(b'')
        self.digest_active = False

        # Generate/Apply Key Stream
        self.generate_digest(len(plaintext) + self.OFFSET)
        ciphertext = bytes([p_text ^ key_stream for p_text, key_stream in zip(plaintext, self.digest[self.OFFSET:])])

        # Update History
        if len(metadata) > 0 or len(plaintext) == 0:
            self.append_to_history(metadata, 0)

        if len(plaintext) > 0:
            self.append_to_history(ciphertext, 1)

        self.history_collector = np.copy(self.collector)
        self.history_key = np.copy(self.roll_key)

        # Generate Tag
        self.generate_digest(self.TAG_SIZE)

        return ciphertext, self.digest

    def sae_unwrap(self, ciphertext, metadata, validation_tag):
        """
        Decrypt an arbitrary ciphertext message using the included metdata as part of an on-going
        session. Creates authenication tag for validation during decryption.

        Inputs:
            ciphertext (bytes): user ciphertext of arbitrary length
            metadata (bytes): associated data from encryption
            validation_tag (bytes): collection of bytes that autheicates the decrypted plaintext as
                                    being encrypted with the same secret key

        Returns:
            (bytes, bool): decrypted plaintext and boolean indicating in decryption was authenicated against secret key
        """
        # Restore Kravatte State to When Latest History was Absorbed
        self.collector = np.copy(self.history_collector)
        self.roll_key = np.copy(self.history_key)
        self.digest = bytearray(b'')
        self.digest_active = False

        # Generate/Apply Key Stream
        self.generate_digest(len(ciphertext) + self.OFFSET)
        plaintext = bytes([p_text ^ key_stream for p_text, key_stream in zip(ciphertext, self.digest[self.OFFSET:])])

        # Update History
        if len(metadata) > 0 or len(ciphertext) == 0:
            self.append_to_history(metadata, 0)

        if len(ciphertext) > 0:
            self.append_to_history(ciphertext, 1)

        self.history_collector = np.copy(self.collector)
        self.history_key = np.copy(self.roll_key)

        # Generate Tag
        self.generate_digest(self.TAG_SIZE)

        # Store Generated Tag and Validate
        self.tag = self.digest.copy()
        valid_tag = self.compare_bytes(self.tag, validation_tag)

        return plaintext, valid_tag

    def append_to_history(self, message, pad_bit):
        """
        Update history collector state with provided message.

        Inputs:
            message (bytes): arbitary number of bytes to be padded into Keccak blocks and absorbed into the collector
            pad_bit (int): Either 1 or 0 to append to the end of the regular message before padding
        """
        if self.digest_active:
            self.collector = np.copy(self.history_collector)
            self.roll_key = np.copy(self.history_key)
            self.digest = bytearray(b'')
            self.digest_active = False

        self.roll_key = self._kravatte_roll_compress(self.roll_key)

        # Pad Message with a single bit and then
        start_len = len(message)
        padded_len = start_len + (self.KECCACK_BYTES - (start_len % self.KECCACK_BYTES))
        padded_bytes = self._pad_10_append(message, padded_len, pad_bit)
        absorb_steps = len(padded_bytes) // self.KECCACK_BYTES

        # Absorb into Collector
        for msg_block in range(absorb_steps):
            m = np.frombuffer(padded_bytes, dtype=np.uint64, count=25, offset=msg_block * self.KECCACK_BYTES).reshape([5, 5], order='F')
            m_k = m ^ self.roll_key
            self.roll_key = self._kravatte_roll_compress(self.roll_key)
            self.collector = self.collector ^ self._keecak(m_k)


class KravatteWBC(Kravatte):
    SPLIT_THRESHOLD = 398

    def __init__(self, block_cipher_size, tweak=b'', key=b''):
        """
        Initialize KravatteWBC object

        Inputs:
            block_cipher_size (int) - size of block cipher in bytes
            tweak (bytes) - arbitary value to customize cipher output
            key (bytes) - secret key for encryptin message blocks
        """
        super(KravatteWBC, self).__init__(key)
        self.split_bytes(block_cipher_size)
        self.tweak = tweak

    def split_bytes(self, message_size_bytes):
        """
        Calculates the size (in bytes) of the "left" and "right" components of the block encryption
        decryption process. Based on algorithm given in Farfalle spec.

        Input
            message_size_bytes (int): user defined block size for this instance of KravatteWBC
        """
        if message_size_bytes <= self.SPLIT_THRESHOLD:
            nL = ceil(message_size_bytes / 2)
        else:
            q = floor(((message_size_bytes + 1) / self.KECCACK_BYTES)) + 1
            x = floor(log2(q - 1))
            nL = ((q - (2**x)) * self.KECCACK_BYTES) - 1
        self.size_L = nL
        self.size_R = message_size_bytes - nL

    def encrypt(self, message):
        """
        Encrypt a user message using KravatteWBC mode
        Inputs:
            message (bytes): plaintext message to encrypt. Length should be <= the block cipher size
                             defined in the KravatteWBC object
        Returns:
            bytes: encrypted block same length as message
        """
        L = message[0:self.size_L]
        R = message[self.size_L:]

        # R0 ← R0 + HK(L||0), with R0 the first min(b, |R|) bits of R
        self.collect_message(L, append_bit=0)
        self.generate_digest(min(self.KECCACK_BYTES, self.size_R), short_kravatte=True)
        extended_digest = self.digest + ((self.size_R - len(self.digest)) * b'\x00')
        R = bytes([p_text ^ key_stream for p_text, key_stream in zip(R, extended_digest)])

        # L ← L + GK (R||1 ◦ W)
        self.collect_message(self.tweak)
        self.collect_message(R, append_bit=1)
        self.generate_digest(self.size_L)
        L = bytes([p_text ^ key_stream for p_text, key_stream in zip(L, self.digest)])

        # R ← R + GK (L||0 ◦ W)
        self.collect_message(self.tweak)
        self.collect_message(L, append_bit=0)
        self.generate_digest(self.size_R)
        R = bytes([p_text ^ key_stream for p_text, key_stream in zip(R, self.digest)])

        # L0 ← L0 + HK(R||1), with L0 the first min(b, |L|) bits of L
        self.collect_message(R, append_bit=1)
        self.generate_digest(min(self.KECCACK_BYTES, self.size_L), short_kravatte=True)
        extended_digest = self.digest + ((self.size_L - len(self.digest)) * b'\x00')
        L = bytes([p_text ^ key_stream for p_text, key_stream in zip(L, extended_digest)])

        # C ← the concatenation of L and R
        return L + R

    def decrypt(self, ciphertext):
        """
        Decrypt a user message using KravatteWBC mode
        Inputs:
            message (bytes): cipehertext message to decrypt.
        Returns:
            bytes: decrypted block same length as ciphertext
        """
        L = ciphertext[0:self.size_L]
        R = ciphertext[self.size_L:]

        # L0 ← L0 + HK(R||1), with L0 the first min(b, |L|) bits of L
        self.collect_message(R, append_bit=1)
        self.generate_digest(min(self.KECCACK_BYTES, self.size_L), short_kravatte=True)
        extended_digest = self.digest + ((self.size_L - len(self.digest)) * b'\x00')
        L = bytes([c_text ^ key_stream for c_text, key_stream in zip(L, extended_digest)])

        # R ← R + GK (L||0 ◦ W)
        self.collect_message(self.tweak)
        self.collect_message(L, append_bit=0)
        self.generate_digest(self.size_R)
        R = bytes([c_text ^ key_stream for c_text, key_stream in zip(R, self.digest)])

        # L ← L + GK (R||1 ◦ W)
        self.collect_message(self.tweak)
        self.collect_message(R, append_bit=1)
        self.generate_digest(self.size_L)
        L = bytes([c_text ^ key_stream for c_text, key_stream in zip(L, self.digest)])

        # R0 ← R0 + HK(L||0), with R0 the first min(b, |R|) bits of R
        self.collect_message(L, append_bit=0)
        self.generate_digest(min(self.KECCACK_BYTES, self.size_R), short_kravatte=True)
        extended_digest = self.digest + ((self.size_R - len(self.digest)) * b'\x00')
        R = bytes([c_text ^ key_stream for c_text, key_stream in zip(R, extended_digest)])

        # P ← the concatenation of L and R
        return L + R


class KravatteWBC_AE(KravatteWBC):
    WBC_AE_TAG_LEN = 16

    def __init__(self, block_cipher_size, key=b''):
        """
        Initialize KravatteWBC_AE object

        Inputs:
            block_cipher_size (int) - size of block cipher in bytes
            key (bytes) - secret key for encryptin message blocks
        """
        super(KravatteWBC_AE, self).__init__(block_cipher_size + self.WBC_AE_TAG_LEN, None, key=key)

    def wrap(self, message, metadata):
        """
        Encrypt a user message and generate included authenicated data. Requires metedata input
        in lieu of customization tweak.

        Inputs:
            message (bytes): User message same length as configured object block size
            metadata (bytes): associated metadata to ensure unqiue output

        Returns:
            bytes: authenicated encrypted block
        """

        self.tweak = metadata  # metadata treated as tweak
        padded_message = message + (self.WBC_AE_TAG_LEN * b'\x00')
        return self.encrypt(padded_message)

    def unwrap(self, ciphertext, metadata):
        """
        Decrypt a ciphertext block and validate included authenicated data. Requires metedata input
        in lieu of customization tweak.

        Inputs:
            message (bytes): ciphertext same length as configured object block size
            metadata (bytes): associated metadata to ensure unqiue output

        Returns:
            (bytes, bool): plaintext byes and decryption valid flag
        """
        L = ciphertext[0:self.size_L]
        R = ciphertext[self.size_L:]
        self.tweak = metadata

        # L0 ← L0 + HK(R||1), with L0 the first min(b, |L|) bits of L
        self.collect_message(R, append_bit=1)
        self.generate_digest(min(self.KECCACK_BYTES, self.size_L), short_kravatte=True)
        extended_digest = self.digest + ((self.size_L - len(self.digest)) * b'\x00')
        L = bytes([c_text ^ key_stream for c_text, key_stream in zip(L, extended_digest)])

        # R ← R + GK (L||0 ◦ A)
        self.collect_message(self.tweak)
        self.collect_message(L, append_bit=0)
        self.generate_digest(self.size_R)
        R = bytes([c_text ^ key_stream for c_text, key_stream in zip(R, self.digest)])

        # |R| ≥ b+t
        if self.size_R >= self.KECCACK_BYTES + self.WBC_AE_TAG_LEN:
            # if the last t bytes of R ̸= 0t then return error!
            valid_plaintext = valid_plaintext = True if R[-self.WBC_AE_TAG_LEN:] == (self.WBC_AE_TAG_LEN * b'\x00') else False

            # L ← L + GK (R||1 ◦ A)
            self.collect_message(self.tweak)
            self.collect_message(R, append_bit=1)
            self.generate_digest(self.size_L)
            L = bytes([c_text ^ key_stream for c_text, key_stream in zip(L, self.digest)])

            # R0 ← R0 + HK(L||0), with R0 the first b bytes of R
            self.collect_message(L, append_bit=0)
            self.generate_digest(self.KECCACK_BYTES, short_kravatte=True)
            extended_digest = self.digest + ((self.size_R - len(self.digest)) * b'\x00')
            R = bytes([c_text ^ key_stream for c_text, key_stream in zip(R, extended_digest)])

        else:
            # L ← L + GK (R||1 ◦ A)
            self.collect_message(self.tweak)
            self.collect_message(R, append_bit=1)
            self.generate_digest(self.size_L)
            L = bytes([c_text ^ key_stream for c_text, key_stream in zip(L, self.digest)])

            # R0 ← R0 + HK(L||0), with R0 the first min(b, |R|) bytes of R 
            self.collect_message(L, append_bit=0)
            self.generate_digest(min(self.KECCACK_BYTES, self.size_R), short_kravatte=True)
            extended_digest = self.digest + ((self.size_R - len(self.digest)) * b'\x00')
            R = bytes([c_text ^ key_stream for c_text, key_stream in zip(R, extended_digest)])

            # if the last t bytes of L||R ̸= 0t then return error!
            valid_plaintext = True if (L + R)[-self.WBC_AE_TAG_LEN:] == (self.WBC_AE_TAG_LEN * b'\x00') else False

        # P′ ← L||R
        return (L + R)[:-self.WBC_AE_TAG_LEN], valid_plaintext

if __name__ == "__main__":
    from time import perf_counter
    my_key = b'\xFF' * 32
    my_message = bytes([x % 256 for x in range(4 * 1024 * 1024)])
    start = perf_counter()
    my_kra = mac(my_key, my_message, 4 * 1024 * 1024)
    stop = perf_counter()
    print("Process Time:", stop - start)
    print(len(my_kra))
