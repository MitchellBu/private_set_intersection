import numpy as np
from utils import MathUtils, Ciphertext, EncryptionScheme
import os

class Alice(object):

    def __init__(self, messages, file_path):
        ''' PSI sender side implementation. \
            The relevant files for bob will be located at "file_path/to_bob" '''
        if type(messages) != np.ndarray:
            raise('Error: the messages should be passed as a numpy array')
        self.messages = messages
        self.file_path = file_path
        self.polynomial = MathUtils().polynomial_coefficients_from_roots(self.messages)
        self.encryption_scheme = EncryptionScheme()
        self.encryption_scheme.generate()
        encrypted_poly = self.encryption_scheme.encrypt_encoded_message(self.polynomial)
        base_path = os.path.join(self.file_path, 'to_bob')
        if not os.path.isdir(base_path):
            os.mkdir(base_path)
        key_path = os.path.join(base_path, 'public_key.npy')
        self.encryption_scheme.to_file(key_path)
        ciphers_path = os.path.join(base_path, 'ciphertexts.npy')
        ciphers_array = np.array([cipher.ciphertext for cipher in encrypted_poly], dtype=object)
        np.save(ciphers_path, ciphers_array, allow_pickle=True)

    def evaluate_intersection(self):
        ''' Evaluate the intersection after recieving bob's file \
         Bob's file should be located at "file_path/from_bob" '''
        ciphers_path = os.path.join(self.file_path, 'from_bob/ciphertexts.npy')
        if not os.path.isfile(ciphers_path):
            raise("Error: bob's file was not found")
        raw_ciphertexts = np.load(ciphers_path, allow_pickle=True)
        ciphertexts = np.array([Ciphertext(raw_cipher, self.encryption_scheme.public_key) for raw_cipher in raw_ciphertexts])
        decryptions = self.encryption_scheme.decrypt_to_encoded_message(ciphertexts)
        return np.intersect1d(self.messages, decryptions)