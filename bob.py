from utils import EncryptionScheme, Ciphertext
import numpy as np
import os, random

class Bob(object):

    def __init__(self, messages, file_path):
        ''' PSI receiver side implementation. \
            Gets as input public_key and ciphertexts files located at file_path/to_bob'''
        if type(messages) != np.ndarray:
            raise('Error: the messages should be passed as a numpy array')
        self.messages = messages
        self.file_path = file_path
        base_path = os.path.join(self.file_path, 'to_bob')
        key_path = os.path.join(base_path, 'public_key.npy')
        ciphers_path = os.path.join(base_path, 'ciphertexts.npy')
        if not os.path.isdir(base_path) \
        or not os.path.isfile(key_path) \
        or not os.path.isfile(ciphers_path):
            raise("Error: Alice's files were not found")
        
        self.encryption_scheme = EncryptionScheme()
        self.encryption_scheme.from_file(key_path)
        self.modulo = self.encryption_scheme.public_key
        raw_encrypted_polynomial = np.load(ciphers_path, allow_pickle=True)
        self.encrypted_polynomial = np.array([Ciphertext(cipher, self.modulo) for cipher in raw_encrypted_polynomial])
        homomorphic_encs = self._compute_homomorphic_encryptions()
        raw_encs = np.array([cipher.ciphertext for cipher in homomorphic_encs])
        output_path = os.path.join(self.file_path, 'from_bob')
        if not os.path.isdir(output_path):
            os.mkdir(output_path)
        ciphers_path = os.path.join(output_path, 'ciphertexts.npy')
        np.save(ciphers_path, raw_encs, allow_pickle=True)

    def _homomorphic_poly_evaluation(self, message):
        ''' Evaluate Enc(P(y)) for the specified message '''
        result = self.encryption_scheme.encrypt_single_message(0)
        var = 1
        for coefficient in self.encrypted_polynomial:
            result = result + (coefficient * var)
            var = (var * message) % self.modulo
        return result

    def _compute_homomorphic_encryptions(self):
        ''' Evaluates Enc(P(y)*r + y) for all messages y'''
        homomorphic_encs = np.array([self._homomorphic_poly_evaluation(int(message)) for message in self.messages])
        for i in range(homomorphic_encs.size):
            homomorphic_encs[i] *= random.randint(1, self.modulo - 1)
            homomorphic_encs[i] += self.encryption_scheme.encrypt_single_message(int(self.messages[i]))
        return homomorphic_encs
