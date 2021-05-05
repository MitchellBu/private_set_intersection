from utils import EncryptionScheme, Ciphertext, Hash
import numpy as np
import os, random, datetime, tqdm

class Bob:

    def __init__(self, messages, file_path):
        """ PSI receiver side implementation. \
            Gets as input public_key and ciphertexts files located at file_path/to_bob"""
        if type(messages) != np.ndarray:
            raise('Error: the messages should be passed as a numpy array')
        self.messages = messages
        self.file_path = file_path
        base_path = os.path.join(self.file_path, 'to_bob')
        key_path = os.path.join(base_path, 'public_key.npy')
        ciphers_path = os.path.join(base_path, 'ciphertexts.npy')
        hash_path = os.path.join(base_path, 'hash_params.npy')
        if not os.path.isdir(base_path) \
        or not os.path.isfile(key_path) \
        or not os.path.isfile(ciphers_path) \
        or not os.path.isfile(hash_path):
            raise("Error: Alice's files were not found")
        
        self.encryption_scheme = EncryptionScheme()
        self.encryption_scheme.from_file(key_path)
        self.modulo = self.encryption_scheme.public_key
        raw_encrypted_polynomial = np.load(ciphers_path, allow_pickle=True)
        self.hash = Hash()
        self.hash.from_file(hash_path)
        t1 = datetime.datetime.now()
        self.encrypted_polynomials = np.array([Ciphertext(raw_encrypted_polynomial[i,j], self.modulo) for i in range(raw_encrypted_polynomial.shape[0]) for j in range(raw_encrypted_polynomial.shape[1])])
        self.encrypted_polynomials = self.encrypted_polynomials.reshape((raw_encrypted_polynomial.shape[0], raw_encrypted_polynomial.shape[1]))
        homomorphic_encs = self._compute_homomorphic_encryptions()
        t2 = datetime.datetime.now()
        print("Bob's computations took: " + str(t2-t1))
        raw_encs = np.array([cipher.ciphertext for cipher in homomorphic_encs])
        raw_encs = np.random.permutation(raw_encs) # Permute set elements to hide order
        output_path = os.path.join(self.file_path, 'from_bob')
        if not os.path.isdir(output_path):
            os.mkdir(output_path)
        ciphers_path = os.path.join(output_path, 'ciphertexts.npy')
        np.save(ciphers_path, raw_encs, allow_pickle=True)

    def _homomorphic_poly_evaluation(self, message):
        """ Evaluate Enc(P(y)) for the specified message and the relevant polynomial \
            using Horner's rule for short exponentations """
        hash_1, hash_2 = self.hash.hash(message)
        poly_1 = self.encrypted_polynomials[hash_1]
        poly_2 = self.encrypted_polynomials[hash_2]
        result_1, result_2 = self.encryption_scheme.encrypt_single_message(0), self.encryption_scheme.encrypt_single_message(0)
        result_1 += poly_1[-1] # Coefficient of the largest power, a_n
        result_2 += poly_2[-1]
        for coefficient in np.flip(poly_1)[1:]:
            result_1 = result_1 * message + coefficient
        for coefficient in np.flip(poly_2)[1:]:
            result_2 = result_2 * message + coefficient
        return result_1, result_2

    def _compute_homomorphic_encryptions(self):
        """ Evaluates Enc(P(y)*r + y) for all messages y """
        homomorphic_encs = np.array([item for message in self.messages for item in self._homomorphic_poly_evaluation(int(message))])
        for i in tqdm.tqdm(range(homomorphic_encs.size)):
            homomorphic_encs[i] *= random.randint(1, self.modulo - 1)
            homomorphic_encs[i] += self.encryption_scheme.encrypt_single_message(int(self.messages[i//2]))
        return homomorphic_encs
