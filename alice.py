import numpy as np
from utils import MathUtils, Ciphertext, EncryptionScheme, Hash, PrimeGenerator
import os
import tqdm, datetime

class Alice:

    def __init__(self, messages, file_path):
        """ PSI sender side implementation. \
            The relevant files for bob will be located at "file_path/to_bob" """
        if type(messages) != np.ndarray:
            raise('Error: the messages should be passed as a numpy array')
        self.messages = messages
        self.file_path = file_path
        self.hash_table_size = round(len(messages) / np.log(np.log(messages.size)))
        print('Number of bins: ' + str(self.hash_table_size))
        self.max_bin_size = round(5 * np.log(np.log(messages.size)))
        print('Single Bin size: ' + str(self.max_bin_size))
        self.hash = Hash()
        self.hash.generate(self.hash_table_size)
        self.polynomials = self._compute_polynomials()
        self.encryption_scheme = EncryptionScheme()
        self.encryption_scheme.generate()
        t1 = datetime.datetime.now()
        encrypted_poly = self.encryption_scheme.encrypt_encoded_message(self.polynomials)
        t2 = datetime.datetime.now()
        print("Alice's coefficients encryption took " + str(t2-t1))
        base_path = os.path.join(self.file_path, 'to_bob')
        if not os.path.isdir(base_path):
            os.mkdir(base_path)
        key_path = os.path.join(base_path, 'public_key.npy')
        self.encryption_scheme.to_file(key_path)
        ciphers_path = os.path.join(base_path, 'ciphertexts.npy')
        hash_path = os.path.join(base_path, 'hash_params.npy')
        self.hash.to_file(hash_path)
        ciphers_array = np.array([encrypted_poly[i,j].ciphertext for i in range(encrypted_poly.shape[0]) for j in range(encrypted_poly.shape[1])], dtype=object)
        ciphers_array = ciphers_array.reshape(encrypted_poly.shape)
        np.save(ciphers_path, ciphers_array, allow_pickle=True)

    def _compute_polynomials(self):
        polynomials = np.zeros((self.hash_table_size, self.max_bin_size), dtype=int)
        roots_by_hash = [[] for _ in range(self.hash_table_size)]
        for message in self.messages:
            hash_1, hash_2 = self.hash.hash(message)
            if len(roots_by_hash[hash_1]) < len(roots_by_hash[hash_2]):
                roots_by_hash[hash_1].append(message)
            else:
                roots_by_hash[hash_2].append(message)
        print('Maximum actual items in a single bin: ' + str(max([len(row) for row in roots_by_hash])))
        for i in range(len(roots_by_hash)):
            roots = np.array(roots_by_hash[i])
            poly = MathUtils().polynomial_coefficients_from_roots(roots)
            for j in range(-int(poly.size), 0, 1):
                polynomials[i, j] = poly[j + poly.size]
        return polynomials
      
    def evaluate_intersection(self):
        """ Evaluate the intersection after recieving bob's file \
         Bob's file should be located at "file_path/from_bob" """
        ciphers_path = os.path.join(self.file_path, 'from_bob/ciphertexts.npy')
        if not os.path.isfile(ciphers_path):
            raise("Error: bob's file was not found")
        raw_ciphertexts = np.load(ciphers_path, allow_pickle=True)
        ciphertexts = np.array([Ciphertext(int(raw_cipher), self.encryption_scheme.public_key) for raw_cipher in raw_ciphertexts])
        decryptions = self.encryption_scheme.decrypt_to_encoded_message(ciphertexts)
        print('Alice sees from Bob: ' + str(decryptions))
        return np.intersect1d(self.messages, decryptions)