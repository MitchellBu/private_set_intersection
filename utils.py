import random
import numpy as np
import os

class PrimeGenerator(object):

    def __init__(self, num_of_bits, confidence):
        ''' generate num_of_bits bits number which is a prime of the form 2*p + 1 with high probability \
        failure probabilty upper bound exponentialy decreases as confidence increases '''
        self.num_of_bits = num_of_bits
        self.confidence = confidence

    def get_prime(self):
        ''' generate the prime '''
        is_prime = False
        is_special_prime = False # prime p such that 2*p + 1 is also a prime
        prime_candidate = 0
        while (not is_prime) or (not is_special_prime):
            rand_bits = random.getrandbits(self.num_of_bits - 2)
            prime_candidate = 2 ** (self.num_of_bits - 2) + rand_bits #Assure that the MSB bit is 1. 
            is_prime = self._primality_check(prime_candidate)
            is_special_prime = self._primality_check(2 * prime_candidate + 1)
        return (2 * prime_candidate + 1)
            
    def _primality_check(self, number):
        ''' Miller-Rabin primality test implementation '''
        d = number - 1 # factorize number as n = (2^r)*d + 1
        r = 0
        while(d % 2 == 0):
            d = int(d / 2)
            r += 1
        for _ in range(self.confidence):
            witness = random.randint(2, number - 2)
            x = pow(witness, d, number)
            if x == 1 or x == number - 1:
                continue
            passed_test = False
            for _ in range(r - 1):
                x = (x ** 2) % number
                if x == number - 1:
                    passed_test = True
                    break
            if not passed_test:
                return False
        return True

class EncryptionScheme(object):

    def __init__(self):
        self.p = None
        self.q = None
        self.g = None
        self.public_key = None
        self.secret_key = None
        self.lookup_dict = None

    def generate(self, security_param=256, prime_confidence=40, max_message=128): #ASCII table contains 128 chars
        self.p = PrimeGenerator(security_param, prime_confidence).get_prime()
        self.q = self.p - 1 # |G| = q
        self.g = 1
        while pow(self.g, 2, self.p) == 1: #Sufficient condition since p is of the form p = 2q + 1
            self.g = random.randint(2, self.q - 1)
        self.lookup_dict = {}
        group_element = 1
        for exp in range(max_message):
            self.lookup_dict[group_element] = exp
            group_element = (group_element * self.g) % self.p

    def gen_keys(self):
        x = random.randint(1, self.q - 1)
        self.public_key = pow(self.g, x, self.p)
        self.secret_key = x

    def to_file(self, file_path, include_secret_key=False):
        ''' Save the scheme to a compressed npz file '''
        values = np.array([self.p, self.q, self.g, self.public_key])
        if include_secret_key:
            values = np.array([self.p, self.q, self.g, self.public_key, self.secret_key])
        lookup_arr = np.array(list(self.lookup_dict.items()))
        np.savez(file_path, values=values, lookup_arr=lookup_arr)

    def from_file(self, file_path):
        ''' Load the scheme from a compressed npz file '''
        with np.load(file_path) as scheme_data:
            values = scheme_data['values']
            try: # assume secret key included
                self.p, self.q, self.g, self.public_key, self.secret_key = tuple(values)
                self.secret_key = int(self.secret_key)
            except:
                self.p, self.q, self.g, self.public_key = tuple(values)
            self.p = int(self.p)
            self.q = int(self.q)
            self.g = int(self.g)
            self.public_key = int(self.public_key)
            lookup_arr = scheme_data['lookup_arr']
            self.lookup_dict = {int(key) : int(value) for [key, value] in lookup_arr}

    #TODO: Add support for very large ints
    #TODO: performance checks
        
    def encode_message(self, message):
        ''' Outputs ASCII codes of message chars'''
        return np.array([ord(char) for char in message], dtype=int)

    def decode_message(self, encoded_message):
        ''' Outputs decoded message from ASCII array'''
        return ''.join(chr(code) for code in encoded_message)

    def _encrypt_single_code(self, code):
        ''' Encrypts single ASCII code plaintext '''
        y = random.randint(1, self.q - 1) # y <- {1,...,q-1}
        encryptor = pow(self.g, y, self.p) # g^y mod p
        powered_message = pow(self.g, int(code), self.p) # g^m mod p
        powered_key = pow(self.public_key, y, self.p) # h^y mod p
        ciphertext = [encryptor, (powered_message * powered_key) % self.p] # (g^y mod p, (g^m * h^y) mod p)
        return ciphertext

    def encrypt_encoded_message(self, encoded_message_vector):
        ''' Outputs the encryption of a whole encoded message '''
        ciphertext_vector = np.array([self._encrypt_single_code(code) for code in encoded_message_vector])            
        return ciphertext_vector

    def _decrypt_single_ciphertext(self, ciphertext):
        ''' Decrypts single ciphertext pair (.,.) to its corresponding ASCII code'''
        if self.secret_key is None:
            raise('Error: secret key was not found.')
        encryptor = int(ciphertext[0]) # g^y mod p
        encrypted_message = ciphertext[1] # (g^m * h^y) mod p
        powered_message = (encrypted_message * pow(encryptor, self.q - self.secret_key, self.p)) % self.p # g^m = ((g^m * h^y) mod p / g^y mod p) mod p
        return self.lookup_dict[powered_message] # g^m -> m

    def decrypt_to_encoded_message(self, ciphertext_vector):
        ''' Decrypts a whole ciphertext to the encoded plaintext'''
        encoded_plaintext_vector = np.array([self._decrypt_single_ciphertext(ciphertext) for ciphertext in ciphertext_vector])
        return encoded_plaintext_vector

        
      