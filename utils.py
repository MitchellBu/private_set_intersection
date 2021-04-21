import random
import numpy as np
import os


class MathUtils(object):

    def _extended_gcd(self, num1, num2):
        ''' Euclidean algorithm implementation '''
        gcd, scalar_1, scalar_2 = 0, 0, 0
        a = np.array([1, 0], dtype=int)
        b = np.array([0, 1], dtype=int)
        while (num2 and num1):
            if num2 > num1:
                x = num2 // num1
                y = num2 % num1
                num2 = y
                b -= x*a
            else:
                x = num1 // num2
                y = num1 % num2
                num1 = y
                a -= x*b
        if num1 == 0:
            gcd,scalar_1, scalar_2 = num2, b[0], b[1]
        else:
            gcd, scalar_1, scalar_2 = num1, a[0], a[1]
        return gcd, scalar_1, scalar_2

    def gcd(self, num1, num2):
        ''' Get the greatest common divisor of num1 and num2'''
        return self._extended_gcd(num1, num2)[0]

    def inverse(self, num, modulo):
        ''' Find the modular inverse of num '''
        return ((self._extended_gcd(num, modulo))[1] % modulo)

class PrimeGenerator(object):

    def __init__(self, num_of_bits, confidence):
        ''' generate num_of_bits bits number which is a prime with high probability \
        failure probabilty upper bound exponentialy decreases as confidence increases '''
        self.num_of_bits = num_of_bits
        self.confidence = confidence

    def get_prime(self):
        ''' generate the prime '''
        is_prime = False
        prime_candidate = 0
        while not is_prime:
            rand_bits = random.getrandbits(self.num_of_bits - 1)
            prime_candidate = 2 ** (self.num_of_bits - 1) + rand_bits #Assure that the MSB bit is 1. 
            is_prime = self._primality_check(prime_candidate)
        return prime_candidate
            
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

class Ciphertext(object):

    def __init__(self, ciphertext, modulo):
        self.ciphertext = ciphertext
        self.modulo = modulo

    def __add__(self, other):
        ''' Homomorphic encryption for the addition of the plaintexts '''
        if other.modulo != self.modulo:
            raise("Error: ciphertext modulo mismatch.")
        return Ciphertext((self.ciphertext * other.ciphertext) % (self.modulo ** 2), self.modulo)

    def __mul__(self, num):
        ''' Homomorphic encryption for the multiplication by scalar of the plaintext '''
        effective_cipher = self.ciphertext
        if num < 0:
            effective_cipher = MathUtils().inverse(self.ciphertext, self.modulo ** 2)
            num = -num
        return Ciphertext(pow(effective_cipher, num, self.modulo ** 2), self.modulo)

    def __str__(self):
        return str(self.ciphertext)

class EncryptionScheme(object):

    #TODO: Research and implement huge ints handling

    def __init__(self):
        self.p = None
        self.q = None
        self.public_key = None # N = pq
        self.secret_key = None # phi(N) = (p-1)(q-1)

    def generate(self, security_param=256, prime_confidence=10):
        self.p = PrimeGenerator(security_param, prime_confidence).get_prime()
        self.q = PrimeGenerator(security_param, prime_confidence).get_prime()
        self.public_key = self.p * self.q
        self.secret_key = self.public_key - self.p - self.q + 1 # (p-1)(q-1) = pq - p - q + 1

    def to_file(self, file_path, include_secret_key=False):
        ''' Save the scheme to a .npy file '''
        values = np.array([self.public_key])
        if include_secret_key:
            values = np.array([self.p, self.q, self.public_key, self.secret_key])
        np.save(file_path, values)

    def from_file(self, file_path):
        ''' Load the scheme from a .npy file '''
        with np.load(file_path) as scheme_data:
            try: # assume secret key included
                self.p, self.q, self.public_key, self.secret_key = tuple(scheme_data)
                self.p = int(self.p)
                self.q = int(self.q)
                self.secret_key = int(self.secret_key)
            except:
                self.public_key = scheme_data[0]
            self.public_key = int(self.public_key)

    def encrypt_single_message(self, plaintext):
        ''' Encrypts single numeric plaintext '''
        if not (type(plaintext) is int):
            raise "Error: plaintext has to be of int type"
        r = 0 
        N = self.public_key
        N_squared = N ** 2
        while MathUtils().gcd(r, self.public_key) != 1:
            r = random.randint(1, N - 1) # Assure that r in Zn*
        cipher_1 = pow(1 + N, plaintext, N_squared) #(1+N)^m mod N^2
        cipher_2 = pow(r, N, N_squared) #r^N mod N^2
        final_cipher = (cipher_1 * cipher_2) % N_squared
        return  Ciphertext(final_cipher, N)

    def decrypt_single_ciphertext(self, ciphertext):
        ''' Decrypts single ciphertext of Ciphertext type'''
        if not (type(ciphertext) is Ciphertext):
            raise "Error: ciphertext has to be of Ciphertext type"
        N = self.public_key
        N_squared = N ** 2
        if self.secret_key is None:
            raise('Error: secret key was not found.')
        cipher = ciphertext.ciphertext
        c_hat = pow(cipher, self.secret_key, N_squared) # c^phi(N) mod N^2
        m_hat = int((c_hat - 1) / N)
        return (m_hat * MathUtils().inverse(self.secret_key, N_squared)) % N    
        
    def encode_message(self, message):
        ''' Outputs ASCII codes of message chars'''
        return np.array([ord(char) for char in message], dtype=int)

    def decode_message(self, encoded_message):
        ''' Outputs decoded message from ASCII array'''
        return ''.join(chr(code) for code in encoded_message)

    def encrypt_encoded_message(self, encoded_message_vector):
        ''' Outputs the encryption of a whole encoded message '''
        ciphertext_vector = np.array([self.encrypt_single_message(message) for message in encoded_message_vector])            
        return ciphertext_vector

    def decrypt_to_encoded_message(self, ciphertext_vector):
        ''' Decrypts a whole ciphertext to the encoded plaintext'''
        encoded_plaintext_vector = np.array([self.decrypt_single_ciphertext(ciphertext) for ciphertext in ciphertext_vector])
        return encoded_plaintext_vector

        
scheme = EncryptionScheme()
scheme.generate(security_param=10)
print("Scheme info: p: " + str(scheme.p) + ", q: " + str(scheme.q) + ", N: " + str(scheme.public_key) + ", phi: " + str(scheme.secret_key))
message_1 = 100
cipher_1 = scheme.encrypt_single_message(message_1)
message_2 = 200
cipher_2 = scheme.encrypt_single_message(message_2)
cipher = cipher_1 + cipher_2 # Demonstration of additive homomorphic property! 
restored_plain = scheme.decrypt_single_ciphertext(cipher)
print("Original message: " + str(message_1 + message_2) + ", ciphertext: " + str(cipher) + ", restored plaintext: " + str(restored_plain))
message_3 = 111
cipher_3 = scheme.encrypt_single_message(message_3)
scalar = 3
cipher_3_mul = cipher_3 * scalar # Demonstration of scalar multiplication property!
res_3 = scheme.decrypt_single_ciphertext(cipher_3_mul)
print("Original message: " + str(message_3 * scalar) + ", ciphertext: " + str(cipher_3_mul) + ", restored plaintext: " + str(res_3))