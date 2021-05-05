import random
import numpy as np
import os
import small_primes
import datetime
import tqdm
from multiprocessing import Pool
import datetime
 
from cmath import exp, pi

class MathUtils:

    def _extended_gcd(self, num1, num2):
        """ Euclidean algorithm implementation """
        gcd, scalar_1, scalar_2 = 0, 0, 0
        a_0, a_1 = 1, 0
        b_0, b_1 = 0, 1
        while (num2 and num1):
            if num2 > num1:
                x = num2 // num1
                y = num2 % num1
                num2 = y
                b_0 -= x*a_0
                b_1 -= x*a_1
            else:
                x = num1 // num2
                y = num1 % num2
                num1 = y
                a_0 -= x*b_0
                a_1 -= x*b_1
        if num1 == 0:
            gcd,scalar_1, scalar_2 = num2, b_0, b_1
        else:
            gcd, scalar_1, scalar_2 = num1, a_0, a_1
        return gcd, scalar_1, scalar_2

    def gcd(self, num1, num2):
        """ Get the greatest common divisor of num1 and num2"""
        return self._extended_gcd(num1, num2)[0]

    def inverse(self, num, modulo):
        """ Find the modular inverse of num """
        return ((self._extended_gcd(num, modulo))[1] % modulo)
    
    def _next_power_of_two(self, num):
        """ get the next power of 2 of a number """
        if num == 0:
            return 1
        if num == 2 ** (num.bit_length() - 1):
            return num
        return 2 ** num.bit_length()

    def _pad_array(self, array, padding_size):
        """ pad array with padding_size zeros """
        return np.append(array, np.zeros(padding_size))
    
    def _remove_padding(self, array):
        """ remove zero padding from the end of the array """
        padding_start_index = (np.nonzero(array)[0])[-1] + 1
        return array[:padding_start_index]
        
    def _fast_DFT(self, sequence, w_n=None):
        """ compute the discrete fourier transform of the given sequence """
        if sequence.size == 1:
            return np.array([sequence[0]], dtype=np.cdouble)
        padding_size = self._next_power_of_two(sequence.size) - sequence.size
        sequence = self._pad_array(sequence, padding_size)
        w = 1
        N = sequence.size
        if w_n is None:
            w_n = exp(2j*pi/N)
        transform = np.zeros(N, dtype=np.cdouble)
        even_transform = self._fast_DFT(sequence[::2], w_n=w_n**2)
        odd_transform = self._fast_DFT(sequence[1::2], w_n=w_n**2)
        for k in range(N // 2):
            transform[k] = even_transform[k] + w * odd_transform[k]
            transform[k + N//2] = even_transform[k] - w * odd_transform[k]
            w *= w_n
        return transform

    def _fast_inverse_DFT(self, sequence):
        """ compute the inverse discrete fourier transform of the given sequence """
        N = sequence.size
        return self._fast_DFT(sequence, w_n=exp(-2j*pi/N)) / N

    def _fast_polynomials_multiplication(self, poly_1, poly_2):
        """ compute the coefficients of the product of the given polynomials """
        poly_1_padded = self._pad_array(poly_1, poly_2.size - 1)
        poly_1_FFT = self._fast_DFT(poly_1_padded)
        poly_2_padded = self._pad_array(poly_2, poly_1.size - 1)
        poly_2_FFT = self._fast_DFT(poly_2_padded)
        mul_FFT = poly_1_FFT * poly_2_FFT
        mul = self._fast_inverse_DFT(mul_FFT)
        mul = np.real(mul) # Get the real part of mul array
        mul = np.rint(mul).astype(int) # Integer rounding
        return self._remove_padding(mul)

    def polynomial_coefficients_from_roots(self, roots):
        """ compute the coefficients of the monic polynomial that has the specified roots """
        N = roots.size
        if N == 0:
            return np.array([1])
        if N == 1:
            return np.array([-roots[0], 1], dtype=int)
        first_roots = roots[0:N//2]
        poly_1 = self.polynomial_coefficients_from_roots(first_roots)
        last_roots = roots[N//2:N]
        poly_2 = self.polynomial_coefficients_from_roots(last_roots)
        return self._fast_polynomials_multiplication(poly_1, poly_2)

class PrimeGenerator:

    def __init__(self, num_of_bits, confidence):
        """ generate num_of_bits bits number which is a prime with high probability \
        failure probabilty upper bound exponentialy decreases as confidence increases """
        self.num_of_bits = num_of_bits
        self.confidence = confidence

    def get_prime(self):
        """ generate the prime """
        is_prime = False
        prime_candidate = 0
        while not is_prime:
            rand_bits = random.getrandbits(self.num_of_bits - 2)
            prime_candidate = 2 ** (self.num_of_bits - 2) + rand_bits 
            prime_candidate = prime_candidate * 2 + 1 #Assure that the MSB & LSB bits are both 1. 
            is_prime = (self._prime_sieving(prime_candidate) and self._primality_check(prime_candidate))
        return prime_candidate

    def _prime_sieving(self, number):
        """ Check that the number does not divide by any small prime """
        for p in small_primes.primes:
            if number % p == 0:
                return False
        return True
            
    def _primality_check(self, number):
        """ Miller-Rabin primality test implementation """
        d = number - 1 # factorize number as n = (2^r)*d + 1
        r = 0
        while(d % 2 == 0):
            d = d//2
            r += 1
        for _ in range(self.confidence):
            witness = random.randint(2, number - 2)
            x = pow(witness, d, number)
            if x == 1 or x == number - 1:
                continue
            passed_test = False
            for _ in range(r - 1):
                x = pow(x, 2, number)
                if x == number - 1:
                    passed_test = True
                    break
            if not passed_test:
                return False
        return True

class Ciphertext:

    def __init__(self, ciphertext, modulo):
        self.ciphertext = ciphertext
        self.modulo = modulo

    def __add__(self, other):
        """ Homomorphic encryption for the addition of the plaintexts """
        if other.modulo != self.modulo:
            raise("Error: ciphertext modulo mismatch.")
        return Ciphertext((self.ciphertext * other.ciphertext) % (self.modulo ** 2), self.modulo)

    def __mul__(self, num):
        """ Homomorphic encryption for the multiplication by scalar of the plaintext """
        effective_cipher = self.ciphertext
        if num < 0:
            effective_cipher = MathUtils().inverse(self.ciphertext, self.modulo ** 2)
            num = -num
        return Ciphertext(pow(effective_cipher, num, self.modulo ** 2), self.modulo)

    def __str__(self):
        return str(self.ciphertext)

class EncryptionScheme:

    def __init__(self):
        self.p = None
        self.q = None
        self.public_key = None # N = pq
        self.secret_key = None # phi(N) = (p-1)(q-1)
        self.N_squared = None

    def generate(self, security_param=128, prime_confidence=100):
        self.p = PrimeGenerator(security_param, prime_confidence).get_prime()
        self.q = PrimeGenerator(security_param, prime_confidence).get_prime()
        self.public_key = self.p * self.q
        self.N_squared = self.public_key ** 2
        self.secret_key = self.public_key - self.p - self.q + 1 # (p-1)(q-1) = pq - p - q + 1

    def to_file(self, file_path, include_secret_key=False):
        """ Save the scheme to a .npy file """
        if not file_path.endswith('.npy'):
            raise('Error: file extension has to be ".npy"')
        values = np.array([self.public_key], dtype=object)
        if include_secret_key:
            values = np.array([self.p, self.q, self.public_key, self.secret_key], dtype=object)
        np.save(file_path, values, allow_pickle=True)

    def from_file(self, file_path):
        """ Load the scheme from a .npy file """
        if not file_path.endswith('.npy'):
            raise('Error: file extension has to be ".npy"')
        try:
            scheme_data = np.load(file_path, allow_pickle=True)
        except:
            raise('Error: failed to open the scheme file.')
        try: # assume secret key included
            self.p, self.q, self.public_key, self.secret_key = tuple(scheme_data)
        except:
            self.public_key = scheme_data[0]
        self.N_squared = self.public_key ** 2

    def encrypt_single_message(self, plaintext):
        """ Encrypts single numeric plaintext """
        if not (type(plaintext) is int):
            raise "Error: plaintext has to be of int type"
        r = 0 
        N = self.public_key
        while MathUtils().gcd(r, self.public_key) != 1:
            r = random.randint(1, N - 1) # Assure that r in Zn*
        cipher_1 = (1 + plaintext * N) % self.N_squared #(1+N)^m mod N^2 = (1+mN) mod N^2
        cipher_2 = pow(r, N, self.N_squared) #r^N mod N^2
        final_cipher = (cipher_1 * cipher_2) % self.N_squared
        return Ciphertext(final_cipher, N)

    def decrypt_single_ciphertext(self, ciphertext):
        """ Decrypts single ciphertext of Ciphertext type """
        if not (type(ciphertext) is Ciphertext):
            raise "Error: ciphertext has to be of Ciphertext type"
        N = self.public_key
        if self.secret_key is None:
            raise('Error: secret key was not found.')
        cipher = ciphertext.ciphertext
        c_hat = pow(cipher, self.secret_key, self.N_squared) # c^phi(N) mod N^2
        m_hat = (c_hat - 1) // N
        return (m_hat * MathUtils().inverse(self.secret_key, self.N_squared)) % N    
        
    def encode_message(self, message):
        """ Outputs ASCII codes of message chars """
        return np.array([ord(char) for char in message], dtype=int)

    def decode_message(self, encoded_message):
        """ Outputs decoded message from ASCII array"""
        return ''.join(chr(code) for code in encoded_message)

    def encrypt_encoded_message(self, encoded_message_vector):
        """ Outputs the encryption of a whole encoded message """
        ciphertext_vector = np.array([self.encrypt_single_message(int(message)) for message in tqdm.tqdm(np.nditer(encoded_message_vector))], dtype=Ciphertext)
        ciphertext_vector = ciphertext_vector.reshape(encoded_message_vector.shape)           
        return ciphertext_vector

    def decrypt_to_encoded_message(self, ciphertext_vector):
        """ Decrypts a whole ciphertext to the encoded plaintext """
        encoded_plaintext_vector = np.array([self.decrypt_single_ciphertext(ciphertext) for ciphertext in ciphertext_vector])
        encoded_plaintext_vector = encoded_plaintext_vector.reshape(ciphertext_vector.shape)
        return encoded_plaintext_vector

class Hash:
    """ pairwise independent hash family implementation """
    
    def __init__(self):
        """ Initialize """
        self.p = None
        self.a, self.c = None, None
        self.b, self.d = None, None

    def generate(self, prime):
        """ Generate hash family parameters with respect to the prime """
        self.p = prime
        self.a, self.c = random.randint(1, self.p - 1), random.randint(1, self.p - 1)
        self.b, self.d = random.randint(0, self.p - 1), random.randint(0, self.p - 1)

    def hash(self, x):
        """ Compute the hash of the specified integer """
        hash_1 = (self.a * x + self.b) % self.p
        hash_2 = (self.c * x + self.d) % self.p
        return hash_1, hash_2

    def to_file(self, file_path):
        """ Save hash function parameters to file """
        if not file_path.endswith('.npy'):
            raise('Error: file extension has to be ".npy"')
        params = np.array([self.p, self.a, self.b, self.c, self.d])
        np.save(file_path, params, allow_pickle=True)

    def from_file(self, file_path):
        """ Load hash parameters from a .npy file """
        if not file_path.endswith('.npy'):
            raise('Error: file extension has to be ".npy"')
        try:
            params = np.load(file_path, allow_pickle=True)
        except:
            raise('Error: failed to open the scheme file.')
        self.p, self.a, self.b, self.c, self.d = tuple(params)
