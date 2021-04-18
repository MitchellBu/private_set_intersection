import random

class PrimeGenerator(object):

    def __init__(self, num_of_bits, certainty):
        ''' generate num_of_bits bits number which is a prime of the form 2*p + 1 with high probability \
        failure probabilty upper bound exponentialy decreases as certainty increases '''
        self.num_of_bits = num_of_bits
        self.certainty = certainty

    def get_prime(self):
        ''' generate the prime '''
        is_prime = False
        is_special_prime = False # prime p such that 2*p + 1 is also a prime
        prime_candidate = 0
        while (not is_prime) or (not is_special_prime):
            rand_bits = random.getrandbits(self.num_of_bits - 2)
            prime_candidate = 2 ** (self.num_of_bits - 1) + rand_bits #Assure that the MSB bit is 1. 
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
        for _ in range(self.certainty):
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

    def __init__(self, security_param=256, prime_certainty=40, max_message=128): #ASCII table contains 128 chars
        self.p = PrimeGenerator(security_param, prime_certainty).get_prime()
        self.q = self.p - 1 # |G| = q
        self.g = 1
        while pow(self.g, 2, self.p) == 1: #Sufficient condition since p is of the form p = 2q + 1
            self.g = random.randint(2, self.q - 1)
        self.public_key = None
        self.secret_key = None
        self.lookup_dict = {}
        group_element = 1
        for exp in range(max_message):
            self.lookup_dict[group_element] = exp
            group_element = (group_element * self.g) % self.p

    #TODO: Add a method for saving/loading the scheme to/from a file (with and without the secret key)
    #TODO: Encoding and decoding a string to/from array of ASCII codes
    #TODO: Generalize the above for multiple messages.. How to seperate messages?
    #TODO: performance checks
        
    def gen_keys(self):
        x = random.randint(1, self.q - 1)
        self.public_key = pow(self.g, x, self.p)
        self.secret_key = x

    def encrypt_message(self, message):
        y = random.randint(1, self.q - 1)
        encryptor = pow(self.g, y, self.p)
        powered_message = pow(self.g, message, self.p)
        powered_key = pow(self.public_key, y, self.p) 
        return encryptor,  (powered_message * powered_key) % self.p

    def decrypt_message(self, ciphertext):
        encryptor = ciphertext[0]
        encrypted_message = ciphertext[1]
        powered_message = (encrypted_message * pow(encryptor, self.q - self.secret_key, self.p)) % self.p
        return self.lookup_dict[powered_message]


# Some testing :)
scheme = EncryptionScheme(security_param=10)
scheme.gen_keys()
print(scheme.p)
print(scheme.g)
print(scheme.secret_key)
print(scheme.public_key)
print(len(scheme.lookup_dict))
message = 123
cipher = scheme.encrypt_message(message)
print("Original message: " + str(message) + " >> Ciphertext: " + str(cipher) + " >> Decrypted plaintext: " + str(scheme.decrypt_message(cipher)))

        
      