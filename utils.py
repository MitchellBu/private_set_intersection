import random

class PrimeGenerator(object):

    def __init__(self, num_of_bits, certainty):
        self.num_of_bits = num_of_bits
        self.certainty = certainty

    def get_prime(self):
        ''' generate the prime '''
        is_prime = False
        prime_candidate = 0
        while not is_prime:
            rand_bits = random.getrandbits(self.num_of_bits - 1)
            prime_candidate = 2 ** (self.num_of_bits - 1) + rand_bits #Assure that the MSB bit is 1
            is_prime = True
            for j in range(self.certainty):
                if not self._primality_check(prime_candidate):
                    is_prime = False
                    break
        return prime_candidate
            
    def _primality_check(self, number):
        ''' Miller-Rabin primality test implementation '''
        d = number - 1 # factorize n as n = (2^r)*d + 1
        r = 0
        while(d % 2 == 0):
            d /= 2
            r += 1
        d = int(d)
        witness = random.randint(2, number - 2)
        x = pow(witness, d, number)
        if x == 1 or x == number - 1:
            return True
        for i in range(r - 1):
            x = (x ** 2) % number
            if x == number - 1:
                return True
        return False

print(PrimeGenerator(128, 20).get_prime())




        
      