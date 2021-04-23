## PrimeGenerator class
Generates n-bit number which is a prime with high probability.
Includes implementation of the Miller-Rabin algorithm that runs with a predefined number of iterations,
along with a prior test that checks division by small primes (which accelerates the prime generation process).
Failure probability exponentially decreases as confidence increases. 
Failure probability of a single iteration is upper bounded by 1/4 [[1]](https://kconrad.math.uconn.edu/blurbs/ugradnumthy/millerrabin.pdf).

