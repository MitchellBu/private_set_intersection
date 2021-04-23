## PrimeGenerator class
Generates n-bit number which is a prime with high probability.
Includes implementation of Miller-Rabin algorithm that runs with a predefined number of iterations and a prior test for division by small primes (that accelerates the generation).
Failure probability exponentially decreases as confidence increases. 
Failure probability of a single iteration is upper bounded by 1/4 [[1]](https://kconrad.math.uconn.edu/blurbs/ugradnumthy/millerrabin.pdf).

