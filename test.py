from alice import Alice
from bob import Bob
import numpy as np

alice_messages = np.array([1,2,3,4,5,6,999], dtype=int)
print("Alice's messages: " + str(alice_messages))
bob_messages = np.array([2,3,4,5,6,7,8,999], dtype=int)
print("Bob's messages: " + str(bob_messages))
file_path = '.'

alice = Alice(alice_messages, file_path)
bob = Bob(bob_messages, file_path)
print('Actual intersection: ' + str(alice.evaluate_intersection()))