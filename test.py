from alice import Alice
from bob import Bob
import numpy as np
import datetime

alice_messages = np.arange(10000)
print("Alice's messages: " + str(alice_messages))
bob_messages = np.arange(5000, 15000)
print("Bob's messages: " + str(bob_messages))
file_path = '.'

alice = Alice(alice_messages, file_path)
bob = Bob(bob_messages, file_path)
t1 = datetime.datetime.now()
intersection = alice.evaluate_intersection()
t2 = datetime.datetime.now()
print('Actual intersection: ' + str(intersection))
print('Evaluating intersection took: ' + str(t2 - t1))