import time
from math import lcm

# a_list = {10,11,12,13,14,15,16,17,18,19}
startTime = time.time()

print(lcm(*range(10,21)))
# print(lcm(*a_list))

executionTime = (time.time() - startTime)
print(f'Execution time in seconds: {executionTime}')
