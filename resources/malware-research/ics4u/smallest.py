import time
startTime = time.time()
solved = False
num = 20
divi = 19
# 20 19 18 17 16 15 14 13 12 11 10 19 8 7 6 5 4 3 2 1

while solved == False:
        
        if num % divi == 0:
            divi -= 1
            if divi == 10:
                solved = True
        else:
            num += 20
            divi = 19
            continue
print(num)
executionTime = (time.time() - startTime)
print(f'Execution time in seconds: {executionTime}')

