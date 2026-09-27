import time
startTime = time.time()
solved = False
num = 20
divi = 20
# 20 19 18 17 16 15 14 13 12 11 10 19 8 7 6 5 4 3 2 1

while solved == False:
        
        if 21162960 % divi == 0:
            divi -= 1
            if divi == 1:
                if str(num).endswith("0"):
                    solved = True
        else:
             print("error")
             print(divi)
             break