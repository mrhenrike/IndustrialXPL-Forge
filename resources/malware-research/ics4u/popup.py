import random
from tkinter import * 
import time
import threading

root = Tk()
root.attributes("-alpha",0)
root.overrideredirect(1)
root.attributes("-topmost",1)

def window()
    while True:
        win = Toplevel(root)
        win.geometry("330x60+" + str(randint(0,root.winfo_screenwidth()-300)) + "+" + str(randint(0, root.winfo_screenheight()-60)))
        win.overrideredirect(1)
        Label(win, text="HAha", fg-"red")
        win.lift