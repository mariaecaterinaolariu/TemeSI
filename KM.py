import socket
import random
import os
import base64
import hashlib
from Crypto.Cipher import AES

def pad(s, size):
    if (len(s) < size):
        while (len(s) < size):
            s += '+'
            
    return s


def unpad(s):
    return s.replace('+', '')

# localhost (A pentru KM)
host_ip = '127.0.0.1'
port = 1065

# cream socektul
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print ("Socket successfully created")
except socket.error as err:
    print("Socket creation failed with error! Try again.")
    exit(0)

# B se conecteaza la acelasi IP si port la care este si A (pentru KM)
s.connect((host_ip, port))
data = s.recv(1024)

# decode pentru a converti Bytes in string
print('Received the message: ', data.decode('utf-8'))

# generam random cheia K
hashK = '27349693387350391929422167390556'

# generam random cheia K'
hashK1 = '21704408273413638998853643881151'

BLOCK_SIZE = 16
#pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
#unpad = lambda s: s[:-ord(s[len(s) - 1:])]

# criptam cheia K cu K'
# private_key -> hash pentru cheia K1
private_key = hashlib.sha256(str(hashK1).encode("utf-8")).digest()
hashK = pad(str(hashK), BLOCK_SIZE)
cipher = AES.new(private_key, AES.MODE_ECB)

# base64 faciliteaza conversia byte -> string si invers
encripted_K = base64.b64encode(cipher.encrypt(hashK))
print(encripted_K)

# trimitem lui A cheia criptata
s.sendall(encripted_K)

data = s.recv(1024)
print('Received the message: ', data.decode('utf-8'))

# trimitem lui A cheia K'
s.sendall(str.encode(str(hashK1)))