import socket
import sys
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

def xor(s1, s2):
    return bytes([_a ^ _b for _a, _b in zip(s1, s2)])


def pad(s, size):
    if (len(s) < size):
        while (len(s) < size):
            s += '+'
            
    return s


def unpad(s):
    return s.replace('+', '')


# localhost (A pentru B)
host_ip = '127.0.0.1'
port = 1070

# cream socektul
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print ("Socket successfully created")
except socket.error as err:
    print("Socket creation failed with error! Try again.")
    exit(0)

# B se conecteaza la acelasi IP si port la care este si A (pentru B)
s.connect((host_ip, port))

# B primeste de la A modul ECB/CFB
data = s.recv(1024)
print('Received the mode: ', data.decode('utf-8'))
mode = data.decode('utf-8')
s.sendall(str.encode("Received"))

# B primeste de la A cheia criptata
data = s.recv(1024)
print('Received the encrypted key: ', data.decode('utf-8'))
encripted_K = data.decode('utf-8')
s.sendall(str.encode("Received"))

# B primeste de la A cheia K' (K' = K1)
data = s.recv(1024)
print('Received the K1 key: ', data.decode('utf-8'))
K1 = data.decode('utf-8')
s.sendall(str.encode("Received"))

# decriptam cheia criptata cu K'
BLOCK_SIZE = 16
iv = '00001111222233334444555566667777'

private_key = hashlib.sha256(str(K1).encode("utf-8")).digest()
encripted_K = base64.b64decode(encripted_K)
cipher = AES.new(private_key, AES.MODE_ECB)
K = unpad(str(cipher.decrypt(encripted_K)))
print(K)

# B primeste de la A mesajul sa confirme inceperea comunicarii
data = s.recv(1024)
print('Received the message: ', data.decode('utf-8'))

# B trimite confirmarea lui A
s.sendall(str.encode("Yes"))

# luam fiecare bloc criptat de la A si il decriptam
data = s.recv(1024)
block = iv

if (mode == "ECB"):
    while (str(data.decode('utf-8')) != "Done"):
        print('Received the encrypted block: ', data.decode('utf-8'))
        encrypted_block = data.decode('utf-8')
        print(len(encrypted_block))

        private_key = hashlib.sha256(str(K).encode("utf-8")).digest()
        encrypted_block = base64.b64decode(encrypted_block)
        cipher = AES.new(private_key, AES.MODE_ECB)
        block = unpad(str(cipher.decrypt(encrypted_block)))
        
        print(block)
        data = s.recv(1024)
else:
    while (str(data.decode('utf-8')) != "Done"):
        print('Received the encryped block: ', data.decode('utf-8'))
        encrypted = data.decode('utf-8')

        # criptam ciphertext cu cheia K
        private_key = hashlib.sha256(str(K).encode("utf-8")).digest()
        block = pad(str(block), BLOCK_SIZE)

        cipher = AES.new(private_key, AES.MODE_ECB)
        encr = base64.b64encode(cipher.encrypt(block))

        # facem xor intre criptarea lui ciphertext cu K si encrypted
        block = xor(str.encode(encrypted), encr)

        print(bytes.decode(block))
        data = s.recv(1024)