import socket
import os 
import sys 
import base64
import hashlib
from Crypto.Cipher import AES
import random

def xor(s1, s2):
    return bytes([_a ^ _b for _a, _b in zip(s1, s2)])


def pad(s, size):
    if (len(s) < size):
        while (len(s) < size):
            s += '+'
            
    return s


def unpad(s):
    return s.replace('+', '')


# A stabileste modul (ECB sau CFB)
mode = "CFB"

# localhost (pentru KM)
host_ip = '127.0.0.1'
port = 1065

# localhost cu alt port (pentru B)
host_ip1 = '127.0.0.1'
port1 = 1070

# socketul pentru KM
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print ("Socket successfully created")
except socket.error as err:
    print("Socket creation failed with error! Try again.")
    exit(1)

# socketul pentru B
try:
    s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print ("Socket successfully created")
except socket.error as err:
    print("Socket creation failed with error! Try again.")
    exit(2)

# A creeaza un server B
s1.bind((host_ip1, port1))
s1.listen()
conn1, addr1 = s1.accept()

# trimitem modul de criptare la B
# folosim econde pentru a transforma un string in Bytes
conn1.sendall(str.encode(mode))

# blocking call (suspenda executia temporar)
data1 = conn1.recv(1024)

# A creeaza un server pentru KM
s.bind((host_ip, port))
s.listen()
conn, addr = s.accept()

# cerem cheia de criptare de la KM
conn.sendall(str.encode("Encrypted key"))

# blocking call (suspenda executia temporar)
data = conn.recv(1024)
encripted_K = data.decode('utf-8')

# trimitem si la B cheia criptata
conn1.sendall(data)
data1 = conn1.recv(1024)

# cerem cheia K' de la KM
conn.sendall(str.encode("K' key"))

# blocking call (suspenda executia temporar)
data = conn.recv(1024)
K1 = data.decode('utf-8')

# trimitem si la B cheia K' generata
conn1.sendall(data)
data1 = conn1.recv(1024)

# decriptam cheia criptata cu K'
BLOCK_SIZE = 16
iv = '00001111222233334444555566667777'

private_key = hashlib.sha256(str(K1).encode("utf-8")).digest()
encripted_K = base64.b64decode(encripted_K)
cipher = AES.new(private_key, AES.MODE_ECB)
K = unpad(str(cipher.decrypt(encripted_K)))
print("Decrypted key: " + K)

# cerem de la B confirmarea inceperii comunicarii
conn1.sendall(str.encode("Shall we start?"))
data1 = conn1.recv(1024)
print('Received the confirmation: ', data1.decode('utf-8'))

# citim plaintextul din fisier
fin = open("plaintext.txt", "r")

# impartim plaintextul pe blocuri de 16 biti
block = fin.read(BLOCK_SIZE)
ciphertext = iv

# criptam fiecare bloc in parte si il trimitem la B
if (mode == "ECB"):
    while (block):
        if (block[len(block) - 1] == '/n' and len(block) > 1):
            break 

        private_key = hashlib.sha256(str(K).encode("utf-8")).digest()
        block = pad(str(block), BLOCK_SIZE)

        cipher = AES.new(private_key, AES.MODE_ECB)
        encrypted_block = base64.b64encode(cipher.encrypt(block))

        # trimitem la B blocul criptat
        conn1.sendall(encrypted_block)

        print("Current block: " + block)
        block = fin.read(BLOCK_SIZE)
else:
    while (block):
        if (block[len(block) - 1] == '/n' and len(block) > 1):
            break 

        # criptam ciphertext cu cheia K
        private_key = hashlib.sha256(str(K).encode("utf-8")).digest()
        ciphertext = pad(str(ciphertext), BLOCK_SIZE)

        cipher = AES.new(private_key, AES.MODE_ECB)
        encr = base64.b64encode(cipher.encrypt(ciphertext))

        # facem xor intre criptarea lui ciphertext cu K si bloc
        ciphertext = xor(str.encode(block), encr)

        # trimitem la B blocul criptat
        conn1.sendall(ciphertext)

        print("Current block: " + block)
        block = fin.read(BLOCK_SIZE)


print("Done!")
conn1.sendall(str.encode("Done"))