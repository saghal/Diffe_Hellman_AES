import socket
import re
import base64
from Crypto.Cipher import AES
import json

def base64_encode(message_bytes):
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message

def base64_decode(base64_message):
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    return message_bytes

def encrypt_AES_GCM(message, secretKey):
    aesCipher = AES.new(secretKey.to_bytes(16,'big'), AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(message)
    return (ciphertext, aesCipher.nonce, authTag)


def decrypt_AES_GCM(message, Bnonc, BauthTag, secretKey):
    ciphertext = message
    nonce = Bnonc
    authTag = BauthTag
    aesCipher = AES.new(secretKey.to_bytes(16,'big'), AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

cilentPrivateKey = 0x7250f5b473a13f2faffa851c4076bc2c # client private key

HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        b = b''
        tmp = s.recv(1024)
        if not tmp:
            continue
        b = b + tmp
        d = json.loads(b.decode('utf-8'))
        if(d['set']=='initialParametrs'):
            print('server registerd initial Parametrs')
            prime = int(d['firstParam'])
            print('prime: ',hex(prime))
            print('generator: ',d['secondParam'])
            clientPublicKey = (int(d['secondParam']) ^ cilentPrivateKey)% prime
            print('client public key: ',hex(clientPublicKey))
            print('client private key:', hex(cilentPrivateKey))
            msg = {'set':'initialParametrs','clientPublicKey':clientPublicKey}
            message = json.dumps(msg).encode('utf-8')
            s.sendall(message)

        if data.startswith('SERVER_PUBLIC_KEY'):                # Receiving servers's public key
            server_public = int(re.findall('[0-9]+' , data)[0])
            print('client public key:' , hex(client_public))
            print('client private key:', hex(cilent_private))
            print('server public key:' , hex(server_public))
            session_key = (server_public ^ cilent_private) % prime  # calculate session key base on server's public key and client's private key
            print("session_key:" , hex(session_key), '\n')

            plaintext = input('Enter your text to send\n')
            ciphertext, nonce = encryption(session_key, plaintext)

            base64_message = base64_encode(ciphertext)
            base64_message_nonce = base64_encode(nonce)
            print('\nthe plain text is  :', plaintext)
            print('the cipher text is :', base64_message)
            print('sending \'', base64_message, '\' (cipher text) to server...\n')
            data = 'CIPHER_TEXT:' + str(base64_message) + ', NONCE:' + str(base64_message_nonce) # send encryted data to server
            s.sendall(data.encode())

        if data.startswith('CIPHER_TEXT :'):                          # Receiving server's cipherText which encryted with session key
            print('Received -------> "', data, '"')
            ciphertext = re.findall('CIPHER_TEXT :(.+),', data)[0]
            nonce = re.findall('NONCE:(.+)', data)[0]
            print('\nraw cipher text of Received message: ', ciphertext)

            message_bytes = base64_decode(ciphertext)
            message_bytes_nonce = base64_decode(nonce)              # convert bsae64 nonce and cipherText to bytes
            plaintext = decryption(session_key, message_bytes, message_bytes_nonce)
            print('the dectypted message of Received message: ', plaintext)
            break
