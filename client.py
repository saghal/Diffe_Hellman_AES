import socket
import re
import base64
from Crypto.Cipher import AES
import json
import time

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

cilentPrivateKey = 0x7250f5b473a13f2faffa851c4076bc2c

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

        elif d['set'] == 'secondParametrs':
            serverPublicKey = int(d['firstParam'])
            print('serverPublicKey: ',hex(serverPublicKey))
            sessionKey = (serverPublicKey ^ cilentPrivateKey) % prime
            print('session Key: ',hex(sessionKey))
            plaintext = input('Write your message: ')
            tempPlaintext = bytes(plaintext,'utf-8')
            ciphertext = encrypt_AES_GCM(tempPlaintext,sessionKey)
            message = base64_encode(ciphertext[0])
            messageNonce = base64_encode(ciphertext[1])
            messageAuthTag = base64_encode(ciphertext[2])
            print('\n\nsending --> ',plaintext)
            print('cipher text: ',message)
            a = {'set':'clientMessage', 'firstParam':str(message),'secondParam':str(messageNonce), 'thirdParam':str(messageAuthTag)}
            b = json.dumps(a).encode('utf-8')
            s.sendall(b)

        elif d['set'] == 'sendMessage':
            print('\n\nReceived message from Server')
            print('cipher : ',d['firstParam'])
            message_bytes = base64_decode(d['firstParam'])
            message_bytes_nonce = base64_decode(d['secondParam'])              # convert bsae64 nonce and cipherText to bytes
            message_bytes_authTag = base64_decode(d['thirdParam'])
            plaintext = decrypt_AES_GCM(message_bytes, message_bytes_nonce, message_bytes_authTag, sessionKey)
            print('the dectypted message of Received message: ', plaintext)
            time.sleep(600)

            break
