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

# server generate a prime number and generater(for example with openssl)
prime = 0xba01af369bef860023562c7f5e517a9b
generator = 2

serverPrivateKey = 0x4de0438f4457df470dd099a3c108a9cc # server private key
serverPublicKey = (generator ^ serverPrivateKey) % prime    # calculate public key

HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    b = b''

    with conn:
        print('Connected by', addr)
        print('set initial paramters prime and generater')
        msg = {'set':'initialParametrs', 'firstParam':str(prime), 'secondParam':str(generator), 'thirdParam':''}
        message = json.dumps(msg).encode('utf-8')
        conn.sendall(message)
        print('server public key:' , hex(serverPublicKey))
        print('server private key:' , hex(serverPrivateKey))
        print('prime:', prime)
        print('generator:',generator)
        msg = {'set':'secondParametrs', 'firstParam':str(serverPublicKey), 'secondParam':str(generator), 'thirdParam':''}
        message = json.dumps(msg).encode('utf-8')
        conn.sendall(message)

        print('send initial paramters to client for connection')

        while True:
            b = b''
            tmp = conn.recv(1024)
            b = b + tmp
            d = json.loads(b.decode('utf-8'))

            if not tmp:
                continue

            elif d['set'] == 'initialParametrs':
                print('\n\nclient Public Key Received')
                clientPublicKey = int(d['clientPublicKey'])
                print('client Public Key: ',clientPublicKey)
                sessionKey = (clientPublicKey ^ serverPrivateKey) % prime
                print('session Key:', hex(sessionKey))

            elif d['set'] == 'clientMessage':
                print('\n\nReceived message from client : ' , d['firstParam'] )
                message = base64_decode(d['firstParam'])
                messageNonce = base64_decode(d['secondParam'])
                messageAuthTag = base64_decode(d['thirdParam'])
                plaintext = decrypt_AES_GCM(message, messageNonce, messageAuthTag, sessionKey)
                print('the dectypted message of Received message: ', plaintext)

                plaintext = input('\nWrite your message: ')
                tempPlaintext = bytes(plaintext,'utf-8')
                ciphertext= encrypt_AES_GCM(tempPlaintext,sessionKey)
                message = base64_encode(ciphertext[0])
                messageNonce = base64_encode(ciphertext[1])
                messageAuthTag = base64_encode(ciphertext[2])
                print('\n\nsend --> ',plaintext)
                print('cipher text: ',message)

                msg = {'set':'sendMessage', 'firstParam':str(message), 'secondParam':str(messageNonce), 'thirdParam':str(messageAuthTag)}
                message = json.dumps(msg).encode('utf-8')
                conn.sendall(message)
                time.sleep(600)
