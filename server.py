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
            data = conn.recv(1024)
            if not data:
                continue
            data = data.decode()
            if data.startswith('CLIENT_PUBLIC_KEY'):                    # Receiving client public key
                print('Received -------> "', data, '"')
                client_public = int(re.findall('[0-9]+' , data)[0])
                print('server public key:' , hex(server_public))
                print('server private key:' , hex(server_private))
                print('client public key:' , hex(client_public))

                session_key = (client_public ^ server_private) % prime  # calculate session key base on client public key and server private key
                print("session_key:" , hex(session_key), '\n\n')

            if data.startswith('CIPHER_TEXT'):                          # Receiving client cipherText which encryted with session key
                print('Received -------> "', data, '"')
                ciphertext = re.findall('CIPHER_TEXT:(.+),', data)[0]
                nonce = re.findall('NONCE:(.+)', data)[0]
                print('raw cipher text of Received message: ', ciphertext)

                message_bytes = base64_decode(ciphertext)
                message_bytes_nonce = base64_decode(nonce)              # convert bsae64 nonce and cipherText to bytes
                plaintext = decryption(session_key, message_bytes, message_bytes_nonce)
                print('the dectypted message of Received message: ', plaintext)

                plaintext = input('\nEnter your text to send\n')
                ciphertext, nonce = encryption(session_key, plaintext)

                base64_message = base64_encode(ciphertext)
                base64_message_nonce = base64_encode(nonce)
                print('\nthe plain text is  :', plaintext)
                print('the cipher text is :', base64_message)
                print('sending \'', base64_message, '\' (cipher text) to client...\n')

                data = 'CIPHER_TEXT :' + str(base64_message) + ', NONCE:' + str(base64_message_nonce) # send encryted data to client
                conn.sendall(data.encode())
                break
