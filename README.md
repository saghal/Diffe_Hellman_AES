
# Diffie-Hellman algorithm for key exchange with AES encryption  

Simple implemention of AES-128 with Diffie-Hellman algorythm for key exchange between client and server (socket)

<img  src="https://upload.wikimedia.org/wikipedia/commons/thumb/4/46/Diffie-Hellman_Key_Exchange.svg/1200px-Diffie-Hellman_Key_Exchange.svg.png">
## Getting Started
The program require some initial paramaters which can be produced by Openssl

### Prerequisites
Install Openssl from [here](https://www.openssl.org/source/)

then install pycrypto:
```
pip install pycryptodome
```
## How to run
- #### step 0
   ```
   git clone https://github.com/saghal/Diffe_Hellman_AES.git
   ```
    * after cloning you can set new keys for client and server
- #### step 1 
    ```
    python server.py
    ```
- #### step 2 
    ```
    python client.py
    ```
## How to generate keys
- ### produce DH initial parameters with openssl
   with this command in Openssl, two public parameters for DH algorithm will produce and with next command we can see them.
    ```
    dhparam -out dhp.pem 128
    pkeyparam -in dhp.pem -text
    ```
- ### how to genrate  server/client   public/private key
    then we can create private key for both sides and see the private keys
    ```
    genpkey -paramfile dhp.pem -out dhkey_client.pem
    genpkey -paramfile dhp.pem -out dhkey_server.pem
    pkey -in dhkey_client.pem -text -noout
    pkey -in dhkey_server.pem -text -noout
    ```

##### more information for generate this keys
* [openssl DH compute key](https://www.php.net/manual/en/function.openssl-dh-compute-key.php)
* [Diffie Hellman Secret key Exchange using openssl](https://sandilands.info/sgordon/diffie-hellman-secret-key-exchange-with-openssl)

## helpful resources
* [python sockets](https://realpython.com/python-sockets/)
* [AES GCM](https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf)