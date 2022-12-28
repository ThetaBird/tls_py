# tls_py
A brief recreation of TLS client-server handshake &amp; communication in Python.

### Details
This is a simple imitation of how files can be sent securely with the use of RSA public/private key pairs to exchange a symmetric AES key for efficient encryption &amp; decryption of a file sent over a connection. 
A mock Certificate Authority (CA) is also generated to demonstrate the prevention of man-in-the-middle (MiTM) attacks.
- All files with .cert and .key extensions can be deleted; if missing, they are re-generated and written to their respective files on initialization of the server and client .py programs. 
- The CA directory contains the public & private keys used in signing and verifying certificates. It also contains the generated certificates for the client & server (respective public RSA keys signed with the CA's private RSA key)
- The Client directory contains the RSA key pairs (pub.key and pri.key), as well as a **received/** directory, which contains the file(s) received from the server & decrypted. The client behavior is defined in Client.py.
 - Client.py can be run with:
 ```sh 
 python3 ./Client/Client.py
 # make sure the appropriate packages are installed with pip.
 ```
- The Server directory contains the RSA key pairs (pub.key and pri.key), as well as a **public/** directory, which contains the file(s) to encrypt and send to the client. The server behavior is defined in Server.py.
 - Server.py can be run with:
 ```sh 
 python3 ./Server/Server.py
 # make sure the appropriate packages are installed with pip.
 ```
- Crypto.py contains all of the methods necessary for generating the RSA key pairs, creating and verifying certificates, &amp; generating an AES key. It also contains all relevant methods for encrypting/decrypting data with RSA and AES, as welll as writing the keys and certs to a file. It is imported and the functions are used by the respective files behind the Client & Server behaviors.

### Behaviors
1. The server binds a listener to a port and listens for incoming connections.
2. The client connects to the server.
3. The client sends a SSL3_MT_CLIENT_HELLO message, in addition to the client CA certificate and its public key.
4. The server receives the message, and verifies the client certificate with the client and CA public keys. If the certificate cannot be verified, the connection is dropped. Otherwise, the server responds with SSL3_MT_SERVER_HELLO + the server CA certificate & public key.
5. The client verifies the server certificate with the server and CA public keys, and drops the connection if the verification fails. Otherwise, the client generates an AES key, encrypts it with the server's public key, and responds with SSL3_MT_CLIENT_KEY_EXCHANGE + the encrypted AES key.
6. The server decrypts the encrypted AES key with its private key, stores it in a variable, and encrypts it again with the client's public key. It then responds with SSL3_MT_SERVER_KEY_EXCHANGE + the encrypted AES key.
7. The client decrypts the encrypted AES key with its private key and compares it to the original generated AES key. If the two are different, then the security of the communication is not stable and the connection is dropped. Otherwise, the client knows that the AES key that the server has is the same key that the client generated. 
8. The client prompts the user to provide a target filepath, encrypts a REQUEST message and the provided path with the AES key, and sends it to the server.
9. The server decrypts the received message, isolates the path, pulls bytes from a file with the provided path, creates a signature by signing the bytes with the server's private RSA key, and sends a RESPONSE message plus the file bytes &amp; signature (all encrypted together with the AES key). 
10. The client decrypts the received message, verifies the signature with the file bytes & server public key, and writes the bytes to a file in the received/ directory if verfication is successful.
11. The connection is closed.


### Installation
```sh
pip install rsa
pip install pyaes
```

### Initialization
```sh
#Server
python3 ./Server/Server.py

#Client
python3 ./Client/Client.py
```

### Notes
- This code was successfully tested on two different CentOS machines managed by my university. Due to certain organizational restrictions, port 4041 was used in this project. 
- This code does not follow the accepted TLS communication structure, as it is just an approximation of what actually goes on behind the scenes. Most notably, the message names (i.e. those starting with "SSL_MT" are treated as string bytes instead of their represented values, and the message contents are combined & separated by a delimiter (as opposed to defining length bytes). For accurate TLS protocol information, please see this resource: https://www.ibm.com/docs/en/ztpf/1.1.0.15?topic=sessions-ssl-record-format