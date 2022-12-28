from socket import *
import os
import sys

sys.path.append('..')
from FileServer.Crypto import *
from FileServer.Protocol import *

pubKey = priKey = slCert = ""
cd = os.path.dirname(__file__)

slCertPath = cd + "/../CA/server.cert"
pubKeyPath = cd + "/pub.key"
priKeyPath = cd + "/pri.key"
publicPath = cd + "/public/"

#INITIALIZE CLIENT'S PUBLIC & PRIVATE RSA KEYS + CA CLIENT CERTIFICATE
(pubKey, priKey, slCert) = init_RSA(pubKeyPath, priKeyPath, slCertPath)

serverSocket = socket(AF_INET, SOCK_STREAM)
# Prepare a server socket
HOST = "127.0.0.1"
PORT = 4041
serverSocket.bind(("", PORT))
serverSocket.listen()

while True:
    # Establish the connection
    print('Ready to serve...')
    connectionSocket, addr = serverSocket.accept()  
    try:
        #WAIT FOR SSL CLIENT HELLO + CA CLIENT CERTIFICATE & CLIENT PUBLIC RSA KEY
        data = connectionSocket.recv(1024)
        msg = data.split(MSG_SPLIT)
        command = msg[0]
        if(not command == b'SSL3_MT_CLIENT_HELLO'):
            connectionSocket.close()
            break

        #VERIFY CLIENT CA CERTIFICATE AGAINST CLIENT PUBLIC KEY
        clientCert = msg[1]
        clientKeyBytes = msg[2]
        hashAlgo = verify_Certificate(clientCert, clientKeyBytes)
        if(not hashAlgo):
            connectionSocket.close()
            break
        #GET CLIENT rsa.PublicKey OBJECT FROM SENT BYTES
        clientKey = getKeyFromBytes(clientKeyBytes)

        #SEND SSL SERVER HELLO W/ CA SERVER CERTIFICATE + SERVER PUBLIC RSA KEY
        connectionSocket.send(b"SSL3_MT_SERVER_HELLO" + MSG_SPLIT + slCert + MSG_SPLIT + pubKey.save_pkcs1())

        #RECEIVE AES KEY FROM CLIENT ENCRYPTED WITH SERVER PUBLIC KEY
        data = connectionSocket.recv(1024)
        msg = data.split(MSG_SPLIT)
        command = msg[0]
        if(not command == b'SSL3_MT_CLIENT_KEY_EXCHANGE'):
            connectionSocket.close()
            break
        #DECRYPT ENCRYPTED AES KEY W/ SERVER PRIVATE RSA KEY
        clientAesEncryptedKey = msg[1]
        aesKey = rsa_decrypt(clientAesEncryptedKey, priKey)
     
        #ENCRYPT AES KEY WITH CLIENT PUBLIC KEY & SEND IT TO CLIENT FOR CONFIRMATION
        serverAesKey = rsa_encrypt(aesKey, clientKey)
        connectionSocket.send(b"SSL3_MT_SERVER_KEY_EXCHANGE" + MSG_SPLIT + serverAesKey)

        #RECEIVE FILE REQUEST FROM CLIENT W/ PATH
        data = connectionSocket.recv(1024)
        data = aes_decrypt(data, aesKey)
        msg = data.split(MSG_SPLIT)
        command = msg[0]

        if(not command == b'REQUEST'):
            connectionSocket.close()
            break
        path = msg[1].decode()

        #PULL BYTES FROM FILE & SIGN W/ SERVER PRIVATE RSA KEY
        (targetBytes, fileSignature) = file_signature(publicPath + path, priKey)
        #CREATE A MESSAGE CONTAINING THE RESPONSE FILE BYTES + SIGNATURE, ENCRYPT WITH AGREED AES KEY, & SEND TO CLIENT
        message = b"RESPONSE" + MSG_SPLIT + targetBytes + MSG_SPLIT + fileSignature
        encryptedMessage = aes_encrypt(message, aesKey)
        connectionSocket.send(encryptedMessage)

        #CLOSE CONNECTION
        connectionSocket.close()
    except IOError:
        connectionSocket.close()

    serverSocket.close()
    sys.exit() # Terminate the program after sending
