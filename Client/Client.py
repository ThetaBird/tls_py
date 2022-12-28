from socket import *
import os
import sys

sys.path.append('..')
from FileServer.Crypto import *
from FileServer.Protocol import * 

pubKey = priKey = clCert = ""
cd = os.path.dirname(__file__)

clCertPath = cd + "/../CA/client.cert"
pubKeyPath = cd + "/pub.key"
priKeyPath = cd + "/pri.key"
receivedPath = cd + "/received/"

#INITIALIZE CLIENT'S PUBLIC & PRIVATE RSA KEYS + CA CLIENT CERTIFICATE
(pubKey, priKey, clCert) = init_RSA(pubKeyPath, priKeyPath, clCertPath)


HOST = input('Server Address: ')
PORT = 4041

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((HOST, PORT))
pubKeyBytes = pubKey.save_pkcs1()

def writeFile(path, fileBytes):
    keyFile = open(receivedPath + path,"wb")
    keyFile.write(fileBytes)

def main():
    #SEND SSL CLIENT HELLO, WITH CLIENT CA CERTIFICATE & CLIENT PUBLIC RSA KEY
    clientSocket.send(b"SSL3_MT_CLIENT_HELLO" + MSG_SPLIT + clCert + MSG_SPLIT + pubKeyBytes)
    
    #RECEIVE SSL SERVER HELLO RESPONSE WITH SERVER CA CERTIFICATE & SERVER PUBLIC RSA KEY
    data = clientSocket.recv(1024)
    msg = data.split(MSG_SPLIT)
    command = msg[0]
    if(not command == b'SSL3_MT_SERVER_HELLO'):
        clientSocket.close()
        return
    serverCert = msg[1]
    serverKeyBytes = msg[2]
    #VERIFY SERVER CERTIFICATE W/ PUBLIC KEY W/ HELP OF CA
    hashAlgo = verify_Certificate(serverCert, serverKeyBytes)
    if(not hashAlgo):
        clientSocket.close()
        return
    #GET rsa.PublicKey OBJECT FROM RSA PUBLIC KEY BYTES SENT FROM SERVER
    serverKey = getKeyFromBytes(serverKeyBytes)
    #CREATE AES KEY FOR FUTURE ENCRYPTION
    (aes_key, encrypted_aes_key) = generate_aes_key(serverKey)

    #SEND AES KEY (ENCRYPTED WITH SERVER PUBLIC KEY) FOR SERVER
    clientSocket.send(b"SSL3_MT_CLIENT_KEY_EXCHANGE" + MSG_SPLIT + encrypted_aes_key)
    
    #RECEIVE THE SAME AES KEY ENCRYPTED WITH CLIENT PUBLIC KEY (CONFIRMATION OF AES)
    data = clientSocket.recv(1024)
    msg = data.split(MSG_SPLIT)
    command = msg[0]
    if(not command == b'SSL3_MT_SERVER_KEY_EXCHANGE'):
        clientSocket.close()
        return
    serverAesEncryptedKey = msg[1]
    #DECRYPT ENCRYPTED AES KEY & COMPARE IF THE TWO MATCH
    serverAesKey = rsa_decrypt(serverAesEncryptedKey, priKey)

    if(not aes_key == serverAesKey):
        clientSocket.close()

    #MAKE A CLIENT REQUEST FOR A FILE FROM THE SERVER
    path = input('File path: ')
    message = b"REQUEST" + MSG_SPLIT + path.encode()
    encryptedMessage = aes_encrypt(message, aes_key)
    clientSocket.send(encryptedMessage)

    #RECEIVE AN ENCRYPTED SERVER RESPONSE W/ FILE BYTES & RSA SIGNATURE
    data = clientSocket.recv(1024)
    data = aes_decrypt(data, aes_key)
        
    msg = data.split(MSG_SPLIT)
    command = msg[0]
    print(command)
    if(not command == b'RESPONSE'):
        clientSocket.close()
        return

    #VERIFY THE RSA SIGNATURE W/ THE FILE BYTES TO MAKE SURE NO TAMERING OCCURED
    fileBytes = msg[1]
    signature = msg[2]

    verified = verify_signature(fileBytes, signature, serverKey)
    if(not verified):
        print("FAIL")
        clientSocket.close()
        return

    #WRITE FILE BYTES TO FILE IN CLIENT DIRECTORY
    writeFile(path, fileBytes)
    clientSocket.close()
    return
    

main()