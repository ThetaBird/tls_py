import rsa
import os
import pyaes

caPubKeyPath = "./CA/capub.key"
caPriKeyPath = "./CA/capri.key"
caPriKey = caPubKey = ""

#GET rsa.AbstractKey FROM A PATH CONTAINING PEM-FORMATTED RSA KEY BYTES
def getKey(path, t):
    keyFile = open(path,"rb")
    keyBytes = keyFile.read()
    if(t == "pri"):
        return rsa.PrivateKey.load_pkcs1(keyBytes)
    return rsa.PublicKey.load_pkcs1(keyBytes)

#GET rsa.PublicKey FROM PEM-FORMATTED RSA PUBLIC KEY BYTES
def getKeyFromBytes(b):
    return rsa.PublicKey.load_pkcs1(b)

#GET SERVER/CLIENT CA CERTIFICATE FROM CA PATH
def getCert(path):
    certFile = open(path,"rb")
    certBytes = certFile.read()
    return certBytes

#WRITE RSA KEY TO FILE IN PEM FORMAT
def writeKey(path, key):
    keyFile = open(path,"wb")
    keyFile.write(key.save_pkcs1())

#WRITE CA CERTIFICATE TO FILE
def writeCert(path, cert):
    certFile = open(path,"wb")
    certFile.write(cert)

#INITIALIZE CLIENT/SERVER CERTIFICATES FOR INITIAL USE
def init_CA_Cert(pubKey, certPath):
    global caPriKey

    cert = rsa.sign(pubKey.save_pkcs1(), caPriKey, 'SHA-1')
    writeCert(certPath, cert)
    return cert

#INITIALIZE CA PRIVATE + PUBLIC RSA KEYS IN GLOBAL VARIABLES FOR FUTURE ACCESS
def init_CA():
    global caPriKeyPath, caPubKeyPath
    global caPriKey, caPubKey

    if(caPriKey != "" and caPubKey != ""):
        return
    
    keysExist = os.path.exists(caPubKeyPath) and os.path.exists(caPriKeyPath)
    if(keysExist):
        caPubKey = getKey(caPubKeyPath,"pub")
        caPriKey = getKey(caPriKeyPath,"pri")
    else:
        (caPubKey, caPriKey) = rsa.newkeys(512, poolsize=1)
        writeKey(caPubKeyPath,caPubKey)
        writeKey(caPriKeyPath,caPriKey)

#INITIALIZE CLIENT/SERVER RSA KEYS & CA CERTIFICATES FOR INITIAL USE
def init_RSA(pubKeyPath, priKeyPath, certPath):
    keysExist = os.path.exists(pubKeyPath) and os.path.exists(priKeyPath) and os.path.exists(certPath)

    if(keysExist):
        pubKey = getKey(pubKeyPath,"pub")
        priKey = getKey(priKeyPath,"pri")
        cert = getCert(certPath)
    else:
        (pubKey, priKey) = rsa.newkeys(512, poolsize=1)
        cert = init_CA_Cert(pubKey, certPath)
        writeKey(pubKeyPath,pubKey)
        writeKey(priKeyPath,priKey)

    return (pubKey, priKey, cert)

init_CA()

#VERIFY SERVER/CLIENT CERTIFICATES AGAINST A PUBLIC KEY
def verify_Certificate(cert, pubKeyStr):
    global caPubKey
    try:
        algo = rsa.verify(pubKeyStr, cert, caPubKey)
        if(algo != "SHA-1"): 
            return False 
        return True
    except rsa.VerificationError:
        return False

#CREATE AES KEY FOR ENCRYPTION
def generate_aes_key(pubKey):
    aes_key = rsa.randnum.read_random_bits(128)
    encrypted_aes_key = rsa.encrypt(aes_key, pubKey)
    return (aes_key, encrypted_aes_key)

#DECRYPT RSA-ENCRYPTED BYTES WITH RSA PRIVATE KEY
def rsa_decrypt(content, priKey):
    return rsa.decrypt(content, priKey)

#ENCRYPT BYTES WITH RSA PUBLIC KEY
def rsa_encrypt(content, pubKey):
    return rsa.encrypt(content, pubKey)

#ENCRYPT BYTES WITH AES KEY
def aes_encrypt(content, key):
    aes = pyaes.AESModeOfOperationCTR(key)
    return aes.encrypt(content)

#DECRYPT AES-ENCRYPTED BYTES WITH AES KEY
def aes_decrypt(content, key):
    aes = pyaes.AESModeOfOperationCTR(key)
    return aes.decrypt(content)

#GET FILE BYTES FROM A PATH & SIGN WITH RSA PRIVATE KEY
def file_signature(path, priKey):
    targetFile = open(path,"rb")
    targetBytes = targetFile.read()
    signature = rsa.sign(targetBytes, priKey, "SHA-1")
    return (targetBytes,signature)

#VERIFY BYTES AGAINST A SIGNATURE
def verify_signature(msg, signature, pubKey):
    try:
        algo = rsa.verify(msg, signature, pubKey)
        if(algo != "SHA-1"): 
            return False 
        return True
    except rsa.VerificationError:
        return False