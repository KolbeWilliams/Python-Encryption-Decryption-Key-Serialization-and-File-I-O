# Develop a program that performs the following:

# AES encryption with either CBC or CTR cipher block mode on user input of a plaintext message.
# Asymmetric encryption utilizing RSA on the symmetric key along with the IV or nonce.
# Write the ciphertext and the encrypted key to either a txt file or a csv file.
# Read the ciphertext and encrypted key from the stored file.
# Asymmetric decryption of the symmetric key.
# Symmetric decryption of the plaintext.
# Displays the plaintext message as string to the console.
# Have the program be able to do either CBC and CTR cipher block mode
# Have the program be able to write various file types pickle, txt, or csv. Any amount of additional file types greater than one.
# Have the program utilize a delimiter to separate the key from the IV/nonce rather than splicing.
# Have the program perform key serialization of the private key to and from file
import sys
import os
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.padding import PKCS7

def AES_Encryption_CBC(plaintext):
    plaintext = plaintext.encode()
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return (key, iv, ciphertext)

def AES_Encryption_CTR(plaintext):
    plaintext = plaintext.encode()
    key = os.urandom(32)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (key, nonce, ciphertext)

def Symmetric_Decrypt_CBC(ciphertext, decrypted_symmetric_key, iv):
    cipher = Cipher(algorithms.AES(decrypted_symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(plaintext) + unpadder.finalize()
    return plaintext.decode()

def Symmetric_Decrypt_CTR(ciphertext, decrypted_symmetric_key, nonce):
    cipher = Cipher(algorithms.AES(decrypted_symmetric_key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

def RSA_Encryption(symmetric_key, iv_or_nonce, receiver_public_key, delimiter = b' ::: '):
    symmetric_key_ivNonce = symmetric_key + delimiter + iv_or_nonce
    encrypted_symmetric_key = receiver_public_key.encrypt(symmetric_key_ivNonce,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))
    return encrypted_symmetric_key

def Asymmetric_Decrypt(receiver_private_key, encrypted_symmetric_key):
    decrypted_key_ivNonce = receiver_private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf = padding.MGF1(algorithm = hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None))
    return decrypted_key_ivNonce

def fileIO(ciphertext, encrypted_symmetric_key, extension, delimiter = b' ::: '):
    with open(f'my_file.{extension}', 'wb') as file:
        file.write(ciphertext)
        file.write(delimiter)
        file.write(encrypted_symmetric_key)

    with open(f'my_file.{extension}', 'rb') as file:
        encrypted_contents = file.read()
        file_ciphertext, file_encrypted_key = encrypted_contents.split(delimiter)

    print(f'\nThe ciphertext that was written to the {extension} file:\n{file_ciphertext}')
    print(f'\nThe encrypted symmetric key that was written to the {extension} file:\n{file_encrypted_key}')

def serializePrivateKey(receiver_private_key, password):
    pem = receiver_private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.BestAvailableEncryption(password))

    with open('serialization.pem', 'wb') as pem_file:
        pem_file.write(pem)

def deserializePrivateKey(password):
    with open('serialization.pem', 'rb') as pem_file:
        contents = pem_file.read()
    return serialization.load_pem_private_key(contents, password = password)

def main():
    #Get user input
    message = input('Enter a message: ')
    AES_choice = ''
    file_choice = ''
    while AES_choice not in ['CBC', 'CTR']:
        AES_choice = input('Do you want to use CBC or CTR of the AES encryption: ').strip().upper()
    while file_choice not in ['txt', 'csv', 'pickle']:
        file_choice = input('Enter file extension to write to ("txt", "csv", or "pickle"): ').strip().lower()

    #Generate keys
    receiver_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,)
    receiver_public_key = receiver_private_key.public_key()

    #Serialize private key to PEM file
    password = getpass('Enter a password for the serialized private key: ').encode()
    serializePrivateKey(receiver_private_key, password)
    
    #Perform encryption of message
    if(AES_choice == 'CBC'):
        symmetric_key, iv, ciphertext = AES_Encryption_CBC(message)
    elif(AES_choice == 'CTR'):
        symmetric_key, nonce, ciphertext = AES_Encryption_CTR(message)

    #Perform encryption of symmetric key
    encrypted_symmetric_key = RSA_Encryption(symmetric_key, (iv if AES_choice == 'CBC' else nonce), receiver_public_key)
    
    #Read and write to a file of user choice
    fileIO(ciphertext, encrypted_symmetric_key, file_choice)
    
    #Deserialize private key
    password = getpass('\nEnter the password to decrypt the serialized private key: ').encode()
    receiver_private_key = deserializePrivateKey(password)

    #Decrypt symmetric key and message
    decrypted_symmetric_key_ivNonce = Asymmetric_Decrypt(receiver_private_key, encrypted_symmetric_key)
    decrypted_symmetric_key, iv_or_nonce = decrypted_symmetric_key_ivNonce.split(b' ::: ')
    if(AES_choice == 'CBC'):
        plaintext = Symmetric_Decrypt_CBC(ciphertext, decrypted_symmetric_key, iv)
    elif(AES_choice == 'CTR'):
        plaintext = Symmetric_Decrypt_CTR(ciphertext, decrypted_symmetric_key, nonce)
    print(f'\nThe plaintext message is: {plaintext}')
    
if __name__ == '__main__':
    main()