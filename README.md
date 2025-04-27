# Python Encryption, Decryption, Key Serialization, and File I/O
# Secure Message Encryption Program

This Python program provides a secure way to encrypt and decrypt messages using a combination of symmetric and asymmetric encryption techniques.

## Features

* **AES Encryption:** Encrypts user-provided plaintext messages using the Advanced Encryption Standard (AES) algorithm.
* **Cipher Block Mode Selection:** Offers the choice between two common AES cipher block modes:
    * **Cipher Block Chaining (CBC):** Each block of plaintext is XORed with the previous ciphertext block before being encrypted. Requires an Initialization Vector (IV).
    * **Counter (CTR):** Each block of plaintext is XORed with an output block of a counter. Requires a nonce (number used once).
* **RSA Asymmetric Encryption:** Protects the confidentiality of the AES symmetric key and the IV/nonce by encrypting them using the RSA asymmetric encryption algorithm.
* **File Storage:** Writes the resulting ciphertext and the RSA-encrypted symmetric key (along with the IV/nonce) to a user-specified file. Supports multiple file types:
    * Text files (`.txt`)
    * Comma Separated Value files (`.csv`)
    * Pickle files (`.pickle`)
* **File Reading:** Reads the ciphertext and encrypted key from the previously stored file.
* **RSA Asymmetric Decryption:** Decrypts the symmetric AES key and the IV/nonce using the corresponding RSA private key.
* **AES Symmetric Decryption:** Decrypts the original ciphertext using the recovered AES symmetric key and IV/nonce to retrieve the plaintext message.
* **Plaintext Display:** Prints the decrypted plaintext message to the console.
* **Key/IV/Nonce Separation:** Utilizes a distinct delimiter (`:::`) to separate the encrypted symmetric key from the IV/nonce within the stored file, ensuring reliable retrieval.
* **Private Key Serialization:** Implements secure storage of the RSA private key by serializing it to a file using Password-based Encryption (PBE).
* **Private Key Deserialization:** Allows loading the RSA private key from the serialized file using the correct password.

## Prerequisites

* Python 3.x
* The `cryptography` library. Install it using pip:
    ```bash
    pip install cryptography
    ```

## How to Run the Program

1.  Save the provided Python code as a `.py` file (e.g., `Cryptography.py`).
2.  Open a terminal or command prompt.
3.  Navigate to the directory where you saved the file.
4.  Run the script using the Python interpreter:
    ```bash
    python Cryptography.py
    ```
5.  The program will prompt you to:
    * Enter the message you want to encrypt.
    * Choose between `CBC` and `CTR` mode for AES encryption.
    * Enter the file extension (`txt`, `csv`, or `pickle`) to save the encrypted data.
    * Enter a password to protect the serialized private key.
    * Enter the same password again to decrypt the serialized private key during the decryption process.
6.  After encryption, the program will display the ciphertext and encrypted key that were written to the chosen file.
7.  It will then proceed with decryption, prompting for the private key password, and finally display the original plaintext message.

## Important Security Considerations

* **Password Security:** The security of the serialized private key heavily relies on the strength and secrecy of the password you choose. Use a strong, unique password and keep it confidential.
* **Key Management:** This program demonstrates the fundamental principles of encryption. In real-world applications, robust key management systems are crucial for securely generating, storing, distributing, and revoking cryptographic keys.
* **File Storage:** The encrypted data is stored locally in a file. Ensure appropriate file system permissions are set to protect this file from unauthorized access.
* **Algorithm Choices:** The algorithms and modes used in this program are generally considered secure. However, cryptographic best practices evolve, so staying informed about current recommendations is essential for production systems.
* **Error Handling:** This is a basic implementation and might not include comprehensive error handling. Robust applications should include mechanisms to gracefully handle potential issues like incorrect passwords or file reading errors.
