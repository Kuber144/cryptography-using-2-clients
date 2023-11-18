# cryptography-using-2-clients

For further details contact the github user: https://github.com/Kuber144 or send a mail at kuberjain144@gmail.com

The code is written using cpp and is using the CryptoPP library. \
It was used to solve the following problem: - \
Write a program in your preferred language to achieve the following: There should be
two clients each on different computers (say, client1 and client2). Any client can send the
starting message. \
The first message will be a communication request from the first client1.
Upon receiving the request client2 will send a message to denote the name of the
encryption algo to be used. \
Both clients will agree on a symmetric key using the deffie Hellman algorithm.
Upon agreement, any client can ask for a file from another client and the other client has
to share it encrypted. \
On receiving the file the client will show the contents of the file after decrypting it.

This solution contains a server and a 2 clients. \
The same code used in client.cpp can be used for both the clients. \
To compile the files the following was used: -\
g++ -g -O2 -I. -I/usr/include/cryptopp dh-param.cpp -o dh-param.exe -lcryptopp -lpthread

To run the codes assuming that the compiled files are server, client1, client2: -

First run the server using ./server {port_number} \
Then run any of the clients using ./client1 {username_1} {port_number} \
Then run the second client using ./client2 {username_2} {port_number}

This code has implemented Blowfish, AES and DES algorithm and the client can chosse whichever algorithm they can use.


## Introduction

This project aims to demonstrate a solution to the following problem: Write a program in your preferred language to achieve the following: There should be two clients each on different computers (say, client1 and client2). Any client can send the starting message. The first message will be a communication request from the first client1. Upon receiving the request client2 will send a message to denote the name of the encryption algo to be used. Both clients will agree on a symmetric key using the Diffie Hellman algorithm. Upon agreement, any client can ask for a file from another client and the other client has to share it encrypted. On receiving the file the client will show the contents of the file after decrypting it.

To ensure that the problem is solved efficiently, two clients are used running on separate computers. These clients initiate communication by employing a request-response mechanism, where any client can ask for a file and the other client responds back with the contents of the file IF available otherwise responding with an appropriate response.

This system is designed to showcase the following key functionalities:
* Key Exchange: Both clients establish a shared symmetric key using the Diffie-Hellman key exchange protocol, ensuring that only they possess the means to decrypt the exchanged files.
* Encrypted File Sharing: Once a shared key is established, either client can request a file from the other. The requested file will be shared securely by encrypting it with the shared key.
* Secure Decryption: Upon receiving an encrypted file, the recipient client will decrypt it using the shared key and display the contents of the file.
By demonstrating the aforementioned functionalities, this project showcases a secure and effective means of data exchange between two clients.

## Project Overview
The solution provided for this question mentioned in the introduction is written in the language c++. This solution contains 2 clients which communicate with each other through the help of a server. The server's only functionality is that it allows the clients to send messages to each other and it serves no other purpose. The same code provided for the client can be used for both the clients. After the first client is connected, it starts listening and waiting for the second client to connect. As soon as the second client connects, they establish a secure connection by doing a diffie hellman key exchange algorithm. Then the client can choose which cryptography algorithm they use for file exchange between each other. As the other objective of our task was to use block cipher, we have implemented the main block cipher algorithms i.e. AES, DES and Blowfish algorithm. The connection between the clients and message exchange using socket programming. After the connection is established, the values for key exchange and all of the implementation of the cryptography algorithms are done using one of the c++ library for cryptography named CryptoPP.

The implementation of AES, DES and Blowfish is using the CryptoPP library.
The Advanced Encryption Standard, or AES, is a NIST approved block cipher specified in FIPS 197, Advanced Encryption Standard (AES). When using AES, one typically specifies a mode of operation and optionally a padding scheme. AES provides confidentiality only using most modes of operation such as ECB and CBC. The Advanced Encryption Standard (AES) is a widely adopted symmetric block cipher. AES encryption involves a key expansion step, an initial round where the plaintext is XORed with the first round key, several rounds with operations such as SubBytes (byte substitution), ShiftRows (row shifts), MixColumns (column mixing), and AddRoundKey (XORing with round keys), and a final round without MixColumns. After these iterations, the resulting state represents the ciphertext. AES is used to provide data confidentiality, and its security stems from its strong key-dependent operations. The number of rounds and key length determine the level of security, with 128-bit, 192-bit, and 256-bit key sizes supported. It is vital to use AES in conjunction with block cipher modes of operation and padding schemes to achieve comprehensive data encryption.

Similarly DES is applied and is a block cipher algorithm and applied using the CryptoPP algorithm. The Data Encryption Standard (DES) is a symmetric key block cipher used for data encryption and decryption. DES operates on 64-bit blocks of data and uses a 56-bit key. The algorithm involves an initial permutation of the plaintext, followed by 16 rounds of key-dependent operations that include data substitution, permutation, and bitwise operations. In each round, a 48-bit subkey is derived from the original 56-bit key, and this subkey is used to modify the data. These operations include expansion, substitution (using S-boxes), permutation, and XORing with the subkey. After the 16 rounds, a final permutation is applied to the data, producing the ciphertext. DES has historically been a widely used encryption standard, but its 56-bit key length is considered too short for modern security needs. Therefore, it is often used in Triple DES (3DES) mode, which applies the DES algorithm three times in succession with different keys for enhanced security. DES encryption provides data confidentiality, but its security level is limited due to advances in computing power, making it vulnerable to brute-force attacks.


The Blowfish algorithm, designed by Bruce Schneier, is a versatile symmetric key block cipher known for its simplicity, speed, and adaptability. Operating on variable-length blocks of data and keys ranging from 32 to 448 bits, Blowfish consists of two main phases: key expansion and data encryption. Key expansion involves converting the variable-length key into a fixed set of subkeys through iterative pseudorandom functions. In the data encryption phase, 64-bit data blocks are divided into two 32-bit halves, and a series of substitution, permutation, and XOR operations are applied in a Feistel network structure. This process can include variable rounds, making Blowfish efficient for various applications.

## Working Methodology

To compile the files the following was used: -
g++ -g -O2 -I. -I/usr/include/cryptopp dh-param.cpp -o dh-param.exe -lcryptopp -lpthread
To run the codes assuming that the compiled files are server, client1, client2: -
First run the server using ./server {port_number}
Then run any of the clients using ./client1 {username_1} {port_number}
Then run the second client using ./client2 {username_2} {port_number}

Please ensure that the ip address is correctly configured in the codes and correctly compiled. The ip address should be the same as the server for the clients. It depends on the network you are connected to. 
Port numbers must be the same for the client and server to establish a connection because they serve as a common endpoint identifier for routing and communication agreement.

After the server is run and then the first client is run, it will listen for a response from the server and will receive the value 1 as it is the first client. Corresponding to this, it will go to the code block designated for the first client. It will now wait for the next client to connect. As the next client connects, it will receive 2 from the server and go to the designated block for starting the diffie hellman key exchange algorithm. Now the client generates the value of p,a,g,b for the key exchange and the key exchange occurs. To ensure that no synchronization error occurs, we have used while loops in appropriate places to ensure that the code does not move forward until and unless the previous process is completed. The variable “cnt” ensures this as we increment it only when the process is finished and the while loops that are placed in the appropriate places are exited when needed.

All of the keys are generated at run time and randomly by giving a different seed everytime by the following line block: -

     AutoSeededRandomPool rnd;
    unsigned int bits = 256;
    SecByteBlock scratch((bits+7)/8);
    SecByteBlock gene((8+7)/8);
    AutoSeededRandomPool rng;
    rng.GenerateBlock(scratch,scratch.size());
    p.Decode(scratch,scratch.size());
    rng.GenerateBlock(gene,gene.size());
    a.Decode(gene,gene.size());
    rng.GenerateBlock(scratch,scratch.size());
    g.Decode(scratch,scratch.size());
    Integer x = ModularExponentiation(g, a, p);
It starts by initializing random number generators (AutoSeededRandomPool and rng) and allocating memory for byte blocks to hold cryptographic data. Random values are generated, decoded, and assigned to variables p, a, and g. Finally, the code computes the shared secret key x using modular exponentiation with g, a, and p. 
Now that the key is exchanged and the private key is generated, the client chooses which algorithm to choose for file exchange from a choice of AES, DES and Blowfish algorithm. They enter the corresponding number for choosing the algorithm and the other client is simultaneously notified which algorithm did the other client choose for file exchange. 

Now that all of the parameters are set, any client can ask for a file in any order and it is not necessary that other client needs to send a message first. To ask for a file, simply type in the file name you want (example: hello.txt), it will be sent to the other client and if it exists, then it will be encrypted using the key and algorithm previously decided and sent. Upon receiving, it will be decrypted and stored in the file named “result.txt”. Again to ensure that no synchronization error occurs, a flag by the name of “isrequest” is used. If the client requested the file, then the value of this flag is 1 otherwise it is 0. Thus by using this flag, we can distinguish between whether the message received from the other client was a file request or the response to the client's request as “isrequest” will be 1 or 0 depending on if the client has requested a file or not. Now, what if the client requests a file that does not exist on the side of other client. Then an appropriate message is sent back to the client and it is then appropriately displayed on the terminal. 

The AES algorithm is done in the function: ECBMode_Encrypt, ECBMode_Decrypt: -

This code performs AES encryption and decryption in Electronic Codebook (ECB) mode. For encryption, it takes a plaintext string text, an AES key key, and its size as input. It sets up an AES encryption object, e, with the provided key, and then encrypts the input text using ECB mode. The encrypted result is stored in the cipher string. For decryption, it takes the ciphertext cipher, the same AES key, and its size. It sets up an AES decryption object, d, with the key, and then decrypts the ciphertext to obtain the original plaintext, which is stored in the recovered string. 

The DES algorithm is done in the function: CBCMode_Encrypt, CBCMode_Decrypt: -

This code performs DES encryption and decryption in Cipher Block Chaining (CBC) mode. For encryption, it takes a plaintext string text, a DES key key, and its size as input. It generates a random Initialization Vector (IV), which is essential for CBC mode. The IV is prepended to the ciphertext to ensure secure encryption. The code sets up a CBC mode encryption object, e, using the provided key and IV, and encrypts the input text. The resulting ciphertext, including the IV, is stored in the cipher string.

For decryption, it takes the ciphertext with IV ciphertextWithIV, the same DES key, and its size. The code extracts the IV from the ciphertext and uses it to set up a CBC mode decryption object, d, with the key and IV. It then processes the ciphertext (excluding the IV) and decrypts it to obtain the original plaintext, which is stored in the recovered string.

The Blowfish algorithm is done in the function: Blowfish_Encrypt, Blowfish_Decrypt: -

This code performs Blowfish encryption and decryption in Cipher Block Chaining (CBC) mode. For encryption, it takes a plaintext string text, a Blowfish key key, and its size as input. A random Initialization Vector (IV) is generated. Similar to DES and AES, the IV is prepended to the ciphertext to ensure secure encryption. The code sets up a CBC mode encryption object, e, using the provided key and IV, and then encrypts the input text. The resulting ciphertext, including the IV, is stored in the cipher string.

For decryption, the code takes the ciphertext with IV ciphertextWithIV, the same Blowfish key, and its size. It extracts the IV from the ciphertext and uses it to set up a CBC mode decryption object, d, with the key and IV. The code processes the ciphertext (excluding the IV) and decrypts it to obtain the original plaintext, which is stored in the recovered string.

Similar to AES, DES encryption in CBC mode ensures data confidentiality. However, it's important to note that DES is considered less secure than AES due to its shorter key length, making it more vulnerable to brute force attacks.

ECB mode, while straightforward, lacks security in many practical scenarios, as it does not provide semantic security and identical blocks of plaintext produce identical blocks of ciphertext, making it susceptible to certain attacks. It's often recommended to use more secure modes like Cipher Block Chaining (CBC) with AES.

Blowfish encryption in CBC mode ensures data confidentiality, similar to DES and AES. However, it's important to note that AES is a more widely adopted and recommended encryption algorithm due to its stronger security properties. Blowfish is considered less secure, and its use is not recommended for new applications that require high security.
```
Integer a,p,b,g,x,y,private_key;
int isrequest=0,cnt=0,algoty=0;
const int IV_SIZE = DES_EDE3::BLOCKSIZE;
const int IV_SIZE2 = CryptoPP::Blowfish::BLOCKSIZE;
```
These are all the globally declared parameters in the code.
The constants define the size of the Initialization Vector (IV) for DES and Blowfish encryption, with IV_SIZE representing the size for DES (8 bytes) and IV_SIZE2 for Blowfish (8 bytes) in the Crypto++ library.


For further details contact the github user: https://github.com/Kuber144 or send a mail at kuberjain144@gmail.com
