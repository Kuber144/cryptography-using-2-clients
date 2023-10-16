# cryptography-using-2-clients

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

For further details contact the github user: https://github.com/Kuber144 or send a mail at kuberjain144@gmail.com
