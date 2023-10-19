#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <iostream>
#include <chrono>
#include <unistd.h>
#include <cryptopp/dh.h>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/des.h>
using std::cerr;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <sstream>
using std::istringstream;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "integer.h"
using CryptoPP::Integer;

#include "nbtheory.h"
using CryptoPP::ModularExponentiation;

#include "dh.h"
using CryptoPP::DH;

#include "secblock.h"
using CryptoPP::SecByteBlock;
#include "cryptopp/des.h"
using CryptoPP::DES_EDE3;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
#include <cryptopp/blowfish.h>
#include "cryptopp/filters.h"
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
int cnt = 0;
Integer a, p, b, g, x, y, private_key;
int isrequest = 0;
int algoty = 0;
const int IV_SIZE = DES_EDE3::BLOCKSIZE;
const int IV_SIZE2 = CryptoPP::Blowfish::BLOCKSIZE;
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void splitString(const char *input, char *username, char *filename)
{
    int i = 0;
    int inputLen = strlen(input);
    while (i < inputLen && input[i] != '-' && input[i + 1] != '>')
    {
        i++;
    }
    if (i < inputLen)
    {
        size_t usernameLen = i;
        size_t filenameLen = inputLen - i - 2;
        strncpy(username, input, usernameLen);
        username[usernameLen] = '\0';
        strncpy(filename, input + i + 2, filenameLen);
        filename[filenameLen] = '\0';
    }
    else
    {
        strcpy(username, "");
        strcpy(filename, "");
    }
}
string Blowfish_Encrypt(string text, byte key[], int keySize)
{
    string cipher = "";

    AutoSeededRandomPool rnd;
    byte iv[IV_SIZE2];
    rnd.GenerateBlock(iv, sizeof(iv));

    try
    {
        cipher = string(reinterpret_cast<const char *>(iv), IV_SIZE2);

        CBC_Mode<CryptoPP::Blowfish>::Encryption e;
        e.SetKeyWithIV(key, keySize, iv);

        StringSource(text, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    return cipher;
}

string Blowfish_Decrypt(string ciphertextWithIV, byte key[], int keySize)
{
    string recovered = "";

    byte iv[IV_SIZE2];
    memcpy(iv, ciphertextWithIV.c_str(), IV_SIZE2);

    try
    {
        CBC_Mode<CryptoPP::Blowfish>::Decryption d;
        d.SetKeyWithIV(key, keySize, iv);

        StringSource(ciphertextWithIV.substr(IV_SIZE2), true, new StreamTransformationFilter(d, new StringSink(recovered)));
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    return recovered;
}
string CBCMode_Encrypt(string text, byte key[], int keySize)
{
    string cipher = "";

    AutoSeededRandomPool rnd;
    byte iv[IV_SIZE];
    rnd.GenerateBlock(iv, sizeof(iv));

    try
    {
        cipher = string(reinterpret_cast<const char *>(iv), IV_SIZE);
        CBC_Mode<DES_EDE3>::Encryption e;
        e.SetKeyWithIV(key, keySize, iv);
        StringSource(text, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return cipher;
}
string CBCMode_Decrypt(string ciphertextWithIV, byte key[], int keySize)
{
    string recovered = "";

    byte iv[IV_SIZE];
    memcpy(iv, ciphertextWithIV.c_str(), IV_SIZE);

    try
    {
        CBC_Mode<DES_EDE3>::Decryption d;
        d.SetKeyWithIV(key, keySize, iv);

        StringSource(ciphertextWithIV.substr(IV_SIZE), true, new StreamTransformationFilter(d, new StringSink(recovered))); // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return recovered;
}
std::string ECBMode_Encrypt(std::string text, byte key[], int keySize)
{
    std::string cipher = "";
    // Encryption
    try
    {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
        e.SetKey(key, keySize);
        CryptoPP::StringSource(text, true, new CryptoPP::StreamTransformationFilter(e, new CryptoPP::StringSink(cipher))); // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return cipher;
}
string ECBMode_Decrypt(string cipher, byte key[], int keySize)
{
    string recovered = "";
    try
    {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
        d.SetKey(key, keySize);
        CryptoPP::StringSource s(cipher, true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::StringSink(recovered))); // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return recovered;
}

void IntegerToByteArray(const Integer &integer, byte *output, size_t length)
{
    CryptoPP::ArraySink arraySink(output, length);
    integer.Encode(arraySink, length);
}
Integer CharArrayToInteger(const char *charArray)
{
    Integer result;
    for (int i = 0; i < strlen(charArray) - 1; i++)
    {
        result *= 10;
        result += (charArray[i] - '0');
    }
    return result;
}
char *trimCString(const char *input)
{
    if (input == nullptr)
    {
        return nullptr;
    }

    char *filename = (char *)(malloc(256 * sizeof(char)));
    int k = 0;
    int i;
    for (i = 0; i < strlen(input) - 1; i++)
    {
        if (input[i] == '\0')
            break;
        if (input[i] != ' ')
            filename[k++] = input[i];
        else
            break;
    }

    filename[i] = '\0';
    return filename;
}
int CharArrayToint(const char *charArray)
{
    int result;
    for (int i = 0; i < strlen(charArray) - 1; i++)
    {
        result *= 10;
        result += (charArray[i] - '0');
    }
    return result;
}
char *ToString(const CryptoPP::Integer &n)
{
    std::ostringstream os;
    os << n;
    std::string x = os.str();
    const int length = x.length();
    char *char_array = new char[length + 1];
    strcpy(char_array, x.c_str());
    return char_array;
}
void *recvmg(void *sock)
{
    int their_sock = *((int *)sock);
    char msg[500];
    int len;
    while ((len = recv(their_sock, msg, 500, 0)) > 0)
    {
        msg[len] = '\0';
        while (cnt < 3)
            sleep(2);
        if (cnt == 3)
        {
            y = CharArrayToInteger(msg);
            cnt++;
        }
        if (cnt == 5)
        {
            if (msg[0] == '2')
            {
                cout << "Client chose AES algo\n";
                algoty = 2;
            }
            else if (msg[0] == '1')
            {
                cout << "Client chose DES algo\n";
                algoty = 1;
            }
            else if (msg[0] == '3')
            {
                cout << "Client chose Blowfish algo\n";
                algoty = 3;
            }
            cnt++;
        }
        else if (cnt == 6)
        {
            const char *chk = "File not found in directory";
            if (isrequest)
            {
                if (strcmp(msg, chk) == 0)
                {
                    cout << msg << "\n";
                    isrequest = 0;
                    continue;
                }
                else
                {
                    std::string tt(msg);
                    if (algoty == 2)
                    {
                        byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
                        IntegerToByteArray(private_key, key, CryptoPP::AES::DEFAULT_KEYLENGTH);
                        tt = ECBMode_Decrypt(tt, key, sizeof(key));
                    }
                    else if (algoty == 1)
                    {
                        byte key[CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH];
                        IntegerToByteArray(private_key, key, CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH);
                        tt = CBCMode_Decrypt(tt, key, sizeof(key));
                    }
                    else if (algoty == 3)
                    {
                        byte key[CryptoPP::Blowfish::DEFAULT_KEYLENGTH];
                        IntegerToByteArray(private_key, key, CryptoPP::Blowfish::DEFAULT_KEYLENGTH);
                        tt = Blowfish_Decrypt(tt, key, sizeof(key));
                    }
                    FILE *rp = fopen("result.txt", "wb");
                    for (size_t i = 0; i < tt.length(); ++i)
                    {
                        fputc(tt[i], rp);
                    }
                    fclose(rp);
                }
                isrequest = 0;
                cout << "File recieved successfully\n";
            }
            else
            {
                char username[256];
                char filename[256];
                splitString(msg, username, filename);
                cout << username << " requested the following file: " << filename << "\n";
                char *tfile = trimCString(filename);
                FILE *fp = fopen(tfile, "rb");
                if (fp == NULL)
                {
                    cout << "File not found\n";
                    len = write(their_sock, "File not found in directory", strlen("File not found in directory"));
                }
                else
                {
                    fseek(fp, 0, SEEK_END);
                    long fileLength = ftell(fp);
                    fseek(fp, 0, SEEK_SET);
                    char *fileContent = new char[fileLength];
                    fread(fileContent, 1, fileLength, fp);
                    fclose(fp);
                    std::string tt(fileContent);
                    if (algoty == 2)
                    {
                        byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
                        IntegerToByteArray(private_key, key, CryptoPP::AES::DEFAULT_KEYLENGTH);
                        tt = ECBMode_Encrypt(tt, key, sizeof(key));
                    }
                    else if (algoty == 1)
                    {
                        byte key[CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH];
                        IntegerToByteArray(private_key, key, CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH);
                        tt = CBCMode_Encrypt(tt, key, sizeof(key));
                    }
                    else if (algoty == 3)
                    {
                        byte key[CryptoPP::Blowfish::DEFAULT_KEYLENGTH];
                        IntegerToByteArray(private_key, key, CryptoPP::Blowfish::DEFAULT_KEYLENGTH);
                        tt = Blowfish_Encrypt(tt, key, sizeof(key));
                    }
                    len = write(their_sock, tt.c_str(), tt.length());
                    if (len < 0)
                    {
                        perror("Error sending file contents");
                        exit(1);
                    }
                    else
                    {
                        cout << "File sent successfully" << endl;
                    }
                    delete[] fileContent;
                }
                memset(tfile, '\0', sizeof(tfile));
            }
        }
        memset(msg, '\0', sizeof(msg));
    }
}
void *recvmg2(void *sock)
{
    int their_sock = *((int *)sock);
    char msg[500];
    int len;
    while ((len = recv(their_sock, msg, 500, 0)) > 0)
    {
        msg[len] = '\0';
        if (cnt == 0)
        {
            p = CharArrayToInteger(msg);
            cnt++;
        }
        else if (cnt == 1)
        {
            g = CharArrayToInteger(msg);
            cnt++;
        }
        else if (cnt == 2)
        {
            x = CharArrayToInteger(msg);
            cnt++;
            private_key = ModularExponentiation(x, b, p);
            cout << "Connection successfully established and key exchanged using diffie hellman algorithm\n 1)DES 2)AES 3)Blowfish\n Please enter the corresponding number for the algorithm to be used" << endl;
        }
        else if (cnt == 4)
        {
            const char *chk = "File not found in directory";
            if (isrequest)
            {
                if (strcmp(msg, chk) == 0)
                {
                    cout << msg << "\n";
                    isrequest = 0;
                    continue;
                }
                else
                {
                    std::string tt(msg);
                    if (algoty == 2)
                    {
                        byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
                        IntegerToByteArray(private_key, key, CryptoPP::AES::DEFAULT_KEYLENGTH);
                        tt = ECBMode_Decrypt(tt, key, sizeof(key));
                    }
                    else if (algoty == 1)
                    {
                        byte key[CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH];
                        IntegerToByteArray(private_key, key, CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH);
                        tt = CBCMode_Decrypt(tt, key, sizeof(key));
                    }
                    else if (algoty == 3)
                    {
                        byte key[CryptoPP::Blowfish::DEFAULT_KEYLENGTH];
                        IntegerToByteArray(private_key, key, CryptoPP::Blowfish::DEFAULT_KEYLENGTH);
                        tt = Blowfish_Decrypt(tt, key, sizeof(key));
                    }
                    FILE *rp = fopen("result.txt", "wb");
                    for (size_t i = 0; i < tt.length(); ++i)
                    {
                        fputc(tt[i], rp);
                    }
                    fclose(rp);
                }
                isrequest = 0;
                cout << "File recieved successfully\n";
            }
            else
            {
                char username[256];
                char filename[256];
                splitString(msg, username, filename);
                cout << username << " requested the following file: " << filename << "\n";
                char *tfile = trimCString(filename);
                FILE *fp = fopen(tfile, "rb");
                if (fp == NULL)
                {
                    cout << "File not found\n";
                    len = write(their_sock, "File not found in directory", strlen("File not found in directory"));
                }
                else
                {
                    fseek(fp, 0, SEEK_END);
                    long fileLength = ftell(fp);
                    fseek(fp, 0, SEEK_SET);
                    char *fileContent = new char[fileLength];
                    fread(fileContent, 1, fileLength, fp);
                    fclose(fp);
                    std::string tt(fileContent);
                    if (algoty == 2)
                    {
                        byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
                        IntegerToByteArray(private_key, key, CryptoPP::AES::DEFAULT_KEYLENGTH);
                        tt = ECBMode_Encrypt(tt, key, sizeof(key));
                    }
                    else if (algoty == 1)
                    {
                        byte key[CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH];
                        IntegerToByteArray(private_key, key, CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH);
                        tt = CBCMode_Encrypt(tt, key, sizeof(key));
                    }
                    else if (algoty == 3)
                    {
                        byte key[CryptoPP::Blowfish::DEFAULT_KEYLENGTH];
                        IntegerToByteArray(private_key, key, CryptoPP::Blowfish::DEFAULT_KEYLENGTH);
                        tt = Blowfish_Encrypt(tt, key, sizeof(key));
                    }
                    len = write(their_sock, tt.c_str(), tt.length());
                    if (len < 0)
                    {
                        perror("Error sending file contents");
                        exit(1);
                    }
                    else
                    {
                        cout << "File sent successfully" << endl;
                    }
                    delete[] fileContent;
                }
                memset(tfile, '\0', sizeof(tfile));
            }
        }
        memset(msg, '\0', sizeof(msg));
    }
}
int main(int argc, char *argv[])
{
    struct sockaddr_in their_addr;
    int my_sock;
    int their_sock;
    int their_addr_size;
    int portno;
    pthread_t sendt, recvt;
    char msg[500];
    char username[100];
    char res[600];
    char ip[INET_ADDRSTRLEN];
    int len;

    if (argc > 3)
    {
        printf("too many arguments");
        exit(1);
    }
    portno = atoi(argv[2]);
    strcpy(username, argv[1]);
    my_sock = socket(AF_INET, SOCK_STREAM, 0);
    memset(their_addr.sin_zero, '\0', sizeof(their_addr.sin_zero));
    their_addr.sin_family = AF_INET;
    their_addr.sin_port = htons(portno);
    their_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(my_sock, (struct sockaddr *)&their_addr, sizeof(their_addr)) < 0)
    {
        perror("connection not esatablished");
        exit(1);
    }
    inet_ntop(AF_INET, (struct sockaddr *)&their_addr, ip, INET_ADDRSTRLEN);
    printf("connected to %s, start chatting\n", ip);
    if ((len = recv(my_sock, msg, 500, 0)) > 0)
    {
        msg[len] = '\0';

        if (strcmp(msg, "1") == 0)
        {
            cout << "Waiting for other client to connect\n";
            AutoSeededRandomPool rnd;
            unsigned int bits = 256;
            SecByteBlock gene((8 + 7) / 8);
            AutoSeededRandomPool rng;
            rng.GenerateBlock(gene, gene.size());
            b.Decode(gene, gene.size());
            their_sock = my_sock;
            pthread_create(&recvt, NULL, recvmg2, &my_sock);
            while (cnt != 3)
                sleep(2);
            cnt++;
            y = ModularExponentiation(g, b, p);
            strcpy(res, ToString(y));
            len = write(my_sock, res, strlen(res));
            if (len < 0)
            {
                perror("message not sent");
                exit(1);
            }
            memset(msg, '\0', sizeof(msg));
            memset(res, '\0', sizeof(res));
            int x = -1;
            while (x != 0)
            {
                if (fgets(msg, 500, stdin) > 0)
                    if (msg[0] != '1' && msg[0] != '2' && msg[0] != '3')
                        cout << "Enter the correct choice\n";
                    else
                        x = 0;
            }
            cout << "Algorithm successfully chosen start sending files\n";
            algoty = msg[0] - '0';
            strcpy(res, msg);

            len = write(my_sock, res, strlen(res));
            if (len < 0)
            {
                perror("message not sent");
                exit(1);
            }
            memset(msg, '\0', sizeof(msg));
            memset(res, '\0', sizeof(res));
            isrequest = 0;
            while (fgets(msg, 500, stdin) > 0)
            {
                strcpy(res, msg);
                isrequest = 1;
                char usernameMsg[500];
                snprintf(usernameMsg, sizeof(usernameMsg), "%s->", argv[1]);
                strcat(usernameMsg, res);

                len = write(my_sock, usernameMsg, strlen(usernameMsg));

                if (len < 0)
                {
                    perror("message not sent");
                    exit(1);
                }

                memset(msg, '\0', sizeof(msg));
                memset(usernameMsg, '\0', sizeof(usernameMsg));
            }
        }
        else if (strcmp(msg, "2") == 0)
        {
            printf("Trying to establish secure connection with client 2\n");
            AutoSeededRandomPool rnd;
            unsigned int bits = 256;
            SecByteBlock scratch((bits + 7) / 8);
            SecByteBlock gene((8 + 7) / 8);
            AutoSeededRandomPool rng;
            rng.GenerateBlock(scratch, scratch.size());
            p.Decode(scratch, scratch.size());
            rng.GenerateBlock(gene, gene.size());
            a.Decode(gene, gene.size());
            rng.GenerateBlock(scratch, scratch.size());
            g.Decode(scratch, scratch.size());
            Integer x = ModularExponentiation(g, a, p);
            their_sock = my_sock;
            pthread_create(&recvt, NULL, recvmg, &my_sock);
            if (cnt == 0)
            {
                strcpy(res, ToString(p));
                len = write(my_sock, res, strlen(res));
                if (len < 0)
                {
                    perror("message not sent");
                    exit(1);
                }
                memset(msg, '\0', sizeof(msg));
                memset(res, '\0', sizeof(res));
                cnt++;
            }
            sleep(1);
            if (cnt == 1)
            {
                strcpy(res, ToString(g));
                len = write(my_sock, res, strlen(res));
                if (len < 0)
                {
                    perror("message not sent");
                    exit(1);
                }
                memset(msg, '\0', sizeof(msg));
                memset(res, '\0', sizeof(res));
                cnt++;
            }
            sleep(1);
            if (cnt == 2)
            {
                strcpy(res, ToString(x));
                len = write(my_sock, res, strlen(res));
                if (len < 0)
                {
                    perror("message not sent");
                    exit(1);
                }
                memset(msg, '\0', sizeof(msg));
                memset(res, '\0', sizeof(res));
                cnt++;
            }
            sleep(1);
            while (cnt != 4)
                sleep(2);
            private_key = ModularExponentiation(y, a, p);
            cout << "Connection successfully esatablished and key shared using diffie hellman algorithm\n Waiting for client to choose algorithm from 1)DES 2)AES 3)Blowfish\n";
            cnt++;
            while (fgets(msg, 500, stdin) > 0)
            {
                strcpy(res, msg);
                isrequest = 1;
                char usernameMsg[500];
                snprintf(usernameMsg, sizeof(usernameMsg), "%s->", argv[1]);
                strcat(usernameMsg, res);

                len = write(my_sock, usernameMsg, strlen(usernameMsg));

                if (len < 0)
                {
                    perror("message not sent");
                    exit(1);
                }

                memset(msg, '\0', sizeof(msg));
                memset(usernameMsg, '\0', sizeof(usernameMsg));
            }
        }
        else
        {
            cout << "Received an unrecognized message" << endl;
        }
    }
    pthread_join(recvt, NULL);
    close(my_sock);
}

// g++ -g3 -ggdb -O0 -I. -I/usr/include/cryptopp dh-param.cpp -o dh-param.exe -lcryptopp -lpthread
// g++ -g -O2 -I. -I/usr/include/cryptopp dh-param.cpp -o dh-param.exe -lcryptopp -lpthread
