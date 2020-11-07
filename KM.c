#include <netdb.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> // C - Implicit Declaration of Function 'inet_addr'

#define MAX 80 
#define PORT 8080 
#define SA struct sockaddr 

//gcc KM.c -l crypto -o client2


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void func(int sockfd) 
{ 
    char buff[MAX]; 
    int n; 
    int trimiteCheia = 0;
    unsigned char mod;
    unsigned char k[16]; // Cheie generata random

	/* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";
    unsigned char ciphertext[128];
    
    int hi = 0;

    for (;;) {
            bzero(buff, sizeof(buff));
            if(hi==0)  //Hi, I am KM!
                {
                    bzero(buff, sizeof(buff)); 
                    strcpy(buff,"Hi, I am KM!"); 
                    write(sockfd, buff, sizeof(buff)); 
                    hi=1;
                }
            else 
                if(trimiteCheia == 0){
                    bzero(buff, sizeof(buff)); 
                    //primeste modul de operare
                    read(sockfd, buff, sizeof(buff)); 
                    printf("1)Modul de operare ales de catre A : %s", buff); 
                    //generam cheia random
                    RAND_bytes(k, sizeof(k));
                    printf("Cheia generata random este: %s\n",k);

                    //-----------------------Criptam cheia
                    EVP_CIPHER_CTX *ctx;
                    int len;
                    int ciphertext_len;

                    if(!(ctx = EVP_CIPHER_CTX_new()))
                        handleErrors();
                    //alegem ori cbc, ori ofb
                    if(strncmp(buff,"cbc",3) == 0)
                        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
                            handleErrors();
                    else if(strncmp(buff,"ofb",3) == 0)
                        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, key, iv))
                            handleErrors();

                    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, k, sizeof(k)))
                        handleErrors();
                    ciphertext_len = len;
                    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
                        handleErrors();
                    ciphertext_len += len;
                    /* Clean up */
                    EVP_CIPHER_CTX_free(ctx);
                    //------------------------

                    printf("Cheia criptata este: %s\n", ciphertext);
                    //trimit cheia criptata
                    if(write(sockfd, ciphertext, sizeof(ciphertext)<=0))
                    {
                        perror ("[server]Eroare la write() catre server. BADUMTZ\n");
                    } 
                    trimiteCheia = 1; 
                }
                
            else
            {
                close(sockfd);
                exit(0);
            }
            
                
     }          
} 
  
int main() 
{ 
    int sockfd, connfd; 
    struct sockaddr_in servaddr, cli; 
	

    // socket create and varification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        printf("socket creation failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully created..\n"); 
    bzero(&servaddr, sizeof(servaddr)); 
  
    // assign IP, PORT 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1"); 
    servaddr.sin_port = htons(PORT); 
  
    // connect the client socket to server socket 
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) { 
        printf("connection with the server failed...\n"); 
        exit(0); 
    } 
    else
        printf("connected to the server..\n"); 
  
    // function for chat 
    func(sockfd); 
  
    // close the socket 
    close(sockfd); 
} 