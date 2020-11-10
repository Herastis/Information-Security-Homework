#include <netdb.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> // C - Implicit Declaration of Function 'inet_addr'
#include <openssl/evp.h>
#include <openssl/aes.h>

#define MAX 80 
#define PORT 8080 
#define SA struct sockaddr 

//  gcc -g B.c -l crypto -o client

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void func(int sockfd) 
{ 
    int hi=0;
    int cbc=0, ofb=0;
    char buff[BUFSIZ]; 
    int primesteCheia = 0;
    int msj_decriptat = 0;
    //----------------------------------------------------------------------
    unsigned char *key = (unsigned char *)"0123456789012345"; // k'
    unsigned char *iv = (unsigned char *)"0123456789012345";   // Vector de initializare 
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];
	//----------------------------------------------------------------------
    for (;;) { 
        bzero(buff, sizeof(buff));
        if(hi==0) // Hi, I am B!
            { 
                bzero(buff, sizeof(buff)); 
                strcpy(buff,"Hi, I am B!"); //trimit Salut sunt B!
                printf("Trimit spre A... \n");
                if (write(sockfd, buff, BUFSIZ) <= 0) // trimite catre KM modul ales
						{
							perror ("[server]Eroare la write() Hi, I am B! spre A. \n");
							//return errno;
						}     
                printf(buff, "%s\n");
                hi=1;
            }
        if ( ((cbc || ofb) == 0) && hi == 1) //primeste modul si ciphertextul
            {   

                //1) Citesc modul de operare de la A
                bzero(buff, sizeof(buff)); 
                read(sockfd, buff, sizeof(buff)); 
                printf("1)Modul de operare ales de catre A : %s", buff);
                if(strncmp(buff,"cbc",3)==0)
                { 
                    printf("Mod de operare: CBC\n"); 
                    cbc=1;
                }
                if(strncmp(buff,"ofb",3)==0)
                {  
                    printf("Mod de operare: OFB\n");   
                    ofb=1;
                }
                //2) Citesc ciphertextul de la A
                bzero(buff, sizeof(buff)); 
                read(sockfd, buff, sizeof(buff)); 
                printf("2)Cheia criptata primita de la A : %s", buff);
                strcpy(ciphertext,buff);
            }
        if(cbc || ofb) //decriptam
        {
			EVP_CIPHER_CTX *ctx;
			int len;
			int plaintext_len;
            int ciphertext_len;

			unsigned char plaintext[16] ={0}; // Cheie ce urmeaza a fi decriptata

			if(!(ctx = EVP_CIPHER_CTX_new()))
				handleErrors();

			if(cbc)
            {
				if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
					handleErrors();
            }
			else 
            if(ofb)
				if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, key, iv))
					handleErrors();
		
			if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
				handleErrors();
			plaintext_len = len;

		
			if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
				handleErrors();
			plaintext_len += len;

			EVP_CIPHER_CTX_free(ctx);

            printf("Cheia decriptata este: %s\n", plaintext);

            msj_decriptat = 1;
        }
        
        if(msj_decriptat)
        {
               
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
    unsigned char key3[16] = {0}; // Criptarea cheilor K1 si K2
    unsigned char iv[16] = {0}; // vector de intializare
  
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