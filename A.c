#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>
#include <pthread.h>

#define MAX 800000 
#define PORT 8080 
#define SA struct sockaddr 
#include <openssl/aes.h>

extern int errno;
//	gcc -g A.c -l crypto -o server

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


int hiB = 0, hiKM = 0; //variabile care verifica comunicarea cu B si KM
int cbc=0, ofb=0;
int primesteCheia = 0; //verifica daca A a primit cheia de la KM
int fisierCriptat = 0;
//----------------------------------------------------------------------
unsigned char *key = (unsigned char *)"0123456789012345"; // k'
unsigned char *iv = (unsigned char *)"0123456789012345";  // Vector de initializare 
unsigned char ciphertext[128];
unsigned char decryptedtext[128];
//----------------------------------------------------------------------
char buff[BUFSIZ]; 
char msg[BUFSIZ];

void *func(int sockfd) 
{ 
    // infinite loop 
    for (;;) {
        //printf("\n[A> "); 
        bzero(buff, BUFSIZ); 
        // 1) A transmite modul de operare catre KM si primeste cheia
        if(hiKM == 0 || primesteCheia == 0)
        {
            bzero(buff, BUFSIZ); 
            if(read(sockfd, buff, BUFSIZ) < 0)
            {
                perror ("[server]Eroare la read() Hi, I am KM! de la KM. \n");
                //return errno;
            }
            if(strcmp("Hi, I am KM!", buff) == 0 && hiKM == 0)
                    {	
                        hiKM = 1;
                        printf("1)Trimite cbc sau ofb catre KM: ");
                        bzero(buff, BUFSIZ); 
                        fgets(buff, BUFSIZ, stdin);
                        if(strncmp(buff,"cbc",3) == 0)
                            cbc = 1;
                        else
                            ofb = 1;

                        if(write(sockfd, buff, BUFSIZ) <= 0) // trimite catre KM modul ales
                        {
                            perror ("[server]Eroare la write() MOD OPERARE spre KM. \n");
                            //return errno;
                        }

                        

                        bzero(buff, BUFSIZ); 
                        //Primeste cheia criptata
                        if(recv(sockfd, buff, sizeof(buff), 0) < 0)
                            {
                                perror ("[server]Eroare la read() CHEIE CRIPTATA de la KM. \n");
                                //return errno;
                            }
                        printf("\n");
                        printf("2)Cheia criptata primita de la KM : %s\n", buff); 	
                        strcpy(ciphertext,buff);
                        primesteCheia = 1;
                        close(sockfd);
                        return;
                    }
        }
        // 1) A transmite modul catre B si trimite cheia de la KM
        if(primesteCheia == 1 && hiB == 0)	
        {
            printf(buff, "%s\n");
            bzero(buff, BUFSIZ);
            if(read(sockfd, buff, BUFSIZ) < 0)
                {
                    perror ("[server]Eroare la read() Hi, I am B! de la B. \n");
                    //return errno;
                }
            printf(buff, "%s");
            if(strcmp("Hi, I am B!", buff) == 0)
                    {	
                        hiB = 1;
                        printf("3)Trimite cbc sau ofb catre B: ");
                        bzero(buff, BUFSIZ); 
                        int n=0; 
                        while ((buff[n++] = getchar()) != '\n') ; 
                        // trimite catre B modul ales
                        if (write(sockfd, buff, BUFSIZ) <= 0) 
                        {
                            perror ("[server]Eroare la write() MOD OPERARE spre B. \n");
                            //return errno;
                        } 

                        bzero(buff, BUFSIZ);
                        strcpy(buff,ciphertext);
                        // trimite catre B ciphertextul
                        if (write(sockfd, buff, BUFSIZ) <= 0) 
                        {
                            perror ("[server]Eroare la write() CIPHERTEXT spre B. \n");
                            //return errno;
                        } 	 
                    }

        }
        // I-am trimis lui B ciphertextul si acum decriptam
        if(hiB == 1) 
        {
            EVP_CIPHER_CTX *ctx;
            int len;
            int plaintext_len;
            int ciphertext_len;

            unsigned char plaintext[16] ={0}; // Cheie ce urmeaza a fi decriptata

            if(!(ctx = EVP_CIPHER_CTX_new()))
                handleErrors();

            if(cbc)
                if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
                    handleErrors();
            else
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

        }
        if(fisierCriptat == 0) // trimitem date din fisierul criptat
        {
                
                char str[50];
                unsigned char enc_out[sizeof(str)];
                unsigned char dec_out[sizeof(str)];
                
                /*
                AES_KEY enc_key, dec_key;
                FILE * pFile;
                pFile = fopen ("Text.txt" , "r");
                if (pFile == NULL) perror ("Error opening file");
                else {
                        while (fgets (str , 16 , pFile) != NULL)
                        {
                            bzero(iv,sizeof(iv));
                            
                            
                            AES_set_encrypt_key(key, sizeof(key)*8, &enc_key);

                            if(cbc)
                                AES_cbc_encrypt(str, enc_out, sizeof(str), &enc_key, iv, AES_ENCRYPT);
                            else
                                if(ofb)
                                    AES_ofb_encrypt(str, enc_out, sizeof(str), &enc_key, iv, AES_ENCRYPT);
                                bzero(buff,sizeof(buff));
                                strcpy(buff,enc_out);
                            if (write(sockfd, buff, BUFSIZ) <= 0) // trimite catre KM modul ales
                            {
                                perror ("[server]Eroare la write() Hi, I am B! spre A. \n");
                                //return errno;
                            }     
                        }
                        fisierCriptat = 1;
                    }
                    */
        }		

        if (strncmp("exit", buff, 4) == 0) { 
            printf("Server Exit...\n"); 
        } 
    }
} 


int main() 
{ 
    
    int sockfd, connfd, len; 
    struct sockaddr_in servaddr, cli; 

    // socket create and verification 
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
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(PORT); 

    // Binding newly created socket to given IP and verification 
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
        printf("socket bind failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully binded..\n"); 

    // Now server is ready to listen and verification 
    if ((listen(sockfd, 5)) != 0) { 
        printf("Listen failed...\n"); 
        exit(0); 
    } 
    else
        printf("Server listening..\n"); 
    
    
    while (1)
    {
        int client;
        pid_t new_PID;
        len = sizeof(cli); 

        pthread_t thread_id;
        printf ("[server]Asteptam la portul %d...\n",PORT);
        fflush (stdout);

        /* acceptam un client (stare blocanta pina la realizarea conexiunii) */
        client = accept (sockfd, (struct sockaddr *) &cli, &len);

        /* eroare la acceptarea conexiunii de la un client */
        if (client < 0)
        {
            perror ("[server]Eroare la accept().\n");
            continue;
        }
        
        int new_client = client;
        pthread_create(&thread_id, NULL, func, (void *)new_client);      
    }  /* while */
} 