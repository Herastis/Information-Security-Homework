#include <netdb.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> // C - Implicit Declaration of Function 'inet_addr'
#define MAX 80 
#define PORT 8080 
#define SA struct sockaddr 



void func(int sockfd) 
{ 
    int hi=0;
    int cbc=0, ofb=0;
    char buff[MAX]; 
    int n; 
    int primesteCheia = 0;
    //----------------------------------------------------------------------
    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";
    unsigned char ciphertext[128];
    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];
	//----------------------------------------------------------------------
    
    for (;;) { 
        bzero(buff, sizeof(buff));
        if(hi==0) // Hi, I am B!
            { 
                strcpy(buff,"Hi, I am B!"); //trimit Salut sunt B!
                bzero(buff, sizeof(buff)); 
                write(sockfd, buff, sizeof(buff)); 
                hi=1;
            }
        else if ((cbc || ofb) == 0) //primeste modul si ciphertextul
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
                printf("2)Cheia criptata primita de la KM : %s", buff);
                strcpy(ciphertext,buff);
            }
            /*
        else if(primesteCheia==0)   //3) primeste cheia de la A
            {
                bzero(buff, sizeof(buff)); 
                if(read(sockfd, buff, sizeof(buff) <= 0))
                {
                    perror ("[server]Eroare la read() de la client. BADUMTZ\n");
                    //return errno;
                }
                else 
                {
                    printf("3)Cheia primita de la A : %s", buff); 
                    primesteCheia = 1;
                    strcpy(ciphertext,buff);
                    printf("Ciphertext: %s", ciphertext);
                }
            }
			*/
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