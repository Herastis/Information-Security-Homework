#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h>
#include <errno.h>
#define MAX 80 
#define PORT 8080 
#define SA struct sockaddr 



// Function designed for chat between client and server. 
void func(int sockfd) 
{ 
	int hiB = 0, hiKM = 0;
	int CBC=0, OFB=0;
	char mod[MAX]; //mod de operare
	int primesteCheia = 0;
	int raspunsB = 0;
	//----------------------------------------------------------------------
	 /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
	 /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";
	unsigned char ciphertext[128];
	/* Buffer for the decrypted text */
    unsigned char decryptedtext[128];
	//----------------------------------------------------------------------
	char buff[MAX]; 
	int n; 
	// infinite loop 
	for (;;) {
		//printf("\n[A> "); 
		bzero(buff, MAX); 
		// 1) A transmite modul de operare catre KM si primeste cheia
		if(hiKM == 0 || primesteCheia == 0)
		{
			printf("A");
			bzero(buff, sizeof(buff)); 
			read(sockfd, buff, sizeof(buff)); 
			if(strcmp("Hi, I am KM!", buff)==0 && hiKM == 0)
					{	
						hiKM = 1;
						printf("1)Trimite cbc sau ofb catre KM: ");
						bzero(buff, MAX); 
						int n=0; 
						while ((buff[n++] = getchar()) != '\n'); 
						write(sockfd, buff, sizeof(buff)); // trimite catre KM modul ales
					}
			if(hiKM == 1 && primesteCheia == 0)
					{
						bzero(buff, MAX); 
						if(read(sockfd, buff, sizeof(buff) < 0))
						{
							perror ("[server]Eroare la read() de la client. BADUMTZ\n");
							//return errno;
						}
						else 
						{
							printf("2)Cheia criptata primita de la KM : %s", buff); 
							primesteCheia = 1;
							strcpy(ciphertext,buff);
						}
					}
		}
		// 1) A transmite modul catre B si trimite cheia de la KM
		else if(primesteCheia == 1 && hiB == 0)	
		{
			bzero(buff, sizeof(buff)); 
			read(sockfd, buff, sizeof(buff)); 
			if(strcmp("Hi, I am B!", buff)==0)
					{	
						hiB = 1;
						printf("3)Trimite cbc sau ofb catre B: ");
						bzero(buff, MAX); 
						int n=0; 
						while ((buff[n++] = getchar()) != '\n') ; 
						write(sockfd, buff, sizeof(buff)); // trimite catre B modul ales

						bzero(buff, MAX);
						write(sockfd, ciphertext, sizeof(buff)); // trimite catre B ciphertextul
					}
		}
		if (strncmp("exit", buff, 4) == 0) { 
			printf("Server Exit...\n"); 
		} 
	}
} 

// Driver function 
int main() 
{ 
	
	int sockfd, connfd, len; 
	struct sockaddr_in servaddr, cli; 
	unsigned char key3[16] = {0}; // Criptarea cheilor K1 si K2
    unsigned char iv[16] = {0}; // vector de intializare

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

      new_PID = fork();

       if (new_PID == 0)
        func(client);        
    }  /* while */

} 
