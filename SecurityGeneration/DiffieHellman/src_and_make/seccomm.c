//client A computes a randomly and pass g_a = pow(g,a) mod dh_prime
//client B computes b randomly and pass g_b = pow(g,b) mod dh_prime
//client B receives g_a and generate the key (256 bytes) g_ab=pow(g_a, b)
//client A receives g_b and generate the key (256 bytes) g_ab=pow(g_b, a)

//craft a message
//Create msg_key : SHA256( key[88+x, 32 bytes] + msg)[128 middle bits]
//aes_key : SHA256(msg_key + key[x, 36 bytes])[0, 8 bytes]
//              + SHA256(key[40+x, 36 bytes] + msg_key)[8, 16 bytes]
//            + SHA256(msg_key + key[x, 36 bytes])[24, 8 bytes]

// aes_iv = SHA256(key[40+x, 36 bytes] + msg_key)[0, 8 bytes]
//            + SHA256(msg_key + key[x, 36 bytes])[8, 16 bytes]
//              + SHA256(key[40+x, 36 bytes] + msg_key)[24, 8 bytes]

//AES_IGE_encryption(msg, aes_key, aes_iv)
//Craft_encryptred_msg
//AES_decrypt_and_check(msg, key)
  // extract msg_key, encrypted data
  // Compute AES_iv, AES_key
  //AES decryption
  

#include <openssl/rand.h>
#include <openssl/evp.h> //for sha256
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <math.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>

#define NBR_CONNECTION 15
#define SIZE_G_EXP 256
#define MAX_DGRAM_SIZE  549

#define NUMBER_OF_CLIENTS_ALLOWED 10 //it is 10 for now, can be updated according to the usecase

//Client connection fds. Currently we limit the number of clients to 10.
int connfd[NUMBER_OF_CLIENTS_ALLOWED];
int mysockfd;

int client_encryption[NUMBER_OF_CLIENTS_ALLOWED] = {0};
bool first_time_writer_call = true;



char connectionTable[NBR_CONNECTION][3] = {'0'};//socket (int, 4 bytes)[0:3]
char receivedMsg[NBR_CONNECTION][2] = {'0'};
char ToSendMsg[NBR_CONNECTION][80] = {'0'}; //msg_key[0:15]; aes_key[16:47] ; aes_iv[48:79]; fingerprint[80:83]                          
char cryptoParam[NBR_CONNECTION][1023] = {'0'}; //random parameter[0:255] ; g**rd_param[256:511]; g_received[512:767]; key[768:1023]
struct sockaddr_in incoming_addr[NBR_CONNECTION];
struct addrinfo* res[NBR_CONNECTION];
char keyTable[NBR_CONNECTION][256] = {'0'};

char msgTable[NBR_CONNECTION][MAX_DGRAM_SIZE];
int msg_size[NBR_CONNECTION];

char p_g[] = "4";  // value generaly chosen among {2, 3, 4, 5, 6, 7}
char p_prime[512] = "13313843571599696264354128333209905067334208685286045369588527696917625482580385180598688943197307274366713926404090994598386175138123309685280805602565223";

void feedTable(char (*table_to_feed)[], char *table, int size, int location, int index){ 
    for (int i =0; i < size; i++){
	(*table_to_feed + index*256)[location + i] = table[i];
    }
}

void readTable(char (*table_to_read)[], char *table, int size, int location, int index){
    for (int i =0; i < size; i++){
	table[i] = (*table_to_read + index)[location + i];
    }
}

void feedTableBis(char *table, int size, int index){ 
    for (int i =0; i < size; i++){
        (*msgTable + index*MAX_DGRAM_SIZE)[i] = table[i];
    }
    msg_size[index] = size;
}

void readTableBis(char *table, int f){
    for (int j =0; j < NBR_CONNECTION; j++){	
	int size = msg_size[j];
        if (size != 0){
	    for (int i =0; i < size; i++){
                table[i] = (*msgTable + j*MAX_DGRAM_SIZE)[i];
                (*msgTable + j*MAX_DGRAM_SIZE)[i] = '0';
	    }
            f = ntohs(incoming_addr[j].sin_port);
            msg_size[j] = 0;
	    break;
        }
    }
}

void readTableTer(char (*table)[], int f[]){    //to retrieve all a table
    for (int j =0; j < NBR_CONNECTION; j++){	
	int size = msg_size[j];
        if (size != 0){
	    for (int i =0; i < size; i++){
                (*table + j*MAX_DGRAM_SIZE)[i] = (*msgTable + j*MAX_DGRAM_SIZE)[i];
                (*msgTable + j*MAX_DGRAM_SIZE)[i] = '0';
	    }
            f[j] = ntohs(incoming_addr[j].sin_port);
            msg_size[j] = 0;
        }
    }
}

char * random_a(){
    unsigned char * a = malloc(256);
    if(RAND_bytes(a, 256) != 1){
	perror("problem with random generator");
    }
    BIGNUM *p_a = BN_bin2bn(a, 256, NULL);
    char * number_a = BN_bn2dec(p_a);
    return number_a;
}

//Takes in a, and generate g_a = pow(g,a)mod p .
//g is the generator, and p is the prime
char * DH_client(int index, unsigned char a[256]){  
    unsigned char * g_a = malloc(256);
    BIGNUM *g = BN_new();
    BIGNUM *prime = BN_new();
    BN_dec2bn(&g, p_g);
    BN_dec2bn(&prime, p_prime);
    
    BN_CTX* ctx;
    ctx = BN_CTX_new();
    BIGNUM *p_a = BN_new();
    BN_dec2bn(&p_a, a);
    BIGNUM *result = BN_new();
    BN_mod_exp(result, g, p_a, prime, ctx); 
    BN_bn2binpad(result, g_a, 256);
    
    char * number_str = malloc(256);
    number_str = BN_bn2dec(result); 
    BN_free(p_a);
    BN_CTX_free(ctx);
    
    return number_str;
}

//Takes in g_a and b and compute g_ab (and g_b and a to compute g_ab), stores in the feedTable 
//in the given index
void DH_clientthird(int index, unsigned char a[256], unsigned char *g_b){   
    BIGNUM *g = BN_new();
    BIGNUM *prime = BN_new();
    BN_dec2bn(&g, p_g);
    BN_dec2bn(&prime, p_prime);
    
    BN_CTX* ctx;
    ctx = BN_CTX_new();
    BIGNUM *p_a = BN_new();
    BIGNUM *p_gb = BN_new();
    BN_dec2bn(&p_a, a);
    BN_dec2bn(&p_gb, g_b);
    BIGNUM *result = BN_new();
    BN_mod_exp(result, p_gb, p_a, prime, ctx); 
    
    char * number_key= BN_bn2dec(result);
    BN_free(p_a);
    BN_CTX_free(ctx);

    feedTable(keyTable, number_key, 256, 0, index);    
}

void prepareMsg(int index, char *msg, char *toSend){
    //length of the payload in bytes
    //sequence number
    //padding with 12 to 1024 or 1 to 15 rd bits to be divisible by 16?
    printf("starts prepareMsg\n");
    unsigned char length[4];
    unsigned char sequence_number[4];
    int l = strlen(msg);
    int seq_nb = 0;
    snprintf(length, 4, "%d", l);
    snprintf(sequence_number, 4, "%d", seq_nb);                                       
    memcpy(toSend, length, 4);
    strncat(toSend, sequence_number, 4);
    strncat(toSend, msg, l);
}

void key_generation(int index,unsigned char * msg_key, unsigned char *aeskey, unsigned char *aes_iv){//generates msg_key, aes_key and aes_iv 
    unsigned char key[256];
    readTable(keyTable, key, 256, 0, index); 
    unsigned char *prekey1 = malloc(36);
    unsigned char *key2 = malloc(52);
    unsigned char *key1 = malloc(52);         
    memcpy(key1, msg_key, 16);
    memcpy(prekey1, key, 36);                                                            
    memcpy(key2, key + 40, 36);
    memcpy(key1+16, prekey1, 36);
    memcpy(key2+36, msg_key, 16); 
    unsigned char *c1 = malloc(32);
    unsigned char *c2 = malloc(32);
    
    EVP_Digest(key1, 52, c1, NULL, EVP_sha256(), NULL);
    EVP_Digest(key2, 52, c2, NULL, EVP_sha256(), NULL);
    
    memcpy(aeskey, c1, 8); 
    memcpy(aeskey+8, c2+8, 16); 
    memcpy(aeskey+24, c1+24, 8); 
    
    memcpy(aes_iv, c2, 8); 
    memcpy(aes_iv+8, c1+8, 16); 
    memcpy(aes_iv+24, c2+24, 8); 
    
}

void key_generation_bis(int index, unsigned char * msg_key, unsigned char *aeskey, unsigned char *aes_iv){//generates aes_key and aes_iv with msg_key
    unsigned char *prekey1 = malloc(36);
    unsigned char *key2 = malloc(52);
    unsigned char *key1 = malloc(52); 
    unsigned char key[256];
    readTable(keyTable, key, 256, 0, index); 
    memcpy(key1, msg_key, 16);
    memcpy(prekey1, key, 36);
    memcpy(key2, key+40, 36);
    memcpy(key1+16, prekey1, 36);
    memcpy(key2+36, msg_key, 16); 
    unsigned char *c1 = malloc(32);
    unsigned char *c2 = malloc(32);
    EVP_Digest(key1, 52, c1, NULL, EVP_sha256(), NULL);
    EVP_Digest(key2, 52, c2, NULL, EVP_sha256(), NULL);
    
    memcpy(aeskey, c1, 8); 
    memcpy(aeskey+8, c2+8, 16); 
    memcpy(aeskey+24, c1+24, 8); 
    
    memcpy(aes_iv, c2, 8); 
    memcpy(aes_iv+8, c1+8, 16); 
    memcpy(aes_iv+24, c2+24, 8); 
}

//Takes in a message buffer and encrypts it and returns the aes encrypted message.
char *aes_ige_encryption(int index, char *input){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *aeskey = malloc(32); 
    unsigned char *aes_iv = malloc(32);
    int inputlength = strlen(input)+1;
    int out_len = inputlength + AES_BLOCK_SIZE;
    int f_len = 0;
    int len = strlen(input);
    unsigned char data[32 + len];    
    unsigned char *msg_key = malloc(16);
    unsigned char key[256];
    unsigned char output[25];
    readTable(keyTable, key, 256, 0, index); 
    memcpy(data, key+88, 32);
    strncat(data, input, len);
    if(EVP_Digest(data, len, output, NULL, EVP_sha256(), NULL) != 1){
        //handleError;
        perror("error evp_digest");
    }
    memcpy(msg_key, output + 8, 16);
    key_generation(index, msg_key, aeskey, aes_iv);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aeskey, aes_iv);
    unsigned char *encrypted_data = malloc(out_len);
    unsigned char *text = malloc(out_len + 20);
    EVP_EncryptUpdate(ctx, encrypted_data, &out_len, input, inputlength);
    EVP_EncryptFinal_ex(ctx, encrypted_data+out_len, &f_len);
    
    memcpy(text, msg_key, 16);
    memcpy(text+16, encrypted_data, out_len+f_len);
    return text;   //The sender takes the input
}

//Decrypts the aes encrypted input message
char *aes_ige_decryption(int index, char *input){
    // extract fingerprint, msg_key, encrypted data
    EVP_CIPHER_CTX *ctxd = EVP_CIPHER_CTX_new(); 
    int length;
    int f_len1 = 0;
    int len = strlen(input);
    unsigned char *aeskey = malloc(32); 
    unsigned char *aes_iv = malloc(32);
    unsigned char *msg_key= malloc(16);
    unsigned char encrypted_data[len];
    unsigned char *data = malloc(len);
    memcpy(msg_key, input, 16);
    memcpy(encrypted_data, input+16, strlen(input) - 16);
    key_generation_bis(index, msg_key, aeskey, aes_iv);
    //AES decryption
    EVP_DecryptInit_ex(ctxd, EVP_aes_256_cbc(), NULL, aeskey, aes_iv);
    EVP_DecryptUpdate(ctxd, data, &length, encrypted_data, strlen(encrypted_data));
    EVP_DecryptFinal_ex(ctxd, data+length, &f_len1);
    return data;   
}


/* Input: client_id : To derive the connection fd to write to.
 * 	  *buff : message to be sent.
 * Description : Simple writer to write to a particular client_id 
 * (the connfd is looked up in the 
 * stored array connfd[] with client_id as index)
 */
void write_to_target_client(int client_id, char* buff) {
	int MAX=256;
	printf("sending %s to %d\n", buff, client_id);
        if(write(connfd[client_id], buff, MAX) == -1) {
		printf("%s",strerror(errno));
	}
}

/* Input: *Client_id (char pointer to the client_id 
 *
 * Description :
 * Called by server
 * Simple reader loop/thread to keep reading on the connfd of the given client_id
 * stored in array connfd[] with client_id as index
*/
void *read_from_client(void *client_id)
{
	int my_id = *(int *)client_id;
	int MAX=256;
        char buff[MAX];
        int target_client;
	bool key_exchange = false;
        for(;;) {
                bzero(buff, MAX);
                // read the message from client and copy it in buffer
		if(read(connfd[my_id], buff, sizeof(buff)) <= 0 ) {
			printf("client tr %d encountered an error , exiting",my_id);
			return NULL;
		}
             //   printf("client tr %d Received: %s\n", my_id, buff);
		
		/*The keyexchange has been finished, remove the flag and indicate the client.
		 * All the messages from now will be treated as normal messages , and will
		 * be checked for the target_client ID in the first byte
		 */
                if( (strcmp(buff, "KE_ACK") == 0) || (strcmp(buff, "KE_FAIL") == 0) ){
				key_exchange = false;
				write_to_target_client(target_client, buff);
				continue;

		}
                if(key_exchange == true) {
                        write_to_target_client(target_client, buff);
                        continue;
                }
		
		//Derive the target_client from the first byte of the message.
		//Example: 2hello   
		//Meaning, a message "hello" destined to clientID "2".
                target_client = atoi(&buff[0]);

		/*Received a message of format "xKE_INIT", where x is the target client
		 * this indicates a start of key exchange protocol, until we receive
		 *  KE_ACK or KE_FAIL in clear text treat all messages coming from 
		 *  this client as if they are destined towards the target alone.
		 *  i.e; dont expect target_client id during these transactions.
		 */
		if(strcmp(&buff[1], "KE_INIT") == 0) {
				key_exchange = true;
				//sprintf(buff, "%d%s", my_id, buff+1);
		} else {
			printf("client tr %d Received: %s\n", my_id, buff);
		}

		/*Update the message by placing the sourceClient in the first byte,
		 * followed by the message.
		 * Received: <dstClientID> + <message>, from sourceClient
		 * Sent: <srcClientID> + <message>, to the dstClientID
		 */
		sprintf(buff, "%d%s", my_id, buff+1);
                printf("target: %d source: %d\n", target_client, my_id);

		//Write to the connfd of the target_client
                write_to_target_client(target_client, buff);
        }
}

/* Input: Expects a pointer to the structure object sockaddr_in(with details of
 *  ip, port, proto. 
 * Example: &servaddr is passed in below example
 *	struct sockaddr_in servaddr;
 * 	servaddr.sin_family = AF_INET;
 *      servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
 *      servaddr.sin_port = htons(2222);
 * Description: This is the code to start a server, which keeps 
 * 	listening for new client connections and creates individual client threads. 
 */
void * server(struct sockaddr_in *servarg) { //Create server
    int MAX=256;
    int sockfd, len;
    int i=0;
    int tmpconnfd;
    int client_id;
    char buff[MAX];

    struct sockaddr_in servaddr, cli;

    pthread_t thread[10];

    // socket creation and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (struct sockaddr*)servarg, sizeof(servaddr))) != 0) {
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

    len = sizeof(cli);
    while(i<NUMBER_OF_CLIENTS_ALLOWED) {

        // Accept the data packet from client and verification
        tmpconnfd = accept(sockfd, (struct sockaddr*)&cli, &len);
        if (connfd[i] < 0) {
            printf("server accept failed...\n");
            exit(0);
        }
        else
            printf("server accept the client(not id) %d...\n", i);

	//Get the clientID advertised.(a must)
	bzero(buff, sizeof(buff) );
	if(read(tmpconnfd, buff, sizeof(buff)) <= 0) {
		printf("An error in read, waiting for the clientID, ignoring the client\n");
		continue;
	}
	if(strlen(buff)!= 1) {
		printf("Got a clientId bigger than 1 byte : %ld bytes, ignoring this client\n", strlen(buff) );
		continue;
	}

	client_id = atoi(buff);
	printf("client ID is %d\n", client_id);

	//Save the connfd in the respective slot of the array.
	connfd[atoi(buff)]=tmpconnfd;
        pthread_create( &thread[atoi(buff)], NULL, read_from_client, (void*)&client_id);
        i++;
    }

    for(i=0; i<NUMBER_OF_CLIENTS_ALLOWED; i++) {
	    pthread_join(thread[i], NULL);
    }

        // After chatting close the socket
    close(sockfd);

}

//Input args:
//	sockfd: socket to write to.
//	my_id: my client id that I want to advertise to the server.
//Output: void
//
//Description: The function that advertises client id to the server, so 
//	that the server can keep an association of clients to their ids.
void advertise_client_id(int sockfd, int my_id) {
	int MAX=256;
	char buff[MAX];
	printf("Advertising my client Id to the server : %d\n", my_id);
	bzero(buff, sizeof(buff));
	sprintf(buff, "%d", my_id);
	if(-1 == write(sockfd, buff, MAX)) {
                printf("advertise_client_id failed, exiting. %s\n",strerror(errno));
		exit(1);
        }
}

//Input args: 
//	sockfd : socket to read from and write to
//	target_client : The target client-id with which are going to perform key exchange.
//Uutput: void
//
//Description: The function that initiates the DiffieHelman key exchange with a given 
//	remote host, through the server. send a KE_INIT to signal key exchange, then KE_ACK when
//	the key exchange is successful and KE_FAIL if the exchange fails.
void start_keyexchange_initiator(int sockfd, int target_client) {
    int MAX=256;
    char buff[MAX];
    char gb_buffer[256];
    unsigned char * g_a = malloc(256);
    unsigned char * a = malloc(256);

    if(sockfd == -1) {
	    sockfd = mysockfd;
    }
    //DiffieHelman params. 
    a = random_a();
    g_a = DH_client(target_client, a);

    //Indicate to the server and to the target client about the intended keyexchange.
    bzero(buff, sizeof(buff));
    sprintf(buff, "%dKE_INIT", target_client);
    if(-1 == write(sockfd, buff, MAX)) {
    	printf("KE_INIT write failed, not starting KE. %s\n",strerror(errno));
	return;
    }

    //Make sure we get the KE_INIT back from the remote target.
    bzero(buff, sizeof(buff));
    read(sockfd, buff, sizeof(buff));
    if(strcmp(&buff[1], "KE_INIT")) {
	    printf("The target client doesnt seem to be ready to receive the keyexchange, exiting");
	    return;
    }


    //Start the keyexchange by sending and receiving the DH params.
    if(-1 == write(sockfd, g_a, MAX)) {
	    printf("sending g_a failed, quit KE. %s\n",strerror(errno));
            if(-1 == write(sockfd, "KE_FAIL", MAX))
            	return;
    }

    read(sockfd, gb_buffer, MAX);
    DH_clientthird(target_client, a, gb_buffer);

    //Send an ACK to check if the exchange has been successfull.
    char *msg="ACK";
    unsigned char *data_send = malloc(strlen(msg) + 10 + AES_BLOCK_SIZE);
    //Encrypt the message with aes encryption
    data_send = aes_ige_encryption(target_client, msg);
    
    if(-1 == write(sockfd, data_send, MAX) ) {
	    printf("sending an encrypted ACK failed, quit KE. %s\n",strerror(errno));
            if(-1 == write(sockfd, "KE_FAIL", MAX))
	            return;
    }

    //Finish after receiving KE_ACK from the other side
    bzero(buff, sizeof(buff));
    read(sockfd, buff, sizeof(buff));
    if(strcmp(buff, "KE_ACK")) {
            printf("The target client doesnt seem to have succesfully exchanged the key with us, exit");
	    if(-1 == write(sockfd, "KE_FAIL", MAX)) 
	            return;
    }


    //Send KE_ACK without encryption to signal end of keyexchange to the server and remote target.
    bzero(buff, sizeof(buff));
    strcpy(buff, "KE_ACK");
    if(-1 == write(sockfd, buff, MAX)) 
	    return;

    printf("The communication with client %d is now encrypted\n", target_client);
    //If the exchange is successful, set the encryption flag
    client_encryption[target_client] = 1;
}


//Input args:
//      sockfd: socket to write to.
//      target_client: Client id of the target with whom we are performing a key exchange.
//Output: void
//
//Description: The function that responds to a Key exchange attempt from remote
void start_keyexchange_responder(int sockfd, int target_client) {
    int MAX=256;
    char buff[MAX];
    char ga_buffer[256];
    unsigned char * g_b = malloc(256);
    unsigned char * b = malloc(256);

    if(sockfd == -1) {
            sockfd = mysockfd;
    }
    printf("key exchange started with target : %d\n", target_client);

    //Send KE_INIT to signal start of exchange from our end.
    bzero(buff, sizeof(buff));
    sprintf(buff, "%dKE_INIT", target_client);
    write(sockfd, buff, MAX);

    //Now wait for the ga_buffer from the initiator.
    read(sockfd, ga_buffer, MAX);
    //Send g_b to the target client.
    b = random_a();
    g_b = DH_client(target_client, b);
    DH_clientthird(target_client, b, ga_buffer);
    
    write(sockfd, g_b, MAX);
    //Exchange is over, do some checks and indicate the end of exchange.

    //Server must have sent an encrypted ACK to us, check if its correct.
    printf("Key exchanged, waiting for the ACK\n");
    bzero(buff, sizeof(buff));
    read(sockfd, buff, MAX);
    printf("received %s\n", buff);
    unsigned char *plaintext = malloc(MAX);
    plaintext = aes_ige_decryption(target_client, buff);
    if(strcmp(plaintext, "ACK")) {
	    printf("The decrypted message is not ACK\n");
	    write(sockfd, "KE_FAIL", MAX);
	    return;
    }
    //Finish by sending a KE_ACK and receiving KE_ACK from the other initiator.
    write(sockfd, "KE_ACK", MAX);

    bzero(buff, sizeof(buff));
    read(sockfd, buff, sizeof(buff));
    if(strcmp(buff, "KE_ACK")) {
	    printf("The received message is not KE_ACK\n");
	    write(sockfd, "KE_FAIL", MAX);
	    return;
    }
    printf("The communication with client %d is now encrypted\n", target_client);
    //if the exchange is successful, set the encryption flag
    client_encryption[target_client] = 1;
}

/* Input:
 *      sockfd : connection fd to read from.
 * Description: Reads from the given socket and sets the given timeout for the read.
 */
void reader(int sockfd, int timeout_s) {
    int MAX=256;
    char buff[MAX];
    int target_client;
    unsigned char *plaintext = malloc(MAX);
    struct timeval tv;
    tv.tv_sec = timeout_s;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));

    bzero(buff, sizeof(buff));
    read(sockfd, buff, sizeof(buff));
    if(strlen(buff) != 0) {
            //printf("From Server : %s\n", buff);
            if(strcmp(&buff[1], "KE_INIT") == 0 ){
                printf("got KE_INIT from the target : %d\n", atoi(buff) );
                start_keyexchange_responder(sockfd, atoi(buff) );
                return;
            }
            target_client = atoi(buff);
            if(client_encryption[target_client] == 1) {
                    plaintext = aes_ige_decryption(target_client, buff+1);
                    printf(">%d : %s", target_client, plaintext);
                    return;
            }

            printf(">%d : %s", target_client, buff+1);
    }
}

/* Input:
 * 	sockfd : connection fd to write to.
 * Description: Reads from the cli and writes to the given socket.
 */
void writer(int sockfd) {
    int MAX=256;
    char buff[MAX];
    unsigned char *data_send = malloc(256);
    int n=0;
    int target_client;
    bzero(buff, sizeof(buff));
    if(first_time_writer_call == true)
    {
        printf("Enter the client number to talk to followed by the message string : \n");
        first_time_writer_call = false;
    }

    while ((buff[n++] = getchar()) != '\n')
       ;
    // write(*(int *)sockfd, buff, sizeof(buff));
    if(strlen(buff) != 0) {
            target_client = atoi(buff);
            if(client_encryption[target_client] == 1) {
                    data_send = aes_ige_encryption(target_client, buff+1);
                    bzero(buff, sizeof(buff) );
                    sprintf(buff, "%d%s", target_client, data_send);
                    write(sockfd, buff, MAX);
                    free(data_send);
                    return;
            }

            write(sockfd, buff, sizeof(buff) );
            free(data_send);
    }
}

/* Input: Expects a pointer to the structure object sockaddr_in(with details of server
 *  ip, port, proto. 
 * Example: &servaddr is passed in below example
 *      struct sockaddr_in servaddr;
 *      servaddr.sin_family = AF_INET;
 *      servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
 *      servaddr.sin_port = htons(2222);
 * Description: This is the code to start a client, which connects to the given server
 * 	ip and port and returns the socket FD of the connection. 
 */	
int client(struct sockaddr_in *servarg) {
    int sockfd;
    struct sockaddr_in servaddr;

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created %d..\n", sockfd);

    mysockfd = sockfd;
    bzero(&servaddr, sizeof(servaddr));

    // connect the client socket to server
    if (connect(sockfd, (struct sockaddr*)servarg, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the server..\n");

    return sockfd;
}

