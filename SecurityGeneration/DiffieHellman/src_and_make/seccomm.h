#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <strings.h>
#include <errno.h>

#include <openssl/aes.h>

//Server
void *server(struct sockaddr_in *servarg);

//Client
int client(struct sockaddr_in *servarg);
void reader(int sockfd, int timeout_s);
void writer(int sockfd);
void advertise_client_id(int sockfd, int my_id);
void start_keyexchange_initiator(int sockfd, int target_client);

