#include <stdio.h>

#include "dustyns_transport_layer.h"
#include "network_layer.h"

#define SERVER_IP "127.0.0.1"
#define PORT "6969"

int main() {

    int sockfd;
    ssize_t recv_len;

    // Create a raw socket for ICMP packets
    if ((sockfd = socket(AF_INET, SOCK_RAW, IP_HDRINCL)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    printf("getting ready to connect\n");
    handle_client_connection(sockfd, inet_addr("192.168.68.59"),inet_addr("192.168.68.59"),1000);

    close(sockfd);
    return 0;
}



