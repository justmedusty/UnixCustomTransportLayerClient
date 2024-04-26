#include <stdio.h>

#include "dustyns_transport_layer.h"
#include "network_layer.h"

#define SERVER_IP "127.0.0.1"
#define PORT "6969"
int main() {

    int server_socket;
    struct addrinfo hints,*server,*pointer;
    size_t addr_len;
    int result;

    hints.ai_socktype = SOCK_RAW;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = IPPROTO_RAW;
    result = getaddrinfo(SERVER_IP,PORT,&hints,&server);
    if(result != 0){
        gai_strerror(result);
        exit(EXIT_FAILURE);
    }

    for(pointer = server;pointer != NULL; pointer = pointer->ai_next){
        if((server_socket = socket(pointer->ai_family,pointer->ai_socktype,pointer->ai_protocol)) == -1){
            perror("socket");
            continue;
        }

        if(connect(server_socket,pointer->ai_addr,pointer->ai_addrlen) == -1){
            perror("connect");
            close(server_socket);
            continue;
        }

    }

    if(pointer == NULL){
        perror("connect");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(server);


}
