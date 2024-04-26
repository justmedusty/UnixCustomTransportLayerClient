
//
// Created by dustyn on 4/22/24.
//
#include <netdb.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include "sys/socket.h"
#include "unistd.h"
#include "stdio.h"
#include "stdlib.h"
#include "poll.h"
#include "netinet/in.h"
#include "errno.h"
#include "string.h"
#include "netinet/ip.h"

#ifndef UNIXCUSTOMTRANSPORTLAYER_DUSTYNS_TRANSPORT_LAYER_H
#define UNIXCUSTOMTRANSPORTLAYER_DUSTYNS_TRANSPORT_LAYER_H

#define BACKLOG 15
#define PAYLOAD_SIZE 512
#define HEADER_SIZE 64
#define PACKET_SIZE ((sizeof (struct iphdr) + HEADER_SIZE + PAYLOAD_SIZE))
#define MAX_PACKET_COLLECTION 1000
#define OUT_OF_BAND_DATA_SIZE 1
#define DATA "DATA"
#define ACKNOWLEDGE "ACK"
#define CORRUPTION "BAD_DATA"
#define RESEND "RESEND"
#define CLOSE "DISCONNECT"
#define OOB "OUT_OF_BAND"
#define INITIAL_TIMEOUT 10
#define MAX_TIMEOUT 160

#define SUCCESS 0
#define ERROR 1


typedef struct Packet {
    struct iovec iov[3];
} Packet;


typedef struct Header {
    char status[20];
    uint16_t checksum;
    uint16_t sequence;
    uint16_t msg_size;

} Header;

uint16_t handle_ack(int socket, Packet *packets);

uint16_t allocate_packet(Packet *packet);

uint16_t free_packet(Packet *packet);

uint8_t compare_checksum(char data[], size_t length, uint16_t received_checksum);

uint16_t calculate_checksum(char *data[], size_t length);

void handle_client_connection(int socket, char src_ip[], char dest_ip[]);

uint16_t send_resend(int socket, uint16_t sequence);

uint16_t send_ack(int socket, uint16_t sequence);

uint16_t handle_close(int socket);

uint16_t handle_corruption(int socket, struct Header *head);

uint16_t set_packet_timeout();

void reset_timeout();

uint16_t packetize_data(Packet packet[], char data_buff[], uint16_t packet_array_len, char *src_ip, char *dest_ip);

void get_transport_packet_host_ready(struct iovec iov[3]);

void get_transport_packet_wire_ready(struct iovec iov[3]);

uint16_t send_oob_data(int socket, char oob_char);


uint16_t send_packet_collection(int socket, uint16_t num_packets, Packet packets[], int failed_packet_seq[PACKET_SIZE]);

void sigalrm_handler();

#endif //UNIXCUSTOMTRANSPORTLAYER_DUSTYNS_TRANSPORT_LAYER_H
