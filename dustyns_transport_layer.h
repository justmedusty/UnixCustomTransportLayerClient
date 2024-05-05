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
#include <signal.h>


#ifndef UNIXCUSTOMTRANSPORTLAYER_DUSTYNS_TRANSPORT_LAYER_H
#define UNIXCUSTOMTRANSPORTLAYER_DUSTYNS_TRANSPORT_LAYER_H

#define BACKLOG 15
#define PAYLOAD_SIZE 512
#define HEADER_SIZE 12
#define PACKET_SIZE ((sizeof (struct iphdr) + HEADER_SIZE + PAYLOAD_SIZE))
#define MAX_PACKET_COLLECTION 1000
#define OUT_OF_BAND_DATA_SIZE 1
#define DATA 1
#define ACKNOWLEDGE 2
#define CORRUPTION 3
#define RESEND 4
#define CLOSE 5
#define OOB 6
#define SECOND_SEND 7
#define NO_BUFFER_SPACE 50000
#define INITIAL_TIMEOUT 15
#define MAX_TIMEOUT 160
#define SUCCESS 0
#define RECEIVED_ACK 6969
//This because they're all unsigned 16 bits,
// so this makes more sense than using 1 since if 1 packet was missing, for example, it would also return 1.
// 65536 would never come up so this makes more sense as the error code.
#define ERROR 65535


typedef struct Packet {
    struct iovec iov[3];
} Packet;


typedef struct Header {
    uint16_t status;
    uint16_t checksum;
    uint16_t sequence;
    uint16_t msg_size;
    uint16_t dest_process_id;
    /*
     * This will mark the last packet in the stream, it will let us know when to stop processing this set of packets.
     */
    uint16_t packet_end;

} Header;

uint16_t handle_ack(int socket, Packet *packets[], uint32_t src_ip, uint32_t dest_ip, uint16_t pid);

uint16_t allocate_packet(Packet *packet_ptr[]);

uint16_t free_packet(Packet *packet);

uint8_t compare_checksum(char data[], size_t length, uint16_t received_checksum);

uint16_t calculate_checksum(char data[], size_t length);

void handle_client_connection(int socket, uint32_t src_ip, uint32_t dest_ip, uint16_t pid);

uint16_t send_resend(int socket, uint16_t sequence, uint32_t src_ip, uint32_t dst_ip, uint16_t pid);

uint16_t send_ack(int socket, uint16_t max_sequence, uint32_t src, uint32_t dest, uint16_t pid);

uint16_t handle_close(int socket, uint32_t src_ip, uint32_t dst_ip, uint16_t pid);

void sig_int_handler();

uint16_t handle_corruption(int socket, uint32_t src_ip, uint32_t dst_ip, uint16_t sequence, uint16_t pid);

uint16_t set_packet_timeout();

void reset_timeout();

uint16_t packetize_data(Packet *packet[], char data_buff[], uint16_t packet_array_len, uint32_t src_ip, uint32_t dest_ip,uint16_t pid);
void get_transport_packet_host_ready(struct iovec iov[3]);

uint16_t send_oob_data(int socket, char oob_char, uint32_t src_ip, uint32_t dst_ip, uint16_t pid);

uint16_t receive_data_packets(Packet *packet_list[],Packet *receiving_packet_list[], int socket, uint16_t *packets_to_resend, uint32_t src_ip,uint32_t dst_ip, uint16_t pid,uint16_t *status);


uint16_t send_missing_packet(int socket, Packet *packet,uint16_t pid);
void sigalrm_handler();

uint16_t send_packet_collection(int socket, uint16_t num_packets, Packet *packets[], uint16_t failed_packet_seq[PACKET_SIZE],uint16_t pid, uint32_t src_ip, uint32_t dest_ip);

uint16_t dump_packet_collection_payload_into_buffer(Packet *packet[], char data_buff[], uint64_t buff_size,uint16_t packet_array_len);

void get_transport_packet_wire_ready(struct iovec *iov);
#endif //UNIXCUSTOMTRANSPORTLAYER_DUSTYNS_TRANSPORT_LAYER_H
