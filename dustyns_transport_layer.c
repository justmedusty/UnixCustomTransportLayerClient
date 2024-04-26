//
// Created by dustyn on 4/22/24.
//

#include <stdbool.h>
#include "dustyns_transport_layer.h"
#include "network_layer.h"

/*
 * Raw sockets are a powerful feature in UNIX. Raw sockets remove the kernels' implementation
 * of the transport layer protocols from the equation, and what you end up with is your own transport
 * layer playground. Using IPPROTO_RAW also allows us to interact with layer 3 directly. Because we will be handling the entire transport layer, we will use sendmsg and recvmsg instead of our usual send/recv.
 * sendmsg and recvmsg alongside a msgheader structure. Because we will be working with the network layer directly here,
 * we will need to pass message metadata in headers such as its size and maybe some kind of packet identifier for acknowledgement
 * from the receiver. We will go through this together.
 *
 * The network layers purpose is getting a packet from point A to point B, ensuring there wasn't any data corruption or
 * the like will be up to us. We can implement some basic checks and balances.
*/



/*
 * Allocate a packet on the heap, being sure to allocate both io vectors inside the packet as well
 * We need to do a standard null check to ensure that allocation is not returning a null pointer
 */

uint16_t num_timeouts;

uint16_t allocate_packet(Packet *packet) {
    packet = malloc(sizeof(Packet));

    if (packet == NULL) {
        perror("malloc");
        return ERROR;
    }
    packet->iov[0].iov_base = malloc(sizeof(struct iphdr));
    packet->iov[0].iov_len = sizeof(struct iphdr);
    packet->iov[1].iov_base = malloc(HEADER_SIZE);
    packet->iov[1].iov_len = HEADER_SIZE;
    packet->iov[2].iov_base = malloc(PAYLOAD_SIZE);
    packet->iov[2].iov_len = PAYLOAD_SIZE;


    if (packet->iov[0].iov_base == NULL || packet->iov[1].iov_base == NULL || packet->iov[2].iov_base == NULL) {
        perror("malloc");
        free_packet(packet);
        return ERROR;
    }

    return SUCCESS;

}

/*
 * Free packet from heap memory, check that it is not null to avoid dereferencing a null pointer, set each packet to null afterwards
 * to make sure there are no double frees.
 */
uint16_t free_packet(Packet *packet) {
    if (packet == NULL) {
        return ERROR;
    }
    if (packet->iov[0].iov_base != NULL) {
        free(packet->iov[0].iov_base);
        packet->iov[0].iov_base = NULL;
    }

    if (packet->iov[1].iov_base != NULL) {
        free(packet->iov[1].iov_base);
        packet->iov[1].iov_base = NULL;
    }

    if (packet->iov[2].iov_base != NULL) {
        free(packet->iov[2].iov_base);
        packet->iov[2].iov_base = NULL;
    }

    free(packet);
    return SUCCESS;
}

/*
 * I'm making up words here I know, deal with it. this will take your data buffer and your
 * preallocated, initialized packet array and fill an array with packet data. We will break everything
 * down into packets of PAYLOAD_SIZE to a maximum amount of packets MAX_PACKET_COLLECTION, sequence them properly,
 * include proper message size, provide a checksum for the data, fill in the layer 3 header.
 */
uint16_t packetize_data(Packet packet[], char data_buff[], uint16_t packet_array_len, char *src_ip, char *dest_ip) {

    //Check they are not passing a packet array larger than the max
    if (packet_array_len > MAX_PACKET_COLLECTION) {
        return ERROR;
    }
    //Init to error code so we know something went wrong if it returns with this value
    uint16_t packets_filled = ERROR;

    //Getting the length of the buffer we are going to packet-ize
    size_t source_length = strlen(data_buff);

    //This will track how many bytes we have left to packet-ize
    size_t remaining_bytes = source_length;

    /*
     * A loop for iterating through each packet and filling the ip header,
     * the transport header, the transport data, all the while we will set the packets_filled each time to the new number of packets filled
     */
    for (int i = 0; i < packet_array_len; ++i) {

        char packet_buff[PAYLOAD_SIZE];

        size_t bytes_copied;
        fill_ip_header(packet->iov[0].iov_base, src_ip, dest_ip);

        /*  Calculate the number of bytes to copy into this packet.
            If the remaining bytes to copy (remaining_bytes) is greater than the size of the payload buffer (PAYLOAD_SIZE),
            set bytes_to_copy to PAYLOAD_SIZE, indicating that a full payload buffer is copied.
            Otherwise, set bytes_to_copy to the remaining_bytes, ensuring that only the remaining data is copied into the payload buffer.
        */

        size_t bytes_to_copy = remaining_bytes > PAYLOAD_SIZE ? PAYLOAD_SIZE : remaining_bytes;

        memcpy(packet_buff, data_buff + (source_length - remaining_bytes), bytes_to_copy);

        memcpy(packet[i].iov[2].iov_base, packet_buff, bytes_to_copy);

        remaining_bytes -= bytes_to_copy;

        Header header = {
                DATA,
                calculate_checksum(packet[i].iov[2].iov_base, bytes_to_copy),
                i,
                sizeof bytes_to_copy
        };


        packet[i].iov[1].iov_base = &header;


        packets_filled = i;


    }
    return packets_filled;

}

/*
 * This will set the alarm for a packet timeout
 * A custom timer is allowed, however, the default will be
 * the value of the TIMEOUT macro. This will set an alarm
 * and if the system does not receive an ack in the given
 * timeframe, a sigalrm will be sent by the kernel to alert us
 * We can implement exponential back off as well.
 * Exponential backoff means each timeout we double the timeout
 * period. This can be useful to conserve resources and ensure any issues are resolved.
 * If not we will abort the sending of this packet set.
 *
 * Exponential backoff is a method to ensure we are not being too
 * aggressive and allowing time for any network issues to pass
 * This can relieve issues such as bogging the network / congestion.
 */
uint16_t set_packet_timeout() {


    if (num_timeouts == 0) {
        alarm(INITIAL_TIMEOUT);
        return INITIAL_TIMEOUT;
    } else {
        uint16_t timeout_value = (INITIAL_TIMEOUT);

        for (int i = 0; i < num_timeouts; ++i) {
            timeout_value *= 2;
        }

        if (timeout_value < MAX_TIMEOUT) {
            alarm(timeout_value);
            return timeout_value;
        } else {
            return ERROR;
        }

    }
}


/*
 * This function simply resets the alarm once we have received an ACK on the series of packets we just sent.
 * We will also need a signal handler to handle
 */
void reset_timeout() {
    alarm(0);
}

void sigalrm_handler() {

    uint16_t timeout = INITIAL_TIMEOUT;
    for (int i = 0; i < num_timeouts; i++) {
        timeout *= 2;
    }
    if (timeout > MAX_TIMEOUT) {
        fprintf(stderr, "Max timeout reached\n");
        exit(EXIT_FAILURE);
    } else {
        set_packet_timeout(0, num_timeouts);
    }


}


/*
 * This will be our checksum function, it is going to iterate through bytes in the data and bitwise XOR them.
 * This means that if the bit matches, 0 is returned.
 * A non-zero value on verification indicates that bits have changed.
 * This is a simple way to implement a checksum in our home-grown transport layer.
 *
 * Visual Example:
 *
 * XORd checksum = 1001 0101
 * Received Data = 1011 0101
 * Result would  = 0010 0000
 *
 * The result is not 0
 * The data has changed
 *
 * Nice and simple, we like that around here
 */

uint16_t calculate_checksum(char *data[], size_t length) {

    uint16_t checksum = 0;

    for (size_t i = 0; i < length; i++) {
        char *byte = data[i];
        checksum ^= *byte;
    }
    return checksum;
}

/*
 * Here will be a function for verifying the checksum when we receive one in a client header message
 * It will return either 0 or -1, checksum good, or checksum not good.
 */

uint8_t compare_checksum(char data[], size_t length, uint16_t received_checksum) {

    uint16_t new_checksum = calculate_checksum(&data, length);
    if ((new_checksum ^ received_checksum) != 0) {
        return (uint8_t) ERROR;
    } else {
        return (uint8_t) SUCCESS;
    }
}

/*
 * This will inspect an array of packets and make sure that we have all the sequencing correct.
 * Also sending out RESEND messages to the other side with the packet sequence number that will need to be sent back.
 */

uint16_t handle_ack(int socket, Packet *packets) {
    bool sequence_received[MAX_PACKET_COLLECTION + 1] = {false}; // Initialize all to false
    int last_received = -1;
    int missing_packets = 0;
    int highest_packet_received;

    // Iterate through each packet in the collection
    for (int i = 0; i < MAX_PACKET_COLLECTION; ++i) {
        Packet *packet = &packets[i];

        if (packet == NULL) break;

        struct iphdr ip_hdr = *(struct iphdr * ) packet->iov[0].iov_base;

        Header *header = (Header *) packet->iov[1].iov_base;

        sequence_received[header->sequence] = true;

        last_received = header->sequence;

        highest_packet_received = last_received;
    }

    // Check for missing packets and send RESEND if needed
    for (int i = 0; i <= last_received; ++i) {
        if (!sequence_received[i]) {
            // Packet with sequence i is missing, send RESEND
            send_resend(socket, i);
            missing_packets += 1;
        }
    }
    if (missing_packets > 0) {

        return missing_packets;

    } else {

        if (send_ack(socket, highest_packet_received) != SUCCESS) {
            return ERROR;
        }

        reset_timeout();
        return SUCCESS;

    }
}

/*
 * This function is for when a set of packets has been checked properly and an acknowledge can be sent.
 * Send the acknowledge message to the client side., return SUCCESS or ERROR depending on return value of sendmsg() call
 */
uint16_t send_ack(int socket, uint16_t max_sequence) {
    Header header = {
            ACKNOWLEDGE,
            0,
            max_sequence,
            0
    };
    struct iovec iov;
    iov.iov_base = &header;
    iov.iov_len = sizeof header;

    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;

    ssize_t bytes_sent = sendmsg(socket, &message, 0);

    if (bytes_sent < 0) {
        return ERROR;
    } else {
        return SUCCESS;
    }

}

/*
 *  This function handles sending RESEND packets which will have no body just a header with the RESEND status, and the seq number of the missing packet
 *  Returns the seq number on success and ERROR otherwise.
 */
uint16_t send_resend(int socket, uint16_t sequence) {
    Header header = {
            RESEND,
            0,
            sequence
    };
    struct iovec iov;
    iov.iov_base = &header;
    iov.iov_len = sizeof header;

    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;

    ssize_t bytes_sent = sendmsg(socket, &message, 0);

    if (bytes_sent < 0) {
        return ERROR;
    } else {
        return header.sequence;
    }

}

/*
 * If we notice a bad payload via XORing and comparing with the checksum, we want to fire off a packet with the status
 * CORRUPTION.
 * The client raw socket will check for and then read the sequence from that header, and if there is a CORRUPTION
 * header, then the client will read the sequence and resend that packet
 */

uint16_t handle_corruption(int socket, struct Header *head) {

    Header header = {
            CORRUPTION,
            0,
            head->sequence
    };
    struct iovec iov;
    iov.iov_base = &header;
    iov.iov_len = sizeof header;

    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;

    ssize_t bytes_sent = sendmsg(socket, &message, 0);
    if (bytes_sent < 0) {
        return ERROR;
    } else {
        return header.sequence;
    }
}

/*
 * This function will send out of band data , which is akin to a network interrupt if you will. We will
 * allow 1 byte of OOB data to be send, could be some kind of escape or abort signal. OOB data is supposed to skip the queue
 * and come off the wire and be processed before anything else.
 */
uint16_t send_oob_data(int socket, char oob_char) {

    Header header = {
            OOB,
            0,
            0,
            OUT_OF_BAND_DATA_SIZE,
    };

    struct iovec iov;
    iov.iov_base = &header;
    iov.iov_len = sizeof header;
    iov.iov_base = &oob_char;
    iov.iov_len = OUT_OF_BAND_DATA_SIZE;

    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 2;

    ssize_t bytes_sent = sendmsg(socket, &message, 0);
    if (bytes_sent < 0) {
        return ERROR;

    } else {
        return SUCCESS;
    }
}


/*
 * Function to handle sending a connection closed message to the client side of the conn.
 * This will be used to let the other side of the association know that the connection
 * is being closed so it can close the connection and clean up.
 */
uint16_t handle_close(int socket) {

    Header header = {
            CLOSE,
            0,
            0,
            0
    };

    struct iovec iov;
    iov.iov_base = &header;
    iov.iov_len = sizeof header;

    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;

    ssize_t bytes_sent = sendmsg(socket, &message, 0);
    if (bytes_sent < 0) {
        return ERROR;
    } else {
        return SUCCESS;
    }
}


/*
 * These two functions will swap the endianness coming on and coming off the wire.
 * The network byte order is big endian, so this is standard practice.
 */

void get_transport_packet_wire_ready(struct iovec iov[3]) {

    Header *header = (Header *) iov[1].iov_base;
    header->sequence = htons(header->sequence);
    header->checksum = htons(header->checksum);
    header->msg_size = htons(header->msg_size);

    iov[1].iov_base = header;


}


void get_transport_packet_host_ready(struct iovec iov[3]) {

    Header *header = (Header *) iov[1].iov_base;
    header->sequence = ntohs(header->sequence);
    header->checksum = ntohs(header->checksum);
    header->msg_size = ntohs(header->msg_size);

    iov[1].iov_base = header;


}

/*
 * This function will send an array of packets 1 by one once they have been set up properly. It will log how many failed packets there were.
 * so we can know what to expect. We will get a resend from the otherside of the association once the packets have been rounded up and counted.
 * On send we will start a timer based on the current number of timeouts.
 *
 * Remember, we are using exponential backoff. Every timeout with the same packet set, we double the timeout length.
 */


uint16_t send_packet_collection(int socket, uint16_t num_packets, Packet packets[],
                                int failed_packet_seq[PACKET_SIZE]) {

    memset(failed_packet_seq, 0, PACKET_SIZE);
    int failed_packets = 0;
    for (int i = 0; i < num_packets; i++) {
        struct msghdr msg_hdr;
        memset(&msg_hdr, 0, sizeof(msg_hdr));

        // Populate msghdr
        msg_hdr.msg_iov = packets[i].iov;
        msg_hdr.msg_iovlen = 3; // Number of iovs
        if (sendmsg(socket, &msg_hdr, 0) == -1) {
            failed_packets++;
            /*
             * We want to be able to go through after and resend.
             * This will take the array in memory that was passed
             * by reference and put the seq # of failed packets in there
             */
            failed_packet_seq[failed_packets - 1] = i;
        }
    }
    set_packet_timeout();

    return failed_packets;

}

/*
 * This is our conn handler function; since we are using raw sockets, there is no transport layer. WE are the transport layer. We will do
 * some basic headers to get some metadata about the incoming messages. There will be no retransmission automatically this is all done by the
 * transport layer. We can implement our own logic to resend messages after a specific timeout time, however for this we will keep it simple.
 * We will just tack some basic metadata like message size / message length. We could even do some kind of checksum. We can implement a basic
 * checksum with a simple bitwise XOR operation.
 *
 * If you do not remember, the bitwise XOR will compare 2 bits, let's say 0 and 1, and will return 1 if they were different, and 0 if they are the same.
 * This will handle basic data corruption. It, of course, is not foolproof, but it is very simple and very lightweight.
 *
 *
 *
 */
void handle_client_connection(int socket, char src_ip[], char dest_ip[]) {

    Packet packet[MAX_PACKET_COLLECTION];
    Packet received_packets[MAX_PACKET_COLLECTION];

    for (int i = 0; i < MAX_PACKET_COLLECTION; i++) {
        uint16_t result;
        result = allocate_packet(&packet[i]);
        if(result == ERROR){
            fprintf(stderr,"Error allocing packet %d\n",i);
            exit(EXIT_FAILURE);
        }
        result = allocate_packet(&received_packets[i]);
        if(result == ERROR){
            fprintf(stderr,"Error allocing received packet %d\n",i);
            exit(EXIT_FAILURE);
        }
    }
    int failed_packet_seq[PACKET_SIZE];


    const char welcome_msg[] = "Welcome to the raw socket server, we are building our own transport layer on top of the IP/network layer of the OSI!";
    uint16_t packets_filled = packetize_data(packet, (char *) welcome_msg, 1, src_ip, dest_ip);
    printf("packets_filled");
    if (packets_filled == ERROR) {
        fprintf(stderr, "Error occurred while packetizing data.\n");
        for (int i = 0; i < MAX_PACKET_COLLECTION; i++) {
            free_packet(&packet[i]);
            free_packet(&received_packets[i]);
        }
        return;
    }

    uint16_t failed_packets;
    signal(SIGALRM, sigalrm_handler);

    while (true) {
        failed_packets = send_packet_collection(socket, packets_filled, packet, failed_packet_seq);
        if (failed_packets == 0) {
            // All packets sent successfully
            break;
        } else if (failed_packets == ERROR) {
            fprintf(stderr, "Error occurred while sending packets.\n");
            for (int i = 0; i < MAX_PACKET_COLLECTION; i++) {
                free_packet(&packet[i]);
                free_packet(&received_packets[i]);
            }
            return;
        } else {
            num_timeouts++;
            if (num_timeouts > 3) {
                fprintf(stderr, "Maximum number of timeouts reached. Exiting.\n");
                for (int i = 0; i < MAX_PACKET_COLLECTION; i++) {
                    free_packet(&packet[i]);
                    free_packet(&received_packets[i]);
                }
                return;
            }
        }
    }

    // Wait for acknowledgment
    if (handle_ack(socket, packet) == ERROR) {
        fprintf(stderr, "Error occurred while handling acknowledgment.\n");
        for (int i = 0; i < MAX_PACKET_COLLECTION; i++) {
            free_packet(&packet[i]);
            free_packet(&received_packets[i]);
        }
        return;
    }

    // Close the connection
    if (handle_close(socket) == ERROR) {
        fprintf(stderr, "Error occurred while handling connection close.\n");
        for (int i = 0; i < MAX_PACKET_COLLECTION; i++) {
            free_packet(&packet[i]);
            free_packet(&received_packets[i]);
            close(socket);
        }
        return;
    }

    for (int i = 0; i < MAX_PACKET_COLLECTION; i++) {
        free_packet(&packet[i]);
        free_packet(&received_packets[i]);
    }

    exit(EXIT_SUCCESS);

}