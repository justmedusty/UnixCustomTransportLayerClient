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
char oob_data;

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

    /*
     * We're going to clear this memory space and set 0s across the board
     * to avoid any funny business.
     */
    memset(packet->iov[0].iov_base, 0, sizeof(struct iphdr));
    memset(packet->iov[1].iov_base, 0, HEADER_SIZE);
    memset(packet->iov[2].iov_base, 0, PAYLOAD_SIZE);


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
 * pre-allocated, initialized packet array and fill an array with packet data. We will break everything
 * down into packets of PAYLOAD_SIZE to a maximum number of packets MAX_PACKET_COLLECTION, sequence them properly,
 * include proper message size, provide a checksum for the data, fill in the layer 3 header.
 *
 */
uint16_t
packetize_data(Packet packet[], char data_buff[], uint16_t packet_array_len, uint32_t src_ip, uint32_t dest_ip) {

    //Check they are not passing a packet array larger than the max
    if (packet_array_len > MAX_PACKET_COLLECTION) {
        return ERROR;
    }
    //Init to error code so we know something went wrong if it returns with this value
    uint16_t packets_filled = ERROR;

    //Getting the length of the buffer we are going to packetize
    size_t source_length = strlen(data_buff);

    //This will track how many bytes we have left to packetize
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
 *
 *
 *
 * The alarm handler. I am not sure if I am going to keep this as is. You can't really pass args to sig handlers so I will need to think about
 * how I want to handle this as I get closer to a full implementation of my protocol.
 */
void reset_timeout() {
    alarm(0);
}

void sigalrm_handler() {
    num_timeouts++;
    uint16_t timeout = INITIAL_TIMEOUT;
    for (int i = 0; i < num_timeouts; i++) {
        timeout *= 2;
    }
    if (timeout > MAX_TIMEOUT) {
        fprintf(stderr, "Max timeout reached\n");
        exit(EXIT_FAILURE);
    } else {
        set_packet_timeout();
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
 * It will return either 0 or 65535, checksum good, or checksum not good.
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

uint16_t handle_ack(int socket, Packet *packets, uint32_t src_ip, uint32_t dest_ip) {

    bool sequence_received[MAX_PACKET_COLLECTION + 1] = {false}; // Initialize all to false
    int last_received = -1;
    int missing_packets = 0;
    int highest_packet_received;

    // Iterate through each packet in the collection
    for (int i = 0; i < MAX_PACKET_COLLECTION; ++i) {
        Packet *packet = &packets[i];

        if (packet == NULL) break;

        struct iphdr ip_hdr = *(struct iphdr *) packet->iov[0].iov_base;

        if (ip_hdr.saddr != src_ip) {
            continue;
        }

        Header *header = (Header *) packet->iov[1].iov_base;

        sequence_received[header->sequence] = true;

        last_received = header->sequence;

        highest_packet_received = last_received;
    }

    // Check for missing packets and send RESEND if needed
    for (int i = 0; i <= last_received; ++i) {
        if (!sequence_received[i]) {
            // Packet with sequence i is missing, send RESEND
            send_resend(socket, i, src_ip, dest_ip);
            missing_packets += 1;
        }
    }
    if (missing_packets > 0) {

        return missing_packets;

    } else {

        if (send_ack(socket, highest_packet_received, src_ip, dest_ip) != SUCCESS) {
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
uint16_t send_ack(int socket, uint16_t max_sequence, uint32_t src, uint32_t dest) {

    Packet packet;

    allocate_packet(&packet);

    struct iphdr ip_hdr;

    Header header = {
            ACKNOWLEDGE,
            0,
            max_sequence,
            0,
            0
    };

    fill_ip_header(&ip_hdr, src, dest);
    packet.iov[0].iov_base = &ip_hdr;
    packet.iov[1].iov_base = &header;

    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = packet.iov;
    message.msg_iovlen = 2;

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
uint16_t send_resend(int socket, uint16_t sequence, uint32_t src_ip, uint32_t dst_ip) {

    Packet packet;

    allocate_packet(&packet);

    Header header = {
            RESEND,
            0,
            sequence,
            0,
            ERROR
    };
    struct iphdr ip_hdr;
    fill_ip_header(&ip_hdr, src_ip, dst_ip);
    packet.iov[0].iov_base = &ip_hdr;
    packet.iov[1].iov_base = &header;

    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = packet.iov;
    message.msg_iovlen = 2;

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

uint16_t handle_corruption(int socket, uint32_t src_ip, uint32_t dst_ip, uint16_t sequence) {

    Packet packet;

    allocate_packet(&packet);

    struct iphdr ip_hdr;

    Header header = {
            CORRUPTION,
            0,
            sequence,
            0,
            ERROR
    };

    fill_ip_header(&ip_hdr, src_ip, dst_ip);

    packet.iov[0].iov_base = &ip_hdr;
    packet.iov[1].iov_base = &header;


    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = packet.iov;
    message.msg_iovlen = 1;

    ssize_t bytes_sent = sendmsg(socket, &message, 0);
    if (bytes_sent < 0) {
        free_packet(&packet);
        return ERROR;
    } else {
        return header.sequence;
    }
}

/*
 * This function is for resending packets that were either never delivered or corrupted along the way.
 * We will just go through the array of bad seq numbers and we will resend the specified packets.
 *
 *
 * We will need to store the sequence of missing packets inside an array as we receive them
 * if one cannot be sent return the first seq num of the packet that cannot be
 * sent.
 */

uint16_t send_missing_packets(int socket, uint16_t *sequence[], uint16_t num_packets, Packet *packet_collection) {


    for (int i = 0; i < num_packets; i++) {

        Header header;
        header = *((Header *) packet_collection[*sequence[i]].iov[1].iov_base);
        header.status = SECOND_SEND;
        packet_collection[*sequence[i]].iov[1].iov_base = &header;
        struct msghdr message;
        memset(&message, 0, sizeof(message));
        message.msg_iov = packet_collection[*sequence[i]].iov;
        message.msg_iovlen = 3;

        ssize_t bytes_sent = sendmsg(socket, &message, 0);

        if (bytes_sent < 0) {
            return *sequence[i];
        } else {
            continue;
        }
    }
    return SUCCESS;
}

/*
 * This function will send out of band data , which is akin to a network interrupt if you will. We will
 * allow 1 byte of OOB data to be send, could be some kind of escape or abort signal. OOB data is supposed to skip the queue
 * and come off the wire and be processed before anything else.
 */
uint16_t send_oob_data(int socket, char oob_char, uint32_t src_ip, uint32_t dst_ip) {

    Packet packet;
    allocate_packet(&packet);
    struct iphdr ip_hdr;
    Header header = {
            OOB,
            0,
            0,
            OUT_OF_BAND_DATA_SIZE,
            ERROR
    };

    fill_ip_header(&ip_hdr, src_ip, dst_ip);

    packet.iov[0].iov_base = &ip_hdr;
    packet.iov[1].iov_base = &header;
    packet.iov[2].iov_base = &oob_char;
    packet.iov[2].iov_len = OUT_OF_BAND_DATA_SIZE;

    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = packet.iov;
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
uint16_t handle_close(int socket, uint32_t src_ip, uint32_t dst_ip) {

    Packet packet;
    allocate_packet(&packet);
    struct iphdr ip_hdr;

    Header header = {
            CLOSE,
            0,
            0,
            0,
            ERROR
    };


    fill_ip_header(&ip_hdr, src_ip, dst_ip);

    packet.iov[0].iov_base = &ip_hdr;
    packet.iov[1].iov_base = &header;

    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = packet.iov;
    message.msg_iovlen = 2;

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
 *
 * I may not even use these but I'll keep around until I come to a final decision.
 *
 * (probably gonna toss these)
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
 *
 * Once this is done it will fill your failed pack seq array with the seq numbers of the packets that didn't send and you can decide what to do from
 * there.
 */


uint16_t
send_packet_collection(int socket, uint16_t num_packets, Packet packets[], uint16_t failed_packet_seq[PACKET_SIZE]) {

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
 * This function will be a packet receiver. I may run this in a separate thread or process but I am not sure yet.
 *It will fill the list of packets passed to it and will also handle the different types of header status' that may come up.
 * Example, should it find an ACK, the timer will be reset, should it find a corruption or a resend, it will add that packet sequence to the passed list.
 * Should it find a close, it will close the socket and return etc.
 *
 * We will handle each packet type here. If Packet type is OOB we will immediately send a sigint signal. This will exit immediately and go to our
 * interrupt handler which will be used to process the oob data separately.
 *
 * If CLOSE, we will close the socket and reset the timeout.
 *
 * On corruption or resend we will fill the memory space passed to us with the seq numbers of the missing packets
 *
 * On ACK we'll return so the server can respond to packet group
 *
 * On DATA or SECOND_SEND we will verify the checksum and if good, add to the array
 * if not good, send a corruption notice and continue
 *
 *
 */

uint16_t receive_data_packets(Packet *receiving_packet_list, int socket, uint16_t *packets_to_resend, uint32_t src_ip,
                              uint32_t dst_ip) {

    memset(packets_to_resend, 0, MAX_PACKET_COLLECTION);
    int i = 0;
    memset(receiving_packet_list, 0, MAX_PACKET_COLLECTION);
    struct msghdr msg;
    struct iphdr *ip_hdr;
    Header *head;
    uint16_t return_value = ERROR;
    int bad_packets = 0;
    int packets_received = 0;


    while (recvmsg(socket, &msg, 0) != 0) {

        ip_hdr = receiving_packet_list[i].iov[0].iov_base;
        if (ip_hdr->saddr != src_ip) {
            continue;
        }
        head = receiving_packet_list[i].iov[1].iov_base;
        char data[head->msg_size];

        if (head->packet_end == head->sequence &&
            (return_value = handle_ack(socket, receiving_packet_list, src_ip, dst_ip)) == SUCCESS) {
            receiving_packet_list[i] = *(Packet *) &msg;
            return SUCCESS;
        } else {
            if (return_value == ERROR) {
                return ERROR;
            }

            switch (head->status) {
                /*
                 * We'll send an interrupt signal when OOB data is discovered
                 */
                case OOB:
                    oob_data = data[0];
                    raise(SIGINT);
                    break;

                case CLOSE:
                    close(socket);
                    reset_timeout();
                    return CLOSE;

                case CORRUPTION :
                    packets_to_resend[++bad_packets] = head->sequence;
                    bad_packets++;
                    break;


                case RESEND :
                    packets_to_resend[++bad_packets] = head->sequence;
                    bad_packets++;
                    break;


                case ACKNOWLEDGE:
                    reset_timeout();
                    return RECEIVED_ACK;


                case SECOND_SEND :
                    if (compare_checksum(data, head->msg_size, head->checksum) != SUCCESS) {
                        memset(&receiving_packet_list[head->sequence], 0, sizeof(Packet));
                        handle_corruption(socket, src_ip, dst_ip, head->sequence);
                    } else {
                        receiving_packet_list[head->sequence].iov[2].iov_base = data;
                    }
                    break;

                case DATA:
                    if (compare_checksum(data, head->msg_size, head->checksum) != SUCCESS) {
                        memset(&receiving_packet_list[head->sequence], 0, sizeof(Packet));
                        handle_corruption(socket, src_ip, dst_ip, head->sequence);
                    } else {
                        receiving_packet_list[head->sequence].iov[2].iov_base = data;
                    }

                    break;

            }
        }
        packets_received++;
    }


    return packets_received;
}


/*
 * When OOB data is handled, we want to send an interrupt which will then immediately go to this handler and start processing the OOB data.
 * I'll just keep this one check for now I will decide what I want to do with this later.
 */
void sig_int_handler() {

    if (oob_data == ']') {
        exit(EXIT_SUCCESS);
    } else {
        exit(EXIT_FAILURE);
    }

}

/*
 * This is our conn handler function; since we are using raw sockets, there is no transport layer. WE are the transport layer. We will do
 * some basic headers to get some metadata about the incoming messages. There will be no retransmission automatically this is all done by the
 * transport layer. We can implement our own logic to resend messages after a specific timeout time, however, for this we will keep it simple.
 * We will just tack some basic metadata like message size / message length. We could even do some kind of checksum. We can implement a basic
 * checksum with a simple bitwise XOR operation.
 *
 * If you do not remember, the bitwise XOR will compare 2 bits, let's say 0 and 1, and will return 1 if they were different, and 0 if they are the same.
 * This will handle basic data corruption. It, of course, is not foolproof, but it is very simple and very lightweight.
 *
 *
 *
 */
void handle_server_connection(int socket, uint32_t src_ip, uint32_t dest_ip) {
    Packet packets[MAX_PACKET_COLLECTION];
    Packet received_packets[MAX_PACKET_COLLECTION];

    signal(SIGINT, sig_int_handler);
    signal(SIGALRM, sigalrm_handler);
    uint16_t failed_packet_seq[MAX_PACKET_COLLECTION];
    char message_buffer[4096];
    uint16_t packets_received;
    uint16_t packets_filled;
    uint16_t failed_packets;


    while (true) {

        memset(message_buffer,0,4096);
        memset(&failed_packet_seq, 0, MAX_PACKET_COLLECTION);

        packets_received = receive_data_packets(received_packets, socket, failed_packet_seq, src_ip, dest_ip);
        if (packets_received == ERROR) {
            fprintf(stderr, "Error occurred while receiving packets.\n");
            break;
        }

        printf("Success!");

        fgets(message_buffer, PAYLOAD_SIZE, 0);

        if(strcmp(&message_buffer[0],"]")){
            send_oob_data(socket,']',src_ip,dest_ip);
        }

        packets_filled = packetize_data(packets, message_buffer, MAX_PACKET_COLLECTION, src_ip, dest_ip);

        if(packets_filled == ERROR){
            fprintf(stderr,"Error occurred packetizing data\n");
            break;
        }

        failed_packets = send_packet_collection(socket, packets_received, received_packets, failed_packet_seq);
        if (failed_packets != SUCCESS) {
            fprintf(stderr, "Error occurred while sending echoed packets.\n");
            break;
        }

    }

    if (handle_close(socket, src_ip, dest_ip) == ERROR) {
        fprintf(stderr, "Error occurred while handling connection close.\n");
    }

    // Clean up allocated memory
    for (int i = 0; i < MAX_PACKET_COLLECTION; i++) {
        free_packet(&packets[i]);
        free_packet(&received_packets[i]);
    }

    // Close the socket
    close(socket);
    exit(EXIT_SUCCESS);
}