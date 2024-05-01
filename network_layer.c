
#include "network_layer.h"



/*
 * This is a standard algorithm for IP checksums.
 * We will use to verify layer 3 headers to ensure
 * that the IP header has not been corrupted during
 * transport.If it is no good, the packet will be thrown out.
 */


unsigned short checksum(void *b, int len) {
    // Cast the input pointer to an unsigned short pointer
    unsigned short *buf = b;

    // Initialize the sum variable
    unsigned int sum = 0;

    // Declare a variable to hold the checksum result
    unsigned short result;

    // Iterate over the data buffer, summing up 16-bit words
    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++; // Add the value pointed to by buf to sum, then move buf to the next 16-bit word
    }

    // If the length is odd, add the last byte separately
    if (len == 1) {
        sum += *(unsigned char*)buf; // Add the value of the last byte to sum
    }

    // Add any carry bits to the lower 16 bits of sum
    sum = (sum >> 16) + (sum & 0xFFFF);

    // Add carry from the addition above to the lower 16 bits of sum
    sum += (sum >> 16);

    // Take the one's complement of sum to obtain the checksum result
    result = ~sum;

    // Return the checksum result
    return result;
}

/*
 * Since we are using IPPROTO_RAW, we will need to fill out IP headers ourselves here.
 * We will need to do our own checksums as well. We need to specify the source ip, the dest ip,
 * the ttl, the version, the packet size, everything!
 *
 * In the end, we will fill in our ip_header checksum for verification of the IP header at layer 3.
 */

uint16_t fill_ip_header(struct iphdr *ip_header, uint32_t src_ip, uint32_t dst_ip) {

    ip_header->ihl = 5; // Header length (in 32-bit words)
    ip_header->version = 4; // IPv4
    ip_header->check = 0; //set checksum to 0 first
    ip_header->tos = 0; // Type of service
    ip_header->tot_len = htons(PACKET_SIZE); // Total length of the packet
    ip_header->id = htons(12345); // Identification
    ip_header->frag_off = 0; // Fragmentation offset
    ip_header->ttl = 64; // Time to live
    ip_header->protocol = IPPROTO_RAW; // Protocol
    ip_header->check = 0; // Checksum (0 for now, will be calculated later)
    ip_header->saddr = src_ip; // Source IP address
    ip_header->daddr = dst_ip; // Destination IP address

    if(ip_header->saddr == INADDR_ANY|| ip_header->daddr == INADDR_ANY ){
        perror("inet_addr");
        return ERROR;
    }

    ip_header->check = checksum(ip_header, sizeof(struct iphdr));

    //get_ip_header_wire_ready(ip_header);

    return SUCCESS;


}
/*
 * We will need to go through each member and flip the endianness to big endian since this is
 * the wire format. We will need to convert the endianness before transmission of a packet and after receiving one
 * You could skip this step, however, it would affect portability.
 */
uint16_t get_ip_header_wire_ready(struct iphdr (*ip_header)){

    ip_header->ihl = htonl(ip_header->ihl);
    ip_header->version = htonl(ip_header->version); // IPv4
    ip_header->tos = 0; // Type of service
    ip_header->tot_len = htons(PACKET_SIZE); // Total length of the packet
    ip_header->id = htons(12345); // Identification
    ip_header->ttl = 64; // Time to live
    ip_header->check = htons(ip_header->check);

    /*
     * Notice we skipped over s and d addr this is because inet_addr() already did this bit flip for us!
     * So we do not need to do anything here. We can leave those ones.
     */

}

/*
 * Here is the opposite, for when we want to read it. We may need to we may not need to.
 */
uint16_t get_ip_header_host_ready(struct iphdr (*ip_header)){

    ip_header->ihl = ntohl(ip_header->ihl);
    ip_header->version = ntohl(ip_header->version); // IPv4
    ip_header->tos = 0; // Type of service
    ip_header->tot_len = ntohl(PACKET_SIZE); // Total length of the packet
    ip_header->id = ntohs(12345); // Identification
    ip_header->ttl = 64; // Time to live
    ip_header->check = ntohs(ip_header->check);



}