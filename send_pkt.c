/*
 * URL Block Redirect
 *
 * send a HTTP 303 redirect packet for client
 *
 * Author: Chad Sheu
 * Last Modify: 2010/02/24
 */ 

#include "conn_redirect.h"

static unsigned int build_pseudo_hdr(unsigned int src_addr, unsigned int dst_addr, unsigned int protocol,
                                     const unsigned char* hdr_data, unsigned int hdr_len, 
                                     const unsigned char* msg_data, unsigned int msg_len, 
                                     unsigned short** buffer); 

static unsigned char* build_tcp_data(struct sockaddr_in* src_sin, struct sockaddr_in* dst_sin, 
                                     const unsigned char* msg, unsigned int msg_size);

static unsigned short check_sum(unsigned short* data, int nbytes);
static int fill_address(int domain, const char* address, unsigned short port, struct sockaddr_in* sin);

static struct conn_info *cinfo;                 

int redirect_conn(struct conn_info *cinfo_, char* redirect_page) 
{
    cinfo = cinfo_;
    srand(time(0));

    // root-privileges needed for the following operation
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s <= 0) {
        perror("[open_sockraw] socket()");
        return 1;
    }

    int enable = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("Error: setsockopt() - Cannot set HDRINCL:\n");
        return 1;
    }

    // We no longer need root privileges
    setuid(getuid());

    // build up out source and destination sock addresses
    struct sockaddr_in src_sin;
    struct sockaddr_in dst_sin;
    fill_address(PF_INET, cinfo->dst_ip, htons(cinfo->dst_port), &src_sin);
    fill_address(PF_INET, cinfo->src_ip, htons(cinfo->src_port), &dst_sin);
 
    // build our TCP datagram
    const unsigned char msg[128]; 
    snprintf(msg, 128, "HTTP/1.1 303\r\n"
                       "Content-Type: text/html\r\n"
                       "Connection: close\r\n"
                       "Location: %s\r\n", redirect_page);

    unsigned char* data = build_tcp_data(&src_sin, &dst_sin, msg, strlen(msg));
    unsigned int pkt_size = sizeof(struct ip) + sizeof(struct tcphdr) + strlen(msg);
    if (sendto(s, data, pkt_size, 0, (struct sockaddr*) &dst_sin, sizeof(dst_sin)) < 0) 
        fprintf(stderr, "Error with sendto() -- %s (%d)\n", strerror(errno), errno);
    
    free(data);
    return 0;
} 

static unsigned short check_sum(unsigned short* data, int nbytes) 
{
    unsigned long sum = 0;
    for (; nbytes > 1; nbytes -= 2) 
        sum += *data++;

    if (nbytes == 1) 
        sum += *(unsigned char*) data;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}   

static int 
fill_address(int domain, const char* address, unsigned short port, struct sockaddr_in* sin)
{
    if (!address) {
        memset(sin, 0, sizeof(struct sockaddr_in));
        sin->sin_family = domain;
        sin->sin_addr.s_addr = htonl(INADDR_ANY);
        sin->sin_port = htons(port);
    }
    else {
        struct addrinfo hints;
        struct addrinfo* host_info = 0;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = domain;

        if (getaddrinfo(address, 0, &hints, &host_info) != 0 ||
            !host_info || !host_info->ai_addr || host_info->ai_family != domain)
        {
            if (host_info) 
                freeaddrinfo(host_info);
                
            return -1;
        }

        memcpy(sin, host_info->ai_addr, sizeof(struct sockaddr_in));
        sin->sin_port = htons(port);
        freeaddrinfo(host_info);
    }
    return 0;
}

static unsigned char* 
build_tcp_data (struct sockaddr_in* src_sin, struct sockaddr_in* dst_sin, 
                const unsigned char* msg, const unsigned int msg_size)
    
{
    const int ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + msg_size;
    unsigned char* datagram = calloc(1, ip_len);
    if (!datagram) 
        return 0;

    // setup useful pointers to locations within the datagram
    struct ip* iph = (struct ip*) datagram;
    struct tcphdr* tcph = (struct tcphdr*)(datagram + sizeof(struct ip));
    unsigned char* data = datagram + sizeof(struct ip) + sizeof(struct tcphdr);

    // build IP header
    iph->ip_hl  = sizeof(struct ip) >> 2;
    iph->ip_v   = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(ip_len);
    iph->ip_id  = htons((int)(rand()/(((double)RAND_MAX + 1)/14095)));
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p   = IPPROTO_TCP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = src_sin->sin_addr.s_addr;
    iph->ip_dst.s_addr = dst_sin->sin_addr.s_addr;

    // now we compute the checksum for the IP header (albeit this is optional)
    iph->ip_sum = check_sum((unsigned short*) iph, sizeof(struct ip));

    // build TCP header
    tcph->source  = htons(src_sin->sin_port);
    tcph->dest    = htons(dst_sin->sin_port);
    tcph->seq     = htonl(cinfo->ack);              
    tcph->ack_seq = htonl(cinfo->seq + cinfo->tcp_len); 
    tcph->res1    = 0;
    tcph->doff    = sizeof(struct tcphdr) >> 2;
    tcph->fin     = 1;
    tcph->syn     = 0;
    tcph->rst     = 0;
    tcph->psh     = 0;
    tcph->ack     = 1;
    tcph->urg     = 0;
    tcph->res2    = 0;
    tcph->window  = htons(512);
    tcph->check   = 0;
    tcph->urg_ptr = htons(0);

    // now we compute the TCP header checksum, across a pseudo message buffer, not the actual TCP header
    unsigned short* buffer = 0;
    unsigned int buffer_size = 
        build_pseudo_hdr(src_sin->sin_addr.s_addr, 
                         dst_sin->sin_addr.s_addr, 
                         IPPROTO_TCP,
                         (const unsigned char*) tcph,       /* Protocol      */
                         sizeof(struct tcphdr),             /* Header Size   */
                         msg,                               /* Conetent      */
                         msg_size,                          /* Message Size  */
                         &buffer);                          /* Pseudo Header */

    tcph->check = check_sum(buffer, buffer_size);
    free(buffer);

    // add message data (if any)
    if (msg_size > 0) 
        memcpy(data, msg, msg_size);

    return datagram;
}

static unsigned int 
build_pseudo_hdr(unsigned int src_addr, unsigned int dst_addr, unsigned int protocol,
                 const unsigned char* hdr_data, unsigned int hdr_len, 
                 const unsigned char* msg_data, unsigned int msg_len, unsigned short** buffer)
{
    struct pseudo_hdr phdr;
    phdr.saddr    = src_addr;
    phdr.daddr    = dst_addr;
    phdr.reserved = 0;
    phdr.protocol = protocol;  
    phdr.length   = htons(hdr_len + msg_len);

    unsigned int buf_size = sizeof(struct pseudo_hdr) + hdr_len + msg_len;
    unsigned char* buf    = calloc(1, buf_size);
    int offset            = 0;

    memcpy(buf + offset, &phdr, sizeof(struct pseudo_hdr)); 
    offset += sizeof(struct pseudo_hdr);
    
    memcpy(buf + offset, hdr_data, hdr_len); 
    offset += hdr_len;
    
    memcpy(buf + offset, msg_data, msg_len);
    *buffer = (uint16_t*) buf;

    return buf_size;
}

