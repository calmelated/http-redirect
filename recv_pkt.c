/*
 * URL Block Redirect
 *
 * Sniffer a HTTP GET packet and return the host information
 *
 * Author: Chad Sheu
 * Last Modify: 2010/2/27
 */

#include "conn_redirect.h"

static int find_pattern2(const char *data, size_t dlen, const char *pattern, size_t plen, char term, unsigned int *numoff, unsigned int *numlen);
static int get_host_info (int sock, char *host, char* pkt_buffer);
static void print_pkt(int nrecv ,char* buffer);

static void print_pkt(int nrecv ,char* buffer) {

    url_debug(stderr,"%d bytes read\n",nrecv);

    unsigned char* ethhead = buffer;
    url_debug(stderr,"Source MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
            ethhead[0], ethhead[1], ethhead[2], ethhead[3], ethhead[4], ethhead[5]);
    url_debug(stderr,"Destination MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
            ethhead[6], ethhead[7], ethhead[8], ethhead[9], ethhead[10], ethhead[11]);

    unsigned char* iphead = buffer+14; /* Skip Ethernet  header */
    if (*iphead == 0x45) {             /* Double check for IPv4 and no options present */
        url_debug(stderr, "Source host %d.%d.%d.%d\n", iphead[12], iphead[13], iphead[14], iphead[15]);
        url_debug(stderr, "Dest host %d.%d.%d.%d\n", iphead[16], iphead[17], iphead[18], iphead[19]);
        url_debug(stderr, "Source,Dest ports %d,%d\n", (iphead[20]<<8)+iphead[21], (iphead[22]<<8)+iphead[23]);
        url_debug(stderr, "Layer-4 protocol %d\n", iphead[9]);
    }

    unsigned char* tcphead = iphead + 20;
    if (iphead[9] == 0x06) {
         url_debug(stderr, "TCP Sequence Number: %x%x%x%x\n", tcphead[4], tcphead[5], tcphead[6], tcphead[7]);
         url_debug(stderr, "TCP Acknowledgement Number: %x%x%x%x\n", tcphead[8], tcphead[9], tcphead[10], tcphead[11]);
         url_debug(stderr, "TCP Header Length: %d\n", tcphead[12]>>4);
         url_debug(stderr, "TCP Control Bits: %02x (UAPRSF)\n", tcphead[13]);
         url_debug(stderr, "TCP Window Size: %d\n", (tcphead[14]<<8)+tcphead[15]);
         
         int i;
         for(i = 4*(tcphead[12]>>4) ; i < nrecv-14-20 ; ++i) 
            url_debug(stderr, "%c", tcphead[i]);
         
         url_debug(stderr, "\n");
     }       
}

int get_conn_info (int nrecv, char *pkt_buffer, struct conn_info *cinfo)
{
    unsigned char* iphead = pkt_buffer + 14;  
    snprintf(cinfo->src_ip, 16, "%d.%d.%d.%d", iphead[12], iphead[13], iphead[14], iphead[15]);
    snprintf(cinfo->dst_ip, 16, "%d.%d.%d.%d", iphead[16], iphead[17], iphead[18], iphead[19]);
    cinfo->src_port = (int)((iphead[20]<<8)+iphead[21]);
    cinfo->dst_port = (int)((iphead[22]<<8)+iphead[23]);

    unsigned char* tcphead = iphead + 20;
    cinfo->tcp_len = nrecv - 14 - 20 - 20;
    cinfo->seq     = ((tcphead[4]<<24)|(tcphead[5]<<16)|(tcphead[6]<<8)|tcphead[7]);
    cinfo->ack     = ((tcphead[8]<<24)|(tcphead[9]<<16)|(tcphead[10]<<8)|tcphead[11]);
 
#if 0
    // Debug
    url_debug(stderr, "Get Connection Info.\n");
    url_debug(stderr, "SrcIP:   %s\n", cinfo->src_ip);
    url_debug(stderr, "DstIP:   %s\n", cinfo->dst_ip);
    url_debug(stderr, "SrcPort: %d\n", cinfo->src_port);
    url_debug(stderr, "DstPort: %d\n", cinfo->dst_port);
    url_debug(stderr, "TCP Len: %d\n", cinfo->tcp_len);
    url_debug(stderr, "Seq:     %x\n", cinfo->seq);
    url_debug(stderr, "ACK:     %x\n", cinfo->ack);  
#endif

}

static int get_host_info (int sock, char *host, char* pkt_buffer) {
    /* 
     * Check to see if the packet contains at least 
     * complete Ethernet (14), IP (20) and TCP/UDP (8) headers.
     */
    int nrecv = recvfrom(sock, pkt_buffer, PKT_BUF_LEN, 0, NULL, NULL);
    if (nrecv < 42) {
        perror("recvfrom():");
        url_debug(stderr, "Incomplete packet (errno is %d)\n", errno);
        return 0;
    }

    /* Skip Ethernet header  */
    unsigned char* iphead = pkt_buffer + 14;     
    if (*iphead != 0x45)                     
        return 0;

    /* Detect whether is HTTP  */
    if(((iphead[22]<<8) + iphead[23]) != 80)
        return 0;

    unsigned char* tcphead = iphead + 20;
    int start_idx = 4 * (tcphead[12]>>4);
    if(!(tcphead[start_idx]   == 'G' && 
         tcphead[start_idx+1] == 'E' &&
         tcphead[start_idx+2] == 'T'))
        return 0;
     
    unsigned char* httphdr = pkt_buffer + 14 + 20 + 20;
    char *start_host = strstr(httphdr, "Host:");
    if(start_host == NULL)
        return 0;

    char *end_host = strstr((const char*)start_host, "\r\n");
    if(end_host == NULL)
        return 0;
    
    int len1 = strlen(start_host);
    int len2 = strlen(end_host);
    bzero(host, 128);
    memcpy(host, (char *)(start_host+6), ((len1-6)-len2));
    return nrecv;
}

/* Return 1 for match, 0 for accept, -1 for partial. */
static int find_pattern2(const char *data, size_t dlen, const char *pattern, 
             size_t plen, char term, unsigned int *numoff, unsigned int *numlen)
{
    size_t i, j, k;
    int state = 0;
    *numoff = *numlen = 0;

    url_debug(stderr, "%s: pattern = '%s', dlen = %u\n",__FUNCTION__, pattern, dlen);
    if (dlen == 0)
        return 0;

    if (dlen <= plen) {	/* Short packet: try for partial? */
        if (strncmp(data, pattern, dlen) == 0)
            return -1;
        else 
            return 0;
    }

    for (i = 0; i <= (dlen - plen); i++) {
        /* DFA : \r\n\r\n :: 1234 */
        if (*(data + i) == '\r') {
            if (!(state % 2)) 
                ++state;	    /* forwarding move */
            else 
                state = 0;		/* reset */
        }
        else if (*(data + i) == '\n') {
            if (state % 2) 
                ++state;
            else 
                state = 0;
        }
        else 
            state = 0;

        if (state >= 4)
            break;

        /* pattern compare */
        if (memcmp(data + i, pattern, plen ) != 0)
            continue;

        /* Here, it means patten match!! */
        *numoff=i + plen;
        for (j = *numoff, k = 0; data[j] != term; j++, k++)
            if (j > dlen) 
                return -1 ;	/* no terminal char */

        *numlen = k;
        return 1;
    }
    return 0;
}

int get_http_info(int sock, httpinfo_t *info, char* pkt_buffer, int flag)
{
    /* 
     * Check to see if the packet contains at least 
     * complete Ethernet (14), IP (20) and TCP/UDP (8) headers.
     */
    int nrecv = recvfrom(sock, pkt_buffer, PKT_BUF_LEN, 0, NULL, NULL);
    if (nrecv < 42) {
        perror("recvfrom():");
        url_debug(stderr,"Incomplete packet (errno is %d)\n", errno);
        return 0;
    } 

    unsigned char* data = pkt_buffer + 14 + 20 + 20;
    unsigned int datalen = nrecv - 14 - 20 - 20;
    /* Basic checking, is it HTTP packet? */
    if (datalen < 10)
	    return 0;	/* Not enough length, ignore it */

    if (memcmp(data, "GET ", sizeof("GET ") - 1) != 0 &&
        memcmp(data, "POST ", sizeof("POST ") - 1) != 0 &&
        memcmp(data, "HEAD ", sizeof("HEAD ") - 1) != 0) 
        return 0;	/* Pass it */

    int found, offset;
    int hostlen, pathlen; 
    /* find the 'Host: ' value for URL and HOST filter */
    found = find_pattern2(data, datalen, "Host: ", sizeof("Host: ") - 1, '\r', &offset, &hostlen);
    url_debug(stderr, "Host found=%d\n", found);
    if (!found || !hostlen)
        return 0;         

    hostlen = (hostlen < PKT_BUF_LEN) ? hostlen : PKT_BUF_LEN;
    strncpy(info->host, data + offset, hostlen);
    *(info->host + hostlen) = 0;		/* null-terminated */
    info->hostlen = hostlen;
    url_debug(stderr, "HOST=%s, hostlen=%d\n", info->host, info->hostlen);

    /* 
     * find the 'GET ' or 'POST ' or 'HEAD ' value, ONLY for URL filter 
     */
    if(flag != DO_URL_CMP)
        return nrecv;

    found = find_pattern2(data, datalen, "GET ", sizeof("GET ") - 1, '\r', &offset, &pathlen);
    if (!found)
        found = find_pattern2(data, datalen, "POST ", sizeof("POST ") - 1, '\r', &offset, &pathlen);

    if (!found)
        found = find_pattern2(data, datalen, "HEAD ", sizeof("HEAD ") - 1, '\r', &offset, &pathlen);
 
    url_debug(stderr, "GET/POST found=%d\n", found);
    if (!found || (pathlen -= (sizeof(" HTTP/x.x") - 1)) <= 0) /* ignor this field */
        return 0;

    pathlen = ((pathlen + hostlen) < PKT_BUF_LEN) ? pathlen : PKT_BUF_LEN - hostlen;
    strncpy(info->url, info->host, hostlen);
    strncpy(info->url + hostlen, data + offset, pathlen);
    *(info->url + hostlen + pathlen) = 0;	/* null-terminated */
    info->urllen = hostlen + pathlen;
    url_debug(stderr, "URL=%s, urllen=%d\n", info->url, info->urllen);

    found = find_pattern2(data, datalen, "Referer: ", sizeof("Referer: ") - 1, '\r', &offset, &pathlen);
    url_debug(stderr, "Referer found=%d, offset %d, pathlen %d\n", found, offset, pathlen);
    if(!found){
        info->referlen = 0;
        return nrecv;
    }

    strncpy(info->refer, data + offset, pathlen);
    *(info->refer + pathlen) = 0;
    url_debug(stderr, "Referer: %s\n", info->refer);
    return nrecv;
}

