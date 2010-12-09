#ifndef __CONN_REDIRECT_INFO__
#define __CONN_REDIRECT_INFO__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/ioctl.h>    
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h> 
#include <time.h>
#include <unistd.h>

#include "csman.h"
#include "csid/csid_gid.h"
#include "csid/csid_local.h"   
#include "csid/csid_urlblock.h"
#include "unilog.h"  

#define WAN_IFACE          "br0"
#define URLR_PID           "/var/run/url_redirect.pid"
#define REDIRECT_PAGE      "block.htm"
#define PKT_BUF_LEN        10240
#define MAX_URL_RULE       16
#define PSEUDO             sizeof(struct pseudo_hdr)
#define TCPHDR             sizeof(struct tcphdr)
#define Z_NL               4294967295
#define DO_URL_CMP         1
#define DO_HOST_CMP        2

#define split(word, wordlist, next, delim) \
    for (next = wordlist, \
	strncpy(word, next, sizeof(word)), \
	word[(next=strstr(next, delim)) ? strstr(word, delim) - word : sizeof(word) - 1] = '\0', \
	next = next ? next + sizeof(delim) - 1 : NULL ; \
	strlen(word); \
	next = next ? : "", \
	strncpy(word, next, sizeof(word)), \
	word[(next=strstr(next, delim)) ? strstr(word, delim) - word : sizeof(word) - 1] = '\0', \
	next = next ? next + sizeof(delim) - 1 : NULL)

#if 0
#define url_debug   fprintf
#else
#define url_debug(format, args...)
#endif 

struct conn_info {
    char src_ip[16];
    int  src_port;
    char dst_ip[16];
    int dst_port;
    unsigned int tcp_len;
    unsigned int ack;
    unsigned int seq;
};

struct pseudo_hdr {
    unsigned long saddr;
    unsigned long daddr;
    char reserved;
    unsigned char protocol;
    unsigned short length;
};
 
typedef struct httpinfo {
    char host[PKT_BUF_LEN + 1];
    int hostlen;
    char url[PKT_BUF_LEN + 1];
    int urllen;
    char refer[PKT_BUF_LEN + 1];
    int referlen;
} httpinfo_t;         
  

int get_conn_info (int nrecv, char *pkt_buffer, struct conn_info *cinfo);
//int get_host_info (int sock, char *host, char* pkt_buffer);
int get_http_info(int sock, httpinfo_t *info, char* pkt_buffer, int flag);
int redirect_conn(struct conn_info *cinfo, char* redirect_page);

#endif 
