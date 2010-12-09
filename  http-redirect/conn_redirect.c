/*
 * URL Block Redirect
 *
 * redirect the restricted URL page to 
 * a warnning page we specify in prior
 *
 * Author: Chad Sheu
 * Last Modify: 2009/11/18
 */ 

#include "conn_redirect.h"

static int flag;
static int white_list;
static int init(char **argv);
static int init_url_redirect();
static int read_url_rule(char rule[MAX_URL_RULE][128], char* router_ip, char* redirect_page);
static int match (httpinfo_t *info, char *wordlist, int flag);
static int chg_iptables_action(char* rule);
static void usage();

int main(int argc, char **argv) {
    if(argc != 2 || init(argv) == -1){
        usage();
        return 0;
    }

    int sock = init_url_redirect();
    if(sock == -1)
        return 0;

    char rule[MAX_URL_RULE][128];
    char redirect_page[128];
    char router_ip[16];
    int nrule = read_url_rule(rule, router_ip, redirect_page);
    if(!nrule) {
        perror("No any URL Block Rules!");
        close(sock);
        return 0;   
    }
    
    while (1) {   
        char pkt_buffer[PKT_BUF_LEN] = {0};
        int  nrecv = 0;
        httpinfo_t info;
        if(!(nrecv = get_http_info(sock, &info, pkt_buffer, flag)))
            continue;

        if(match(&info, router_ip, DO_HOST_CMP) == 1){
            url_debug(stderr, "dont redirect for local ip\n");
            continue;
        }
 
        int i;
        int do_redirect = 0;
        if(white_list == 0){
            for(i = 0; i < nrule ; ++i) {
                if(match(&info, rule[i], flag) == 1){
                    do_redirect = 1;
                    break;
                }
            }
        }
        else {
            do_redirect = 1;
            for(i = 0; i < nrule ; ++i) {
                url_debug(stderr, "rule[%d] = %s \n", i, rule[i]);
                if(match(&info, rule[i], flag) == 1){
                    do_redirect = 0;
                    break;
                }
            }
            rule[i][0] = '*';
        }

        if(do_redirect){
             // match block rule --> redirect
            url_debug(stderr, "\n===> Redirect the Connection by rule[%d] = %s \n", i, rule[i]);

            struct conn_info cinfo;
            get_conn_info(nrecv, pkt_buffer, &cinfo);
            redirect_conn(&cinfo, redirect_page);            
            chg_iptables_action(rule[i]); 
        }
    } 
    close(sock);
}

static int init(char **argv)
{
    flag = 0;
    white_list = 0;
    if(strcmp(argv[1], "-url") == 0 || strcmp(argv[1], "-u") == 0)
        flag = DO_URL_CMP;
 
    if(strcmp(argv[1], "-url!") == 0 || strcmp(argv[1], "-u!") == 0){
        flag = DO_URL_CMP; 
        white_list = 1;
    }

    if(strcmp(argv[1], "-host") == 0 || strcmp(argv[1], "-h") == 0)
        flag = DO_HOST_CMP;
    
    if(strcmp(argv[1], "-host!") == 0 || strcmp(argv[1], "-h!") == 0){
        flag = DO_HOST_CMP;
        white_list = 1;
    }

    if(!flag){
        fprintf(stderr,"No such parameter %s\n", argv[1]);
        return -1;
    }  
    return 0;
}

static int chg_iptables_action(char* rule)
{
    char iptables_rule[PKT_BUF_LEN];
    snprintf(iptables_rule, PKT_BUF_LEN, "iptables -D url_block -p tcp -m webstr --url \"%s\" -j DROP", rule);
    system(iptables_rule);

    snprintf(iptables_rule, PKT_BUF_LEN, "iptables -A url_block -p tcp -m webstr --url \"%s\" -j REJECT --reject-with tcp-reset", rule);
    system(iptables_rule);
 
    snprintf(iptables_rule, PKT_BUF_LEN, "iptables -A url_block -p tcp -m webstr --url \"%s\" -j DROP", rule);
    system(iptables_rule);

    snprintf(iptables_rule, PKT_BUF_LEN, "iptables -D url_block -p tcp -m webstr --url \"%s\" -j REJECT --reject-with tcp-reset", rule);
    system(iptables_rule);
}

static void usage(){
    fprintf(stderr,"Usage:\n"
           "1. conn_redirect -url     :Redirect the connection URL filtered to the warning page\n"
           "2. conn_redirect -host    :Redirect the connection HOST blocked to the warning page\n"
           "3. conn_redirect -url!    :DONT redirect the connection URL filtered to the warning page\n"
           "4. conn_redirect -host!   :DONT redirect the connection HOST blocked to the warning page\n"
          );
}

static int init_url_redirect()
{
	int pid = 0;
	FILE *fd = NULL;
	
    //kill the previous process
	if ((fd = fopen(URLR_PID, "r")) != NULL) {
		fscanf(fd,"%d",&pid);
		fclose(fd);
        remove(URLR_PID);
		kill(pid,SIGTERM);
		sleep(1);
	}   

	if ((fd = fopen(URLR_PID, "w")) != NULL) {
		fprintf(fd,"%d",getpid());
		fclose(fd);
	}

    int sock;
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        perror("socket");
        goto fail;
    }

    /* Set the network card in promiscuos mode */
    struct ifreq ethreq;
    strncpy(ethreq.ifr_name, WAN_IFACE ,IFNAMSIZ);
    if (ioctl(sock,SIOCGIFFLAGS,&ethreq) == -1) {
        perror("ioctl (SIOCGIFCONF) 1");
        goto fail;
    }

    ethreq.ifr_flags |= IFF_PROMISC;
    if (ioctl(sock,SIOCSIFFLAGS,&ethreq) == -1) {
        perror("ioctl (SIOCGIFCONF) 2");
        goto fail;
    }

end:
    return sock; 

fail:
    close(sock);
    return -1;
}

static int match (httpinfo_t *info, char *wordlist, int flag) {
    char needle[PKT_BUF_LEN];
   	char token[] = "<&nbsp;>";

    char* haystack = NULL;
    char* haystack_more = NULL;
    int hlen;
    int hlen_more;
    if(flag == DO_URL_CMP){
        haystack = info->url;
        hlen = info->urllen;

        if(info->referlen > 0){
            haystack_more = info->refer;
            hlen_more = info->referlen;
        }
    }  
    else if(flag == DO_HOST_CMP){
        haystack = info->host;
        hlen = info->hostlen;    
    }

    char *next;
    int nlen = 0;
    split(needle, wordlist, next, token) {
        nlen = strlen(needle);
        url_debug(stderr, "keyword=%s, nlen=%d, hlen=%d\n", needle, nlen, hlen);
        if (!nlen || !hlen || nlen > hlen) 
            continue;

        if (haystack != NULL && strstr(haystack, needle) != NULL)
            return 1;
        
        if (haystack_more != NULL && strstr(haystack_more, needle) != NULL)
            return 1;

    }  
    return 0;
} 

static int 
read_url_rule(char rule[MAX_URL_RULE][128], char* router_ip, char* redirect_page){
    int fd = open_csman(NULL,0);
    if (fd < 0) {
        perror("Can't Open CSMAN");
        goto end;
    }
    
    struct in_addr local_ip;
    read_csman(fd, CSID_C_LOCAL_LANIP, &local_ip, sizeof(struct in_addr), CSM_R_ZERO);
    snprintf(router_ip, 16, "%s", inet_ntoa(local_ip));
    snprintf(redirect_page, 128, "http://%s/%s", inet_ntoa(local_ip), REDIRECT_PAGE);

    unsigned int urlb_enable;
    read_csman(fd, CSID_C_URLBLOCK_ENABLE, &urlb_enable, sizeof(unsigned int), CSM_R_ZERO); 
    if(!urlb_enable){
        perror("URL Block isn't enable!");
        goto end;
    }
    
    int i;
    int nrule = 0;
    for (i = 0; i < MAX_URL_RULE; i++) {
        int rule_enable;
        read_csman(fd, (CSID_C_URLBLOCK_RULE_ENABLE + i), &rule_enable, sizeof(int), CSM_R_ZERO); 
        if(!rule_enable)
            continue;
        
        char rule_[128];
        read_csman(fd, (CSID_C_URLBLOCK_RULE_URL + i), rule_ , 128 , CSM_R_ZSTR); 
        if(!strcmp(rule_ ,""))
            continue;

        bzero(rule[nrule], 128);
        strncpy(rule[nrule], rule_, (strlen(rule_) + 1));
        ++nrule;
    }
    return nrule;

end:
    close_csman(fd);
    return 0;
}      

