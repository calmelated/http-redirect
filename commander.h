#ifndef __COMMANDER__
#define __COMMANDER__

#include <stdlib.h>  // for system function
#include <stdio.h>   // for acess file and string function
#include <signal.h>
#include <error.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>  //for inet_ntoa function	 
#include <arpa/inet.h>   //for inet_ntoa function	
#include <sys/socket.h>  //for inet_ntoa and sucket function	 
#include <netdb.h>   // for gethostbyname function 
#include <net/if.h>  // for struct ifreq
#include <linux/sockios.h> // for SIOCGMIIPHY and SIOCGMIIREG
//#include <errno.h>  // for errno number
#include <time.h> // for ctime and asctime or other time function
#include <sys/timeb.h> // for ftime function
#include <sys/time.h> // for gettimeofday and settimeofday
#include <unistd.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include "ralink_gpio.h"

#define GPIO_DEV        "/dev/gpio"

#include "csman.h"
#include "csid/csid_gid.h"
#include "csid/csid_local.h"
#include "csid/csid_http.h"
#include "csid/csid_dhcp.h"
#include "csid/csid_fix.h"
#include "csid/csid_pppoe.h"
#include "csid/csid_pptp.h"
#include "csid/csid_l2tp.h"
#include "csid/csid_ddns.h"
#include "csid/csid_dnsproxy.h"
#include "csid/csid_ntp.h"
#include "csid/csid_schedule.h"
#include "csid/csid_sendmail.h"
#include "csid/csid_routing.h"
#include "csid/csid_misc.h"
#include "csid/csid_spap.h"
#include "csid/csid_snmp.h"
#include "csid/csid_pkfilter.h"
#include "csid/csid_qos.h"
#include "csid/csid_urlblock.h"
#include "csid/csid_dmfilter.h"
#include "csid/csid_vcomputer.h"
#include "csid/csid_macctl.h"
#include "csid/csid_portfw.h"
#include "csid/csid_mrouting.h"
#include "csid/csid_sys.h"
#include "csid/csid_wlanap.h"
#include "csid/csid_wlanapcli.h"
#include "csid/csid_sdmz.h"
#include "csid/csid_3g.h"
#include "csid/csid_wlancli.h"
#include "csid/csid_local.h"
#include "csid/csid_green.h"
#include "csid/csid_pptpserv.h"
#include "csid/csid_l2tpserv.h"
#include "csid/csid_iburst.h"
#include "csid/csid_tr069.h"
#include "csid/csid_gre.h"
#include "unilog.h"

#include "board_config.h"

#define IF_NAME_SIZE 10

#define JOB_STATE_NORMAL 0
#define JOB_STATE_FORK 1

#define NOTIFIER_LIST_NUM			14
#define LAN_ALTERED_LIST			0
#define WAN_TYPE_SET_ALTERED_LIST	1
#define ROUTING_ALTERED_LIST		2
#define WAN_CONNECTED_LIST			3
#define WAN_DISCONNECTED_LIST		4
#define JOB_REGULAR_ROUTINE			5
#define DHCPSRV_ALTERED_LIST		6
#define WLANAP_ALTERED_LIST			7
#define MACCTL_ALTERED_LIST			8
#define WLANAP_ATE_ALTERED_LIST		9
#define WAN_WAIT_TRAFFIC_LIST		10
#define WLANCLI_ALTERED_LIST	    11
#define PPTPSRV_ALTERED_LIST        12
#define L2TPSRV_ALTERED_LIST        13


typedef struct CMD_JOBS CMD_JOBS_T;

struct CMD_JOBS
{
	char *name;
	int (*init)(int fd, CMD_JOBS_T *job);
	int (*phase_two)(int fd, CMD_JOBS_T *job);
	int pid;
	char state;	
};

typedef int (*notify_func) __P((void *, int));

struct notifier {
    struct notifier *next;
    notify_func	    func;
    void	    *arg;
    CMD_JOBS_T	*job;
};

extern int no_disconnect_dnrd;

int notify(int notifierList, int val);
void remove_notifier(int notifierList , notify_func func, void *arg);
int add_notifier(int notifierList , notify_func func, void *arg, CMD_JOBS_T *job);

/* handle_lan */
int init_lan(int fd, CMD_JOBS_T *job);

/* hanlde_wan */
int wan_phase_two(int fd, CMD_JOBS_T *job);
int init_wan(int fd, CMD_JOBS_T *job);

/*handle_nat*/
int init_nat(int fd, CMD_JOBS_T *job);

/*handle_qos*/
int init_qos(int fd, CMD_JOBS_T *job);

/*handle_upnp*/
int init_upnp(int fd, CMD_JOBS_T *job);

/*handle_routing*/
int init_routing(int fd, CMD_JOBS_T *job);

/*handle_snmp*/
int init_snmp(int fd, CMD_JOBS_T *job);

/*handle_ddns*/
int init_ddns(int fd, CMD_JOBS_T *job);

/*handle_mail*/
int init_mail(int fd, CMD_JOBS_T *job);

/*handle_spap*/
int init_spap(int fd, CMD_JOBS_T *job);

/*handle_time*/
int init_time(int fd, CMD_JOBS_T *job);

/*handle_rbydom*/
int init_rbydom(int fd, CMD_JOBS_T *job);

/*handle_rbyip*/
int init_rbyip(int fd, CMD_JOBS_T *job);

/* hanlde_dhcpsrv*/
int init_dhcpsrv(int fd, CMD_JOBS_T *job);

/* handle_wlanap*/
int init_wlanap(int fd, CMD_JOBS_T *job);
int wlan_phase_two(int fd, CMD_JOBS_T *job);

/* handle_wlancli*/
int init_wlancli(int fd, CMD_JOBS_T *job);

/* handle_wlanap*/
int init_dnsrelay(int fd, CMD_JOBS_T *job);

/*handle_sdmz*/
int init_sdmz(int fd, CMD_JOBS_T *job);

/*handle_autobak*/
int init_autobak(int fd, CMD_JOBS_T *job);

/* handle_igmp */
int init_igmp(int fd, CMD_JOBS_T *job);

/* handle_green */
int init_green(int fd, CMD_JOBS_T *job);

/* handle_gpio */
int init_gpio(int fd, CMD_JOBS_T *job);

/* handle wlan ap ate */
int init_wlanap_ate(int fd, CMD_JOBS_T * job);

/* handle pptp server */
int init_pptpsrv(int fd, CMD_JOBS_T * job);

/* handle l2tp server */
int init_l2tpsrv(int fd, CMD_JOBS_T * job);

/* handle tr069 */
int init_tr069(int fd, CMD_JOBS_T * job);
/* handle_keep_alive */
int init_keep_alive(int fd, CMD_JOBS_T * job);

/* handle_3g_status */
int init_3g_status(int fd, CMD_JOBS_T * job);

/* handle_gre_tunnel */
int init_gre_tunnel(int fd, CMD_JOBS_T * job); 

#endif



