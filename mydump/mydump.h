#ifndef MDH
#define MDH

#include <stdlib.h>
#include <stdio.h>

#define IPV4 0x0800

void print_err_msg_exit(int errnum, int retcode);

//int packetContainsStr(const u_char *packet, char *searchstring, size_t pktlen);
//void handle_cb(u_char *args, const struct pcap_pkthdr *pktheader, const u_char *packet);

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
#define ARP 0x0806
/* Ethernet header */
struct sniff_ethernet {
	u_char  ether_dhost[ETHER_ADDR_LEN];	/* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];	/* source host address */
	u_short ether_type;					 /* IP? ARP? RARP? etc */
};

//UDP header
struct sniff_udp {
	u_short sport;		/* source port */
	u_short dport;		/* destination port */
	u_short udp_length;
	u_short udp_sum;
};



#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

#endif
