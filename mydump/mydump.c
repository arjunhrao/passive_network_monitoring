//Homework 2 CSE 508
#include "debug.h"
#include "mydump.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <net/ethernet.h>
#include <time.h>

const char *error_msgs[] = {
	"USAGE: [-h] [-i interface] [-r file] [-s string] expression\n"									\
    "-h				Displays the help menu.\n\n"													\
    "-i				Live capture from the network device <interface> (e.g., eth0). If not\n"		\
    				"specified, mydump should automatically select a default interface to\n"		\
    				"listen on (hint 1). Capture should continue indefinitely until the user\n"		\
    				"terminates the program.\n\n"													\
	"-r 			Read packets from <file> in tcpdump format (hint 2).\n\n"						\
    "-s 			Keep only packets that contain <string> in their payload (after any BPF\n"		\
    				"filter is applied). You are not required to implement wildcard or regular\n"	\
    				"expression matching. A simple string matching operation should suffice\n"		\
    				"(hint 3).\n\n"																	\
	"<expression> 	is a BPF filter that specifies which packets will be dumped. If\n"				\
	"no filter is given, all packets seen on the interface (or contained in the\n"					\
	"trace) should be dumped. Otherwise, only packets matching <expression> should\n"				\
	"be dumped.\n\n"																				\
	"For each packet, mydump prints a record containing the timestamp, source and\n"				\
	"destination MAC address, EtherType, packet length, source and destination IP\n"				\
	"address and port, protocol type (e.g., TCP, UDP, ICMP, OTHER), and the\n"						\
	"raw content of the packet payload.\n",
	"ERROR: Either an interface, a file, or neither can be provided (in which case interface is the default) but NOT BOTH.",
	"ERROR: '?' case in getopt. An argument was not specified or an invalid flag was specified.",
	"ERROR: read from file flag specified more than once.",
	"ERROR: read from file flag specified but no file specified.",//4
	"ERROR: interface flag specified more than once.",//5
	"ERROR: default case in getopt reached.",
	"ERROR: Please specify only one or 0 BPF filters as a single expression.",
	"ERROR: Please specify an interface with the -i flag, or do not specify the flag at all (for a default interface)."//8
};

/* IP header */ //I moved this here bc of some error with in_addr
struct sniff_ip {
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
	#define IP_RF 0x8000            /* reserved fragment flag */
	#define IP_DF 0x4000            /* dont fragment flag */
	#define IP_MF 0x2000            /* more fragments flag */
	#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset);

void print_packet(const char *string, const struct pcap_pkthdr *header, const u_char *packet);


//static void handle_cb(u_char *args, const struct pcap_pkthdr *pktheader, const u_char *packet);

//NOTE: The following three functions are built on those in http://www.tcpdump.org/sniffex.c as per hint 0.
/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

//print info for the packet. We call this when we know that the string is in the payload in got_packet.
//Basically splitting up the function for ease of use
void print_packet(const char *string, const struct pcap_pkthdr *header, const u_char *packet) {
	
	


	/* declare pointers to packet headers */
	const struct sniff_udp *udp;			//UDP header
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const u_char *payload;                    /* Packet payload */

	int size_ip, size_tcp, size_payload;
	int size_udp = 8;
	int size_icmp = 8;

	//convert and print out timestamp
	time_t raw_time = (time_t)header->ts.tv_sec;
	char *tempptr = ctime(&raw_time);
	char time[128];
	memset(time, '\0', 128);
	strcpy(time, tempptr);
	time[strlen(time)-1] = '\0';
	printf("%s | ", time);

	
	//define ethernet header used in sniffex.c in hint 0
	ethernet = (struct sniff_ethernet*)(packet);
	
	//let's take care of MAC addresses
	//I somehow just could not figure out how to do this with the ethernet fields here so I used a different struct
	//Oh. It has something to do with converting bytes to ascii. But oh well I already did it a different way.
	//printf("MAC: %s ", ethernet->ether_shost);
	//printf("-> %s | ", ethernet->ether_dhost);
	struct ethhdr *eh = (struct ethhdr*)packet;
    //src MAC
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x -> ", eh->h_source[0], eh->h_source[1], eh->h_source[2], eh->h_source[3], eh->h_source[4], eh->h_source[5]);
    //dst MAC
    printf("%02x:%02x:%02x:%02x:%02x:%02x | ", eh->h_dest[0], eh->h_dest[1], eh->h_dest[2], eh->h_dest[3], eh->h_dest[4], eh->h_dest[5]);
	
	

	printf("Type: 0x%04x | ", ntohs(ethernet->ether_type));
	if (ntohs(ethernet->ether_type) == IPV4) {//if IPV4 packet
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);//get header
		size_ip = IP_HL(ip)*4;
		if (size_ip < 20) {
			printf("* Invalid IP header length: %u bytes\n", size_ip);
			return;
		}//as in the sniffex.c file
		
		//switch statement is unnecessary, use if statements:
		if (ip->ip_p == IPPROTO_TCP) {
			printf("TCP | ");
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("* Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}
			printf("pkt len: %d | ", ntohs(ip->ip_len));

			printf("IP Addresses and port #s: %s.%d ->", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
			printf(" %s.%d | ", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
			
			
			//get payload
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

			if (size_payload > 0) {
				printf("Payload (%d bytes): \n", size_payload);
				
				if (string != NULL) {
					if (strstr( (char *)payload, string) == NULL) {//Don't want to print the rest of the payload
						//we don't need this actually bc we already checked but w/e, can't hurt
						//printf("doesn't match search string%c", '.');
						return;
					}
				}
				print_payload(payload, size_payload);
			}
			printf("\n");
		}
		else if (ip->ip_p == IPPROTO_ICMP) {//if ICMP
			printf("ICMP | ");
			
			printf("pkt len: %d | ", ntohs(ip->ip_len));

			printf("IP Addresses: %s -> ", inet_ntoa(ip->ip_src));
			printf("%s | ", inet_ntoa(ip->ip_dst));
			
			//get payload
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
			size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
			
			if (size_payload > 0) {
				printf("Payload (%d bytes): \n", size_payload);
				print_payload(payload, size_payload);
			}
			printf("\n");
		}
		else if (ip->ip_p == IPPROTO_UDP) {//if UDP
			printf("UDP | ");
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
			
			printf("pkt len %d | ", ntohs(ip->ip_len));

			printf("IP addresses and port #s: %s.%d -> ", inet_ntoa(ip->ip_src), ntohs(udp->sport));
			printf("%s.%d | ", inet_ntoa(ip->ip_dst), ntohs(udp->dport));
			
			
			//get payload
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
			size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
			
			if (size_payload > 0) {
				printf("Payload (%d bytes):\n", size_payload);
				//some error searching in UDP packets due to non-printable characters: https://piazza.com/class/j6lyorzz9qj5i3?cid=48
				print_payload(payload, size_payload);
			}
			printf("\n");
		} 
		else {
			printf("IPv4: OTHER | ");
			//get payload
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
			size_payload = ntohs(ip->ip_len) - (size_ip);
			
			if (size_payload > 0) {
				printf("Payload (%d bytes):\n", size_payload);
				print_payload(payload, size_payload);
			}
			printf("\n");
		}
	}
	else {
		if (ntohs(ethernet->ether_type) == ARP) {
			printf("ARP\n");
		}
		else {
			printf("OTHER\n");
			//printf("Type: Other - %d\n", ntohs(ethernet->ether_type));
		}

		payload = (u_char *)(packet + SIZE_ETHERNET);

		printf("Raw Payload preview%c \n", ':');
		/*
		if (string != NULL) {
			if (strstr( (char *)payload, string) == NULL) {//Don't want to print the rest of the payload
				//printf("doesn't match search string%c", '.');
				return;
			}
		}
		*/
		print_payload(payload, 46);//data is at least 46 bytes for an ethernet packet according to google
		printf("\n");
		
	}
	
	return;
}

//callback function
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	
	if (args == NULL) {
		print_packet( (char *)args, header, packet);
	}
	else {
		//This is the same stuff we did in print_packet except we're just checking for the string in the payload
		//before printing things.

		/* declare pointers to packet headers */
		//const struct sniff_udp *udp;			//UDP header
		const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
		const struct sniff_ip *ip;              /* The IP header */
		const struct sniff_tcp *tcp;            /* The TCP header */
		const u_char *payload;                    /* Packet payload */

		int size_ip, size_tcp, size_payload;
		int size_udp = 8;
		int size_icmp = 8;

		const char *string = (char *)args;
		//get ethernet header
		ethernet = (struct sniff_ethernet*)(packet);
		
		if (ntohs(ethernet->ether_type) == IPV4) {
			//get ip header
			ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
			size_ip = IP_HL(ip)*4;
			if (size_ip < 20) {
				printf("   * Invalid IP header length: %u bytes\n", size_ip);
				return;
			}
			
			if (ip->ip_p == IPPROTO_TCP) {//if TCP

				tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
				size_tcp = TH_OFF(tcp)*4;
				if (size_tcp < 20) {
					printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
					return;
				}
				
				//get payload
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
				size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
				
				//check with strstr
				if (size_payload > 0) {
					char payload_buffer[size_payload+1];
					payload_buffer[size_payload] = 0;
					strncpy(payload_buffer, (char *)payload, size_payload);
					
					if (strstr(payload_buffer,string) != NULL)
						print_packet(string, header, packet);
					else
						return;
				}
				else {
					return;
				}
			}
			else if (ip->ip_p == IPPROTO_ICMP) {
				//get payload
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
				size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
				
				if (size_payload > 0) {
					char payload_buffer[size_payload+1];
					payload_buffer[size_payload] = 0;
					strncpy(payload_buffer, (char *)payload, size_payload);
					
					if (strstr(payload_buffer,string) != NULL)
						print_packet(string, header, packet);
					else
						return;
				}
				else {
					return;
				}
			}
			else if (ip->ip_p == IPPROTO_UDP) {
				const struct sniff_udp *udp;			//UDP header
				udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
				if (udp) {}
				
				//get payload
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
				size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
				
				if (size_payload > 0) {
					char payload_buffer[size_payload+1];
					payload_buffer[size_payload] = 0;
					strncpy(payload_buffer, (char *)payload, size_payload);
					//some error searching in UDP packets due to non-printable characters: https://piazza.com/class/j6lyorzz9qj5i3?cid=48
					//debug("Payload_buffer: %s\n", payload_buffer);
					
					//so change nonprintable characters. But then searching for something with ..s isn't going to give
					//the right answer huh.
					//One potential solution: make it a space, not a dot. A space cannot be included in the search
					//string anyways.
					//TBH i don't think any of this matters... doesn't strstr keep going until it hits a null
					//character anyways, which means non-printable characters like the EOF character won't stop it?
					//Yeah, I tested it. strstr still finds a string after the occurrence of an EOF character...
					//https://piazza.com/class/j6lyorzz9qj5i3?cid=48 seems to have been sort of misleading - that or
					//I'm misinterpreting it.
					//Maybe it's ok bc i already strncpy'd it? idk.
					//Something seems to be wrong with ARP and whatnot though for searching (it sometimes prints out
					//actual characters in the payload, but then searching for those chars gets nothing).
					//Not sure how to fix that problem though.
					for (int i = 0; i < size_payload; i++) {
						if (!isprint(payload_buffer[i]) ) {//if it's not printable, just make it a dot.
							payload_buffer[i] = ' ';
						}
					}

					//debug("Payload_buffer: %s\n", payload_buffer);

					if (strstr(payload_buffer,string) != NULL)
						print_packet(string, header, packet);
					else
						return;
				}
				else {
					return;
				}
			} 
			else {
				//get payload
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
				size_payload = ntohs(ip->ip_len) - (size_ip);
				
				if (size_payload > 0) {
					char payload_buffer[size_payload+1];
					payload_buffer[size_payload] = 0;
					strncpy(payload_buffer, (char *)payload, size_payload);
					
					if (strstr(payload_buffer,string) != NULL)
						print_packet(string, header, packet);
					else
						return;
				}
				else {
					return;
				}
			}
		}
		//else if (ntohs(ethernet->ether_type) == ARP) {
		else {

			payload = (u_char *)(packet + SIZE_ETHERNET);
			size_payload = 46;

			if (size_payload > 0) {
				char payload_buffer[size_payload+1];
				payload_buffer[size_payload] = 0;
				strncpy(payload_buffer, (char *)payload, size_payload);

				//debug("Payload_buffer: %s\n", payload_buffer);

				for (int i = 0; i < size_payload; i++) {
					if (!isprint(payload_buffer[i]) ) {//if it's not printable, just make it a dot.
						payload_buffer[i] = ' ';
					}
					//else {
						//debug("printable char: %c\n", payload_buffer[i]);
					//}
				}

				//debug("Payload_buffer: %s\n", payload_buffer);

				if (strstr(payload_buffer,string) != NULL)//if it matches
					print_packet(string, header, packet);
				else
					return;
			}
			else {
				return;
			}

			/*
			if (string != NULL) {
				if (strstr( (char *)payload, string) == NULL) {
					return;
				}
			}
			print_packet(string, header, packet);
			*/
		}
		//else {
		//	printf("ETHERTYPE OTHER\n");
		//}

	}
}


int main(int argc, char *argv[]) {

	char *interface = NULL;
	char *file = NULL;
	//FILE *in = NULL;
	char *string = NULL;
	char *expression = NULL;
	int rFlagUsed = 0;
	int iFlagUsed = 0;

	//fprintf(stdout, "%s", "testing");
	//We want to look through the arguments to determine what was provided
	//Want it to be valid even if they weren't provided in the standard order,
	//so long as they conform to the right flags and inputs.
	int c;
	while ((c = getopt(argc, argv, "hr:i:s:")) != -1) {//starting off with a colon means we can use :: for optional arguments,
		//and : is returned instead of ?
	    switch (c) {
	        case 'h':
	            print_err_msg_exit(0, EXIT_SUCCESS);//should go to stdout
	            break;

        	case 'i':{
        		if (iFlagUsed) {
        			print_err_msg_exit(5, EXIT_FAILURE);
        		}
        		if (optarg == NULL) {//then -i was specified but no interface.
        			print_err_msg_exit(8, EXIT_FAILURE);
        		}
        		else {
        			interface = optarg;//argument present
        		}
        		iFlagUsed = 1;
	            break;
	        }

	        case 'r':{
	        	debug("input file: \"%s\"\n", optarg);//check if file is valid
	        	if (rFlagUsed) {
	        		print_err_msg_exit(3, EXIT_FAILURE);
	        	}
	        	//else
	       		if (optarg == NULL) {//no corresponding arg was provided with the file flag
	       			print_err_msg_exit(4, EXIT_FAILURE);
	       		}
	       		//otherwise, set the file string
	            file = optarg;
	            rFlagUsed = 1;//and the flag used int
	            break;
	        }

	        case 's':
	            string = optarg;
	            break;

	        case '?':{
	        	print_err_msg_exit(2, EXIT_FAILURE);
	            break;
	        }

	        default:
	            print_err_msg_exit(6, EXIT_FAILURE);
	            break;
	    }
	}


	//The variable optind is the index of the next element of the argv[] vector to be processed
	if (argc-1 == optind) {//then the expression is there.
		expression = argv[optind];
	}//If argc == optind, then: "no filter is given, all packets seen on the interface (or contained in the trace) should be dumped."
	else if (argc != optind) {//otherwise, we have an error.
		print_err_msg_exit(7, EXIT_FAILURE);
	}
	//and otherwise, no expression provided so it stays null.

	if (interface && file)//can't have both specified
		print_err_msg_exit(1, EXIT_FAILURE);



	//**********************************************************
	char errbuf[PCAP_ERRBUF_SIZE];//for error string
	memset(errbuf, '\0', sizeof(errbuf));
	bpf_u_int32 mask;//sniffing device netmask
	bpf_u_int32 net;//IP address of sniffing device
	struct bpf_program filter;//compiled filter expression
	memset(&filter, '\0', sizeof(struct bpf_program));
	pcap_t *handle;
	
	
	if (interface == NULL && file == NULL) {//then default interface
		//use default - "If not specified, mydump should automatically select a default interface to listen on (hint 1)."
		interface = pcap_lookupdev(errbuf);
		if (interface == NULL) {
            fprintf(stderr, "\npcap_lookupdev ERROR: %s\n", errbuf);
            exit(EXIT_FAILURE);
        } else {
            debug("Default interface: %s\n", interface);
        }
	}
	
	if (interface != NULL && file == NULL) {//file == NULL. Now interface can't be null unless file isn't
		if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {//as seen on http://www.tcpdump.org/pcap.html
			fprintf(stderr, "Can't get netmask for device due to pcap_lookupnet error: %s\n", errbuf);
			net = 0;
			mask = 0;
		}//otherwise begin session
		handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device due to pcap_open_live error: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}
	else if (file != NULL && interface == NULL) {//then file != NULL and interface == NULL.
		handle = pcap_open_offline(file, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Can't read file/dump offline - pcap_open_offline error: %s\n", errbuf);
            exit(EXIT_FAILURE);
		}
	}

	//This was causing me to segfault so I'm commenting it out. I'm not sure why though.
	//It happens when I use a default interface and that's it. It doesn't go past the if statement either,
	//just segfaults on the pcap_datalink method I think.
	//Oh i fixed it. I didn't open live in that case.
	
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Only Ethernet is supported as a link-layer protocol. (Interface used: %s)\n", interface);
		exit(EXIT_FAILURE);
	}
	

	if (expression) {//If expression, then use as filter. Otherwise, if NULL, then "no filter, all packets to be dumped."
		//compile filter
        if (pcap_compile(handle, &filter, expression, 0, net) == -1) {//as seen on http://www.tcpdump.org/pcap.html
            fprintf(stderr, "Couldn't parse filter %s: %s\n", expression, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
        //set the filter
        if (pcap_setfilter(handle, &filter) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", expression, pcap_geterr(handle));
            exit(EXIT_FAILURE);
		}
	}

	debug("expression checked and filters set: %s\n", expression);


	//http://www.tcpdump.org/manpages/pcap_loop.3pcap.html
	//Do NOT assume that the packets for a given capture or ``savefile`` will have any given link-layer header type, such as DLT_EN10MB
	//for Ethernet. For example, the "any" device on Linux will have a link-layer header type of DLT_LINUX_SLL even if all devices on
	//the system at the time the "any" device is opened have some other data link type, such as DLT_EN10MB for Ethernet.  

	//start sniffing
	//A value of -1 or 0 for cnt is equivalent to infinity, so that packets are processed until another ending condition occurs
	//int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
    debug("interface: %s\n", interface);
    debug("searh string: %s\n", string);
    debug("expression: %s\n", expression);
    
	int cnt = -1;
	pcap_loop(handle, cnt, got_packet, (u_char *)string);

	pcap_close(handle);
	
	return 0;

}





//https://piazza.com/class/j6lyorzz9qj5i3?cid=39
//For “other” just print the raw payload. If a packet is not IP, your program should still be able to print a meaningful
//record (e.g., only it’s MAC addresses and type)

void print_err_msg_exit(int errnum, int retcode) {
	
	if (errnum != 0) {//if not help message then print to stderr
		fprintf(stderr, "\n%s\n", error_msgs[errnum]);
		fprintf(stderr, "\n%s\n", error_msgs[0]);//print usage
	}
	else {//print to stdout
		fprintf(stdout, "\n%s\n", error_msgs[errnum]);
	}
	exit(retcode);
}

