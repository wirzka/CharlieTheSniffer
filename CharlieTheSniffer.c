/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    TODOs:
    [✔] Enhance the packet handler
        [✔] Do not print on a log file, but on terminal
        [✔] The key is to use the packetHandler in a smart way (Put the proto recognition inside it, then call the respective printing function for the headers)
    [ ] Enhance packet capture:
        [✔] Add type control on ICMP packet
        [ ] Format a better output
        [ ] Provide filtering capabilities
    [✔] Provide pcap output file option
    [✔] Clean code
    [✔] Clean options structure
    [✔] Handle case where no interface has been given
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

#include <errno.h>
#include <getopt.h> /* library to parse arguments */
#include <netinet/if_ether.h> /* library to handle ethernet frame */
#include <netinet/igmp.h> /* library to handle IGMP packet */
#include <netinet/in.h> /* library to work with internet address, protocols, ports */
#include <netinet/ip.h> /* library providing support for IP header */
#include <netinet/ip_icmp.h> /* library providing support for ICMP header */
#include <netinet/tcp.h> /* library providing support for TCP header */
#include <netinet/udp.h> /* library providing support for UDP header */
#include <libgen.h>
#include <pcap.h> /* libpcap library, the program's core */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Constant declaration */
/*
*    Using getopt() to handle cmd line argument parsing
*    Creating two useful constant:
*    1. OPTSTR:  we will put here our valid options
*    2. USAGE_FMT: here we will place our helping message
*    
*    Be aware that if:
*    - character followed by a colon, then option required an argument
*    - character not followed by a colon, then no argument required for the given option
*/
#define OPTSTR "sli:h"
#define USAGE_FMT  "\n--------------- CharlieTheSniffer ---------------\n\n\
Usage:\n [-s] [-i ID] [-h] \n\
        -s show interfaces\n\
        -i <ID> to select a interface by giving its name\n\
        -h show this helping message\n\n\
Example:\n ./csniff -i eth0 \n\
Tips:\n\
If you don't want the output on terminal you can direct it to a file with the pipeling power:\n\
    $ sudo charliethesniffer.c -i eth0 > file_with_output\n\
Disclaimer:\nYou MUST use this tool only within environment where\nyou have officially the rights to do so.\n\n"
#define DUMPFILE "charliedump.pcap"
#define SIZE_ETHERNET 14

typedef u_int tcp_seq;

extern char *optarg;

/* 
 * Structure to save arguments options.
 * I've made a struct to let it be more keen
 * to updates.
 */
typedef struct {
    char         *intFace;
} options_t;

struct sockaddr_in source,dest;

/* Functions prototypes */
// Support functions
void showInterfaces();  /* Function to show the available interfaces to the user */
void usage(char *msg);  /* Function to issuing helping message */
void showError(char *msg);  /* Function to standardise error output */
void showStatus(char *msg); /* Function to standardise status output */

// Packet sniffer functions
void printEthHeader(const u_char *packetBody); /* Function to print the Ethernet Header */
void printIpHeader(const u_char *packetBody);  /* Function to print IP header */
void printTcpPacket(const u_char *packetBody, int length);  /* Function to print the TCP packet */
void printUdpPacket(const u_char *packetBody, int length);  /* Function to print the UDP packet*/
void printIcmpPacket(const u_char *packetBody, int length); /* Function to print ICMP packet */
void printIgmpPacket(packetBody, headerLen); /* Function to print IGMP pracket */
void printPacketData(const u_char *data, int length); /* Function to print packet data */
void packetHandler(u_char *args, const struct pcap_pkthdr *packetHeader, const u_char *packetBody); /* Function to handle every action on the packets */
int cookingPreSniffer(char *dev); /* Function to start capturing packets */

/* main */
int main(int argc, char *argv[]){
    int opt, id;
    // Initializing the options struct with the following values
    options_t options = {NULL};
    // Array that will be used to provide a message
    char msg[256];

    // We start looping till we finish to fetch the arguments issued at the launching of the program
    while ((opt = getopt(argc, argv, OPTSTR)) != EOF){
        switch(opt) {
            // To call showInterfaces function and print the interfaces' identifier
            case 's':
                showInterfaces();
                break;
            
            // To select the interface where we want to sniff
            case 'i':
                // Setting the device name inside our options structure so we can use it later
                options.intFace = optarg;
                
                // Cooking the message with snprintf to avoid overflow and then call the standardised output function
                snprintf(msg, sizeof(msg), "%s %s", "Opening device", options.intFace);
                
                showStatus(msg);
                
                // Calling the cooking function that will set the given device for the sniffing phase
                cookingPreSniffer(options.intFace);
                break;

            // For any other case just return the helping message
            default:
                usage(USAGE_FMT);
                /*
                    using exit to quit the entire program and not just the while loop
                    so no other helping message will be issued
                */
                exit(0);
        }
    }

    // If any given argument issues the helping message defined in USAGE_FMT
    if(argc < 2){
        usage(USAGE_FMT);
        exit(0);
    }

    return 0;
    
}

/*-------Support functions-------*/
/* Function to show the available interfaces to the user */
void showInterfaces(){
    char error[PCAP_ERRBUF_SIZE]; /* Array where it'll store any error message */

    pcap_if_t *interfaces, *temp; /* pcap structure for interfaces */
    
    int i=0; /* variable that will be used as index later */
    
    /*
    Looking for any interfaces on the local machine
    If pcap_findalldevs returns -1, it means that an error occured
    otherwise it will prompt all the available interfaces.
    */
    if(pcap_findalldevs(&interfaces,error)==-1){
        showError("Something went wrong in pcap findall devs");
    }
    else{
        printf("The interfaces are:");
        /*
        Iterating the linked list
        ~~~ how to iterate through linked list:
            To go to the next node we need to indicate that node with:
            temp->next
            Where temp is the node where we are at the moment.
        ~~~
        */
        for(temp=interfaces;temp;temp=temp->next){
            printf("\n%d : %s",i++,temp->name);
        }
        printf("\n");
    }
}

/* Function to issuing helping message */
void usage(char *msg){
    fprintf(stderr, msg);
}

/* Function to standardise error output */
void showError(char *msg){
    fprintf(stderr, "\x1b[31m%s\n%s\n\x1b[0m", "[!] ERROR [!]", msg);
}

/* Function to standardise status output */
void showStatus(char *msg){
    fprintf(stdout, "%s: %s [!]\n", "[!] STATUS", msg);
}

/*-------Packet sniffer functions-------*/
/* Function to start capturing packets */
int cookingPreSniffer(char *dev){
    pcap_t *handle; /* Struct that we will use to handle sniffing process and packets */
    char errbuf[512]; /* Array that will be used by pcap_open_live to store any error message */
    char buf[256]; /* Array that will be used to ouput messages */
    struct pcap_pkthdr packetHeader; /* Struct to store the packet header's data */
    
    showStatus("Live capturing");
    /*
        PROTOTYPE:
        pcap_t *pcap_open_live(const char *device, int snaplen,
                               int promisc, int to_ms, char *errbuf);
        EXPLANATION:
        device  =   our interface
        snaplen =   to specifies snapshot length to be set on the handle
        promisc =   insert non-zero value to set interface in promiscuous mode
        to_ms   =   packet buffer timeout in milliseconds
        errbuf  =   array to store any error retrieved
    */
    
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    
    // In the case something blown up
    if (handle == NULL){
        snprintf(buf, sizeof(buf), "%s", errbuf);
        showError(buf);
        return -1;
    }

    showStatus("Showing results");

    /*
        PROTOTYPE:
        pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname);
    
        EXPLANATION:

        P       = the packet handle/file to fetch
        fname   = the filename where to dump all the captured traffic, we have defined it in the constants section

    */
    pcap_dumper_t *dumped = pcap_dump_open(handle, DUMPFILE);

    /*
        PROTOTYPE:
        int pcap_loop(pcap_t *p, int cnt,
                    pcap_handler callback, u_char *user);
        EXPLANATION:
        p        =   the packet handle/file to fetch
        cnt      =   numbers of packet to be processed (-1 OR 0 means infinity)
        callback =   the function to be called everytime we fetch a packet
        user     =   arguments for the callbakc function, we have the dumped pointer for our pcap output file
    */
    pcap_loop(handle, 1000, packetHandler, dumped);
    
    // Securely closing the pcap file
    /*
        PROTOTYPE:
        void pcap_dump_close(pcap_dumper_t *p);
    */
    pcap_dump_close(dumped);

    return 1;
}

/* Function to handle every action on the packets */
void packetHandler(u_char *dumpFile, const struct pcap_pkthdr *packetHeader, const u_char *packetBody){
    int headerLen = packetHeader->len; /* Header length of the packet */
    struct iphdr *ipHeader = (struct iphdr*)(packetBody + sizeof(struct ethhdr)); /* Creating the ipHeader struct and populating it with data gathered from packet */
    
    pcap_dump(dumpFile, packetHeader, packetBody);
    
    switch (ipHeader->protocol){
        case IPPROTO_ICMP: /* ICMP protocol */
            printIcmpPacket(packetBody, headerLen);
            break;
        case IPPROTO_IGMP: /* IGMP protocol */
            printIgmpPacket(packetBody, headerLen);
            break;
        case IPPROTO_TCP: /* TCP protocol */
            printTcpPacket(packetBody, headerLen);
            break;
        case IPPROTO_UDP: /* UDP protocol */
            printUdpPacket(packetBody, headerLen);
            break;
        default:
            // other protocols not yet supported (e.g. GGP)
            break;
    }

}

/* Function to print the Ethernet Header */
void printEthHeader(const u_char *packetBody){

    struct ethhdr *ethHeader = (struct ethhdr *)(packetBody); /* Creating the struct for ethernet header and populating it with rispective data */

    fprintf(stdout , "\n");
	fprintf(stdout , "Ethernet Header\n");
    /* As the MAC address is in HEX we have to print it out with this technique */
	fprintf(stdout , "   |-Destination Address  : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", ethHeader->h_dest[0], ethHeader->h_dest[1], ethHeader->h_dest[2],
                                                                                     ethHeader->h_dest[3], ethHeader->h_dest[4], ethHeader->h_dest[5]);
	fprintf(stdout , "   |-Source Address       : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", ethHeader->h_source[0], ethHeader->h_source[1], ethHeader->h_source[2],
                                                                                     ethHeader->h_source[3], ethHeader->h_source[4], ethHeader->h_source[5]);
	fprintf(stdout , "   |-Protocol             : %u \n",(unsigned short)ethHeader->h_proto);
}

/* Function to print IP header */
void printIpHeader(const u_char *packetBody){
    unsigned short ipHeaderLen; /* variable to store IP header length */

    printEthHeader(packetBody); /* Printing the ethernet header */
    
    struct iphdr *ipHeader = (struct iphdr *)(packetBody + sizeof(struct ethhdr)); /* creating and populating struct for IP header */
    ipHeaderLen = ipHeader->ihl*4; /* calcultating IP header length using Internet Header Length and multipling it for bits it occupies */

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ipHeader->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ipHeader->daddr;

    fprintf(stdout, "\n");
	fprintf(stdout, "IP Header\n");
	fprintf(stdout, "   |-IP Version           : %d\n",(unsigned int)ipHeader->version);
	fprintf(stdout, "   |-IP Header Length     : %d DWORDS or %d Bytes\n",(unsigned int)ipHeader->ihl,((unsigned int)(ipHeader->ihl))*4);
	fprintf(stdout, "   |-Type Of Service      : %d\n",(unsigned int)ipHeader->tos);
	fprintf(stdout, "   |-IP Total Length      : %d  Bytes(Size of Packet)\n",ntohs(ipHeader->tot_len));
	fprintf(stdout, "   |-Identification       : %d\n",ntohs(ipHeader->id));
	fprintf(stdout, "   |-TTL                  : %d\n",(unsigned int)ipHeader->ttl);
	fprintf(stdout, "   |-Protocol             : %d\n",(unsigned int)ipHeader->protocol);
	fprintf(stdout, "   |-Checksum             : %d\n",ntohs(ipHeader->check));
	fprintf(stdout, "   |-Source IP            : %s\n", inet_ntoa(source.sin_addr));
	fprintf(stdout, "   |-Destination IP       : %s\n", inet_ntoa(dest.sin_addr));
}

/* Function to print the TCP packet */
void printTcpPacket(const u_char *packetBody, int length){
    unsigned short ipHeaderLen; /* variable to store IP header length */

    struct iphdr *ipHeader = (struct iphdr *)( packetBody + sizeof(struct ethhdr)); /* creating and populating struct for IP header */
    ipHeaderLen = ipHeader->ihl*4; /* calcultating IP header length using Internet Header Length and multipling it for bits it occupies */

    struct tcphdr *tcpHeader = (struct tcphdr*)(packetBody + ipHeaderLen + sizeof(struct ethhdr)); /* Creating and populating struct for TCP header */

    int tcpHeaderLen = sizeof(struct ethhdr) + ipHeaderLen + tcpHeader->doff*4; /* Calculating the TCP header length */

    fprintf(stdout, "\n===================TCP Packet===================\n");
    
    printIpHeader(packetBody); /* printing IP header */
    
    fprintf(stdout, "\nTCP header\n");
    fprintf(stdout , "   |-Source Port          : %u\n",ntohs(tcpHeader->source));
	fprintf(stdout , "   |-Destination Port     : %u\n",ntohs(tcpHeader->dest));
	fprintf(stdout , "   |-Sequence Number      : %u\n",ntohl(tcpHeader->seq));
	fprintf(stdout , "   |-Acknowledge Number   : %u\n",ntohl(tcpHeader->ack_seq));
	fprintf(stdout , "   |-Header Length        : %d DWORDS or %d BYTES\n" ,(unsigned int)tcpHeader->doff,(unsigned int)tcpHeader->doff*4);
	fprintf(stdout , "   |-Urgent Flag          : %d\n",(unsigned int)tcpHeader->urg);
	fprintf(stdout , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcpHeader->ack);
	fprintf(stdout , "   |-Push Flag            : %d\n",(unsigned int)tcpHeader->psh);
	fprintf(stdout , "   |-Reset Flag           : %d\n",(unsigned int)tcpHeader->rst);
	fprintf(stdout , "   |-Synchronise Flag     : %d\n",(unsigned int)tcpHeader->syn);
	fprintf(stdout , "   |-Finish Flag          : %d\n",(unsigned int)tcpHeader->fin);
	fprintf(stdout , "   |-Window               : %d\n",ntohs(tcpHeader->window));
	fprintf(stdout , "   |-Checksum             : %d\n",ntohs(tcpHeader->check));
	fprintf(stdout , "   |-Urgent Pointer       : %d\n",tcpHeader->urg_ptr);
	
	fprintf(stdout , "\n~~~~~~~~~~~~~~~~~~~~~Data Payload~~~~~~~~~~~~~~~~~~~~~\n");
	/* From there we start printing the respective data payload of the various headers */
    fprintf(stdout, "IP header\n");
    printPacketData(packetBody, length);
    sleep(0.5);
    fprintf(stdout, "TCP header\n");
    printPacketData(packetBody + ipHeaderLen, tcpHeader->doff*4);
    sleep(0.5);
    fprintf(stdout, "Data payload\n");
    printPacketData(packetBody + tcpHeaderLen, length - tcpHeaderLen);
    sleep(0.5);
}

/* Function to print the UDP packet*/
void printUdpPacket(const u_char *packetBody, int length){
    unsigned short ipHeaderLen;

    struct iphdr *ipHeader = (struct iphdr *)(packetBody + sizeof(struct ethhdr));
    ipHeaderLen = ipHeader->ihl*4;

    struct udphdr *udpHeader = (struct udphdr*)(packetBody + ipHeaderLen + sizeof(struct ethhdr));

    int headerLen = sizeof(struct ethhdr*) + ipHeaderLen + sizeof udpHeader;
    
    fprintf(stdout , "\n\n===================UDP Packet===================\n");
	
	printIpHeader(packetBody);
	
	fprintf(stdout , "\nUDP Header\n");
	fprintf(stdout , "   |-Source Port          : %d\n" , ntohs(udpHeader->source));
	fprintf(stdout , "   |-Destination Port     : %d\n" , ntohs(udpHeader->dest));
	fprintf(stdout , "   |-UDP Length           : %d\n" , ntohs(udpHeader->len));
	fprintf(stdout , "   |-UDP Checksum         : %d\n" , ntohs(udpHeader->check));

    fprintf(stdout , "\n~~~~~~~~~~~~~~~~~~~~~Data Payload~~~~~~~~~~~~~~~~~~~~~\n");
    fprintf(stdout , "IP Header\n");
    printPacketData(packetBody, ipHeaderLen);
    sleep(0.5);
    fprintf(stdout , "UDP Header\n");
    printPacketData(packetBody + ipHeaderLen, sizeof udpHeader);
    sleep(0.5);
    fprintf(stdout , "Data Payload\n");	
    //Move the pointer ahead and reduce the size of string
    printPacketData(packetBody + headerLen, length - headerLen);
    sleep(0.5);
}

/* Function to print ICMP packet */
void printIcmpPacket(const u_char *packetBody, int length){
    unsigned short ipHeaderLen;

    struct iphdr *ipHeader = (struct iphdr *)(packetBody + sizeof(struct ethhdr));
    ipHeaderLen = ipHeader->ihl*4;

    struct icmphdr *icmpHeader = (struct icmphdr *)(packetBody + ipHeaderLen + sizeof(struct ethhdr));

    int headerLen = sizeof(struct ethhdr) + ipHeaderLen + sizeof icmpHeader;

    fprintf(stdout, "\n\n===================ICMP Packet===================\n");	
	
	printIpHeader(packetBody);
			
	fprintf(stdout, "\n");
		
	fprintf(stdout, "ICMP Header\n");
	fprintf(stdout, "   |-Type                 : %d",(unsigned int)(icmpHeader->type));
	switch(icmpHeader->type){
        case ICMP_ECHOREPLY:
            fprintf(stdout , "  (Echo Reply)\n");
            break;
        case ICMP_DEST_UNREACH:
            fprintf(stdout , "  (Destination Unreachable)\n");
            break;
        case ICMP_SOURCE_QUENCH:
            fprintf(stdout , "  (Source Quench)\n");
            break;
        case ICMP_REDIRECT:
            fprintf(stdout , "  (Redirect)\n");
            break;
        case ICMP_ECHO:
            fprintf(stdout , "  (Echo Request)\n");
            break;
        case ICMP_TIME_EXCEEDED:
            fprintf(stdout , "  (Time Exceeded)\n");
            break;
        case ICMP_PARAMETERPROB:
            fprintf(stdout , "  (Parameter Problem)\n");
            break;
        case ICMP_TIMESTAMP:
            fprintf(stdout , "  (Timestamp Request)\n");
            break;
        case ICMP_TIMESTAMPREPLY:
            fprintf(stdout , "  (Timestamp Reply)\n");
            break;
        case ICMP_INFO_REQUEST:
            fprintf(stdout , "  (Information Request)\n");
            break;
        case ICMP_INFO_REPLY:
            fprintf(stdout , "  (Information Reply)\n");
            break;
        case ICMP_ADDRESS:
            fprintf(stdout , "  (Address Mask Request)\n");
            break;
        default:
            fprintf(stdout , "  (Unknown)\n");
            break;
        
    }
	fprintf(stdout, "   |-Code                 : %d\n",(unsigned int)(icmpHeader->code));
	fprintf(stdout, "   |-Checksum             : %d\n",ntohs(icmpHeader->checksum));
	fprintf(stdout, "\n");

	fprintf(stdout, "IP Header\n");
	printPacketData(packetBody, ipHeaderLen);
	sleep(0.5);
	
    fprintf(stdout, "UDP Header\n");
	printPacketData(packetBody + ipHeaderLen, sizeof icmpHeader);
	sleep(0.5);
	
    fprintf(stdout, "Data Payload\n");	
	printPacketData(packetBody + headerLen, length - headerLen);
	sleep(0.5);
}

/* Function to print IGMP pracket */
void printIgmpPacket(const u_char *packetBody, int length){
    unsigned short ipHeaderLen;
    struct in_addr* ia;
    struct iphdr *ipHeader = (struct iphdr *)(packetBody + sizeof(struct ethhdr));
    ipHeaderLen = ipHeader->ihl*4;

    struct igmp* igmpPacket = (struct igmp *)(packetBody + ipHeaderLen + sizeof(struct ethhdr));

    int packetLength = sizeof(struct ethhdr) + ipHeaderLen + sizeof igmpPacket;
    fprintf(stdout , "\n\n===================IGMP Packet===================\n");
	printIpHeader(packetBody);
	fprintf(stdout , "\n");
		
	fprintf(stdout , "IGMP Packet\n");
	fprintf(stdout , "   |- Type : %d\n",(u_int8_t)(igmpPacket->igmp_type));
    fprintf(stdout , "   |- MRT : %d\n",(u_int8_t)(igmpPacket->igmp_code));
    fprintf(stdout , "   |- Checksum : %d\n",(u_int16_t)(igmpPacket->igmp_cksum));
    fprintf(stdout , "   |- Group Address : %d\n",(struct in_addr)(igmpPacket->igmp_group));
}

/* Function to print packet data */
void printPacketData(const u_char *data, int length){
    int i , j;
	for(i=0 ; i < length ; i++)
{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(stdout , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(stdout , "%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(stdout , "."); //otherwise print a dot
			}
			fprintf(stdout , "\n");
		} 
		
		if(i%16==0) fprintf(stdout , "   ");
			fprintf(stdout , " %02X",(unsigned int)data[i]);
				
		if( i==length-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) 
			{
			  fprintf(stdout , "   "); //extra spaces
			}
			
			fprintf(stdout , "         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
				  fprintf(stdout , "%c",(unsigned char)data[j]);
				}
				else 
				{
				  fprintf(stdout , ".");
				}
			}
			
			fprintf(stdout ,  "\n" );
		}
	}
}
