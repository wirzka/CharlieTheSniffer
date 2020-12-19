#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <pcap.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>

/* Constant declaration */
/*
    Using getopt() to handle cmd line argument parsing
    Creating two useful constant:
    1. OPTSTR:  we will put here our valid options
    2. USAGE_FMT: here we will place our helping message
    
    Be aware that if:
    - character followed by a colon, then option required an argument
    - character not followed by a colon, then no argument required for the given option
*/

#define OPTSTR "sli:h"
#define USAGE_FMT  "Usage for csniff:\n [-s] [-i ID] [-l] [-o] [-h] \n\
Example:\n ./csniff -i 1 -l \n\
Tips:\n To select an interface you have to provide the ID number.\n"
#define OUTFILENAME "ctscapture"
#define ERR_FOPEN_OUTPUT "fopen(output, w)"

// extern int errno;
extern char *optarg;
// extern int opterr, optind;

/* Structure to save arguments options */
typedef struct {
    char         *intFace;
    u_int32_t    flags;
    FILE         *output;
    bool         live;
} options_t;

/* Functions prototypes */
// Support functions
void showInterfaces();
void usage(char *msg);
void showError(char *msg);
int checkArg(char *optarg);

// Packet sniffer functions
void printPacketInfo(const u_char *packet, struct pcap_pkthdr packetHeader);
void packetHandler(u_char *args, const struct pcap_pkthdr *packetHeader, const u_char *packetBody);
int capturePacket(char *dev);

/* main */
int main(int argc, char *argv[]){
    int opt, id;
    options_t options = {"", 0x0, stdout, false};
    // printf(getopt(argc, argv, OPTSTR));
    while ((opt = getopt(argc, argv, OPTSTR)) != EOF){
        switch(opt) {
            // To call showInterfaces function and print the interfaces' identifier
            case 's':
                showInterfaces();
                break;
            
            case 'i':
                options.intFace = optarg;
                printf("\n[!] STATUS: Opening device %s [!]\n", options.intFace);
                capturePacket(options.intFace);
                break;
            
            // To enable live packet capture
            case 'l':
                options.live = true;
                break;

            // To select a given interfaces by issuing the ID

            default:
                usage(USAGE_FMT);
                // using return to exit the while loop too, so no other helping message will be issued
                return -1;
        }
    }

    // If any given argument issues the helping message defined in USAGE_FMT
    if(argc < 2){
        usage(USAGE_FMT);
        return -1;
    }
    return 0;
}

/*-------Support functions-------*/
/* Function to show the available interfaces to the user */
void showInterfaces(){
    char error[PCAP_ERRBUF_SIZE];
    // pcap structure for interfaces
    pcap_if_t *interfaces, *temp;
    int i=0;
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
    fprintf(stderr, "%s\n%s\n", "[!] ERROR [!]", msg);
}

/*-------Packet sniffer functions-------*/
/* Function to start capturing packets */
int capturePacket(char *dev){
    pcap_t *handle;
    char *errbuf;
    char buf[256];
    const u_char *packet;
    struct pcap_pkthdr packetHeader;
    printf("[!] STATUS: Live capturing [!]\n");
    handle = pcap_open_live(dev, BUFSIZ, 1, 100000, errbuf);
    if (handle == NULL){
        sprintf(buf, "%s", errbuf);
        showError(buf);
        return -1;
    }
    packet = pcap_next(handle, &packetHeader);
    // checking if we haven't get any packets
    if(packet == NULL){
        showError("No packet found.");
        return -1;
    }
    /* Our function to output some info */
    printf("[!] STATUS: Showing results [!]\n");
    pcap_loop(handle, 0, packetHandler, capturePacket);
    // printPacketInfo(packet, packetHeader);
    return 1;
}

/* Function to handle every action on the packets */
void packetHandler(u_char *args, const struct pcap_pkthdr *packetHeader, const u_char *packetBody){
    printPacketInfo(packetBody, *packetHeader);
}

/* Function to print the info gathered from the packet */
void printPacketInfo(const u_char *packet, struct pcap_pkthdr packetHeader) {
    printf("Packet capture length: %d\n", packetHeader.caplen);
    printf("Packet total length %d\n", packetHeader.len);
}