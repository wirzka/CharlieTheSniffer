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
#define OPTSTR "s:li:h"
#define USAGE_FMT  "Usage for csniff:\n [-i ID] [-l] [-o] [-h] \n\
Example:\n ./csniff -i 1 -l \n\
Tips:\n To select an interface you have to provide the ID number.\n"
#define OUTFILENAME "ctscapture"
#define ERR_FOPEN_OUTPUT "fopen(output, w)"
#define ERR_DO_THE_NEEDFUL "Something went tremendously wrong. FLATLINE."
#define DEFAULT_PROGNAME "csniff"

extern int errno;
extern char *optarg;
extern int opterr, optind;


/* Structure to save arguments options */
typedef struct {
    int          intFace;
    u_int32_t    flags;
    FILE         *output;
    bool         live;
} options_t;

/* Functions prototypes */
void showInterfaces();
void usage(char *progname, int opt);
void showError(char *msg);
int checkArg(char *optarg);

/* main */
int main(int argc, char *argv[]){
    int opt, id;
    options_t options = { 0, 0x0, stdout, false };
    // printf(getopt(argc, argv, OPTSTR));
    while ((opt = getopt(argc, argv, OPTSTR)) != EOF){
        switch(opt) {
            // To call showInterfaces function and print the interfaces' identifier
            case 's':
                showInterfaces();
                break;
            
            case 'i':
                options.intFace = checkArg(optarg);
                if(options.intFace != -1)
                    printf("[+] You have opted for interface id: %d [+]\n", options.intFace);
                else
                    // call error
                    showError("Interface ID not valid.");
                break;
            
            // To enable live packet capture
            case 'l':
                options.live = true;
                break;

            // To select a given interfaces by issuing the ID

            default:
                usage(USAGE_FMT, opt);
                /* NOTREACHED */
                break;
        }
    }

    // If any given argument issues the helping message defined in USAGE_FMT
    if(argc < 2){
        usage(USAGE_FMT, opt);
        return 0;
    }
    
    if(options.live){
        printf("ok");
    }
    return 0;
}

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
            printf("\n%d : %s \n",i++,temp->name);
        }
    }
}

/* Function issuing the helping message */
void usage(char *progname, int opt){
    fprintf(stderr, progname?progname:DEFAULT_PROGNAME);
}

/* Function to standardise error output */
void showError(char *msg){
    fprintf(stderr, "%s\n%s\n", "[!] ERROR [!]", msg);
}

/* Function to check integeriness/positiveness the argument's option given with -i arg*/
int checkArg(char *optarg){
    if(isalpha(*optarg) != 0){
        return -1;
    }  else {
        int intArg = atoi(optarg);
        if(intArg < 0){
            return intArg * -1;
        } else {
            return intArg;
        }
    }
}