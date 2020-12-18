#include <stdio.h>
#include <pcap.h>

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
        printf("Error in pcap findall devs");
    }
    else{
        printf("The interfaces are:");
        for(temp=interfaces;temp;temp=temp->next){
            printf("\n%d : %s \n",i++,temp->name);
        }
    }
}

/* Function issuing the helping message */
void usage(){

}

int main(int argc, char *argv[]){
    if(argc != 2){
        printf("No man\n");
        return 0;
    }
    if(*argv[1] == 'y'){
        showInterfaces();
    }
    else if(isdigit(*argv[1])){
        printf("YAY");
    }
    else if(argc < 1 || argc > 1){
        printf("No input entered.");
    }
    else{
        printf("Nope");
    }
    return 0;
}