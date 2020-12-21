# CharlieTheSniffer
Charlie The Sniffer is a tool created by me for a university project. It is actually a basic packet sniffer written in very bad C.
## DOCs grabbed from the web
- [Tutorials Point for C](https://www.tutorialspoint.com/cprogramming/index.htm)
- [Official website for LibPcap](http://www.tcpdump.org/pcap.html) 
- [LibPcap in C](https://www.devdungeon.com/content/using-libpcap-c)
- [Write a good C main fun](https://opensource.com/article/19/5/how-write-good-c-main-function)
- [Protocol numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
## Random ideas on how to bring it to life
1. Liberty to choose which interface to use (if wlan in -> what actually is monitor mode? Do we actually need it?)
2. Printing live capture on the terminal
3. Saving the capture on pcap files vs raw txt files (Can it be done?!)
4. Fixed time capture vs. time stopped by key combination
5. Which proto can we sniff by default?
6. Adding filter to sniff specific proto
7. It has to be a cmd line tool, so parsing argument at the beginning is a MUST -> help message is REQUIRED
8. Give the user the choice to sniff only his traffic or all traffic coming to his in

## Network packets format
Before going deeper with the code, in order to gain a better understanding of the logic and of the code, we have to understand how the data transmitted are formatted.
So let's begin.
(Add quick brief on TCP/IP behaviours)

### TCP Packet
The Tranmission Control Protocol packet is composed by a header, that includes all the options and details on how the packet should be handled, and a payload, containing the actual data transmitted.

Let's take a look at the header structure (source: [RFC 793](https://tools.ietf.org/html/rfc793)):

![TCP Header structure issued by RFC](./img/tcpheader.PNG)

Just to clarify, the first number row (0-3), are bytes (It indicates, the second number row are bits. Giving that, this is the map that we must follow to gather the right information from the TCP header. For example, we will need to know what will be the source port and the destination port of the given packet. In this case, we will have to fetch from the header the first 16 bytes for the former and the second 16 bytes for the latter. And so on for every other information that we will need.

### IP Packet
The Internet Protocol packet is similar to the TCP packet, it is composed by a header and a payload. So we will have again the map to follow.
Give it a look (source: [RFC 791](https://tools.ietf.org/html/rfc791)):

![IP Header structure issued by RFC](./img/ipheader.PNG)

### ICMP Packet
The Internet Control Message Protocol is a little bit different. It does not rely on a dedicated packet structure, but it is integrated with the IP header where we will find the number 1 inside the protocol flag, then the first octet of the data portion of the datagram is used as the ICMP type field, that will affect the following bits. 
The data field will differ based on which message will be provided.

The most common ICMP message is the ECHO/ECHO REPLY, unchained by the well known PING command.

It will be as follow (source [RFC 792](https://tools.ietf.org/html/rfc792)):

![ICMP ECHO message](./img/icmpecho.PNG)


### UDP Packet

***Btw, KISS is your best friend.***
