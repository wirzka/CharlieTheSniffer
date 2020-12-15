# CharlieTheSniffer
Charlie The Sniffer is a tool created by me for a university project. It is actually a basic packet sniffer written in very bad C.
## DOCs grabbed from the web
- [Tutorials Point for C](https://www.tutorialspoint.com/cprogramming/index.htm)
- [Official website for LibPcap](http://www.tcpdump.org/pcap.html) 
- [LibPcap in C](https://www.devdungeon.com/content/using-libpcap-c)

## Random ideas on how to bring it to life
1. Liberty to choose which interface to use (if wlan in -> what actually is monitor mode? Do we actually need it?)
2. Printing live capture on the terminal
3. Saving the capture on pcap files vs raw txt files (Can it be done?!)
4. Fixed time capture vs. time stopped by key combination
5. Which proto can we sniff by default?
6. Adding filter to sniff specific proto
7. It has to be a cmd line tool, so parsing argument at the beginning is a MUST -> help message is REQUIRED
8. Give the user the choice to sniff only his traffic or all traffic coming to his in

***Btw, KISS is your best friend.***
