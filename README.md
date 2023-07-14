We have developed a powerful command line tool called "tcpgrep" that is used to filter the network traffic for displaying the TCP packets information based on a variety of criteria, including source and destination IP addresses, ports and protocols.This command line tool helps the user to get the required information on the TCP packets by using the following options. The command is tcpgrep and the options are:-  

o  For displaying help option , 
tcpgrep pcapfilename

o  To display the total number of tcp packets,
tcpgrep pcapfilename -t

o  To display the total number of incomplete tcpsession, 
tcpgrep pcapfilename -i

o  To display the incomplete tcpsessions with packet numbers, 
tcpgrep pcapfilename -in

o  To display the total number of rst packets,
tcpgrep pcapfilename -r

o  To display the total rst packets with packet number, 
tcpgrep pcapfilename -rn

o  To display the total number of duplicate ack packets, 
tcpgrep pcapfilename -a

o  To display the total number of duplicate ack packets with packet number,
tcpgrep pcapfilename -an

o  To dump specific range of tcp packet, tcpgrep pcapfile name -p packet range start – end range

Example: tcpgrep pcapfilename -p 2-10

o  To dump specific range of ports, tcpgrep pcapfile name -p: ip address:port no

Example: tcpgrep pcapfilename -p 192.168.4.5:443

o  To dump specified tcpflags, tcpgrep pcapfile name -pflags: A,P,F,U,S,R 

Example : tcpgrep pcapfilename -pA ,-pF,-pS,-pU,-pR,-pP
