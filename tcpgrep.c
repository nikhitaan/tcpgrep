
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include<getopt.h>
#include<time.h>
#include<netinet/if_ether.h>

void display_help()
{
    printf("\n./tcpgrep <filename> <parameters> \n" 
        "-t Display total number of TCP packets\n"
       "-i Display total number of incomplete TCP sessions \n"
       "-in Display total number of incomplete TCP sessions with packet numbers \n"
       "-r Display total number of RST packets \n"
       "-rn Display total number of RST packets with packet numbers \n"
       "-a Display total number of duplicate TCP ack packets \n"
       "-an Display total number of duplicate TCP ack packets with packet numbers \n"
       "-p <num1> - <num2> Dump specific range of TCP packets. Dump one by one if no range is specified from first. \n"
       "-p <IP:port> Start dumping packets with specified IP:port \n"
       "-p <TCP Flag> Start dumping packets with specified TCP Flag.\n"
       "(U: Urgent A: Acknowledgement P: Push R: Reset S: Sync F: Fin)\n\n");
}
//....................................................................................................................


//display total tcp sessions
void display_total_tcp_packets(pcap_t *handle)
{
   // TODO: Implement function to display total number of TCP sessions
    int total_sessions = 0; // Variable to store the total number of TCP sessions
    struct pcap_pkthdr header;
    const u_char *packet;
    struct ip *iph;
    struct tcphdr *tcph;
    int tcp_packets = 0;
    // Loop through each packet in the pcap handle
    while (packet = pcap_next(handle, &header))
    {
#if 0
        iph = (struct ip *)(packet + 14); // Assuming Ethernet header is 14 bytes
        tcph = (struct tcphdr *)(packet + 14 + iph->ip_hl * 4); // Assuming IPv4 header length is in 32-bit words
         // Check if the packet is TCP
        if (iph->ip_p == IPPROTO_TCP)
         {
            // Increment the total number of sessions if it's a new TCP session
            if (tcph->syn == 1 && tcph->ack == 0)
             {
                total_sessions++;
             }
         }
#endif
        tcp_packets++;
    }
    printf("\nTotal number of TCP packets: %d\n", tcp_packets);
}
//....................................................................................................................


//display total incomplete tcp sessions
void display_total_incomplete_tcp_sessions(pcap_t *handle)
{
    // TODO: Implement function to display total number of incomplete TCP sessions
    int total_sessions = 0;
    struct pcap_pkthdr header;
    const u_char *packet;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    int packet_count = 0;
    while ((packet = pcap_next(handle, &header)) != NULL)
    {
      packet_count++;
      ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
      if (ip_header->protocol == IPPROTO_TCP)
      {
         tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
         if (tcp_header->fin == 0 && tcp_header->rst == 0 && tcp_header->ack == 1)
         {
            total_sessions++;
         }
      }
    }
    printf("\nTotal incomplete TCP sessions: %d\n", total_sessions);
}
//....................................................................................................................


//display incomplete tcp sessions with packet numbers
void display_incomplete_tcp_sessions_with_packet_numbers(pcap_t *handle) {
    struct pcap_pkthdr header;
    const u_char *packet;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    int packet_count = 0;
    int total_sessions = 0;
    printf("\n%-6s %-15s %-15s %-10s %-10s %-10s %-10s %-10s %-10s %-1s %-1s %-1s %-1s %-1s %-1s\n",
        "Packet", "SrcIP", "DstIP", "SrcPort", "DstPort", "seqno", "ackno", "wndsize", "chcksum", "U", "A", "P", "R", "S", "F");
    while ((packet = pcap_next(handle, &header)) != NULL) {
        packet_count++;
        ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
        
        if (ip_header->protocol == IPPROTO_TCP) {
            tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
            
            if (tcp_header->fin == 0 && tcp_header->rst == 0 && tcp_header->ack == 1) {
                total_sessions++;
               
                printf("%-6d ", packet_count);
                printf("%-15s ", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
                printf("%-15s ", inet_ntoa(*(struct in_addr *)&ip_header->daddr));
                printf("%-10d ", ntohs(tcp_header->source));
                printf("%-10d ", ntohs(tcp_header->dest));
                printf("%-10u ", ntohl(tcp_header->seq));
                printf("%-10u ", ntohl(tcp_header->ack_seq));
                printf("%-10d ", ntohs(tcp_header->window));
                printf("%-10u ", ntohs(tcp_header->check));
                printf("%-1d ", tcp_header->urg);
                printf("%-1d ", tcp_header->ack);
                printf("%-1d ", tcp_header->psh);
                printf("%-1d ", tcp_header->rst);
                printf("%-1d ", tcp_header->syn);
                printf("%-1d\n", tcp_header->fin);
            }
        }
    }
   
    printf("\nTotal incomplete TCP sessions: %d\n", total_sessions);
}
//....................................................................................................................


// display total rst packets
void display_total_rst_packets(pcap_t *handle)
{
    // TODO: Implement function to display total number of RST packets
    struct pcap_pkthdr header;
    const u_char *packet;
    int packet_count = 0;
    int rst_count = 0;
    while (packet = pcap_next(handle, &header))
    {
        struct ip *ip_hdr = (struct ip*)(packet + sizeof(struct ethhdr));
        struct tcphdr *tcp_hdr = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
        if (ip_hdr->ip_p == IPPROTO_TCP && tcp_hdr->rst)
        {
            rst_count++;
        }
        packet_count++;
    }
    printf("Total number of TCP RST packets: %d\n", rst_count);
}
//....................................................................................................................


//display rst packets with packet numbers
void display_rst_packets_with_packet_numbers(pcap_t *handle) {
    // TODO: Implement function to display total number of RST packets with packet numbers
    struct pcap_pkthdr header;
    const u_char *packet;
    int packet_count = 0;
    int rst_count = 0;
    u_int ip_header_length;
    struct ip *ip_hdr;
    struct tcphdr *tcp_header;
    printf("\n%-6s %-15s %-15s %-10s %-10s %-10s %-10s %-10s %-10s %-1s %-1s %-1s %-1s %-1s %-1s\n",
        "Packet", "SrcIP", "DstIP", "SrcPort", "DstPort", "seqno", "ackno", "wndsize", "chcksum", "U", "A", "P", "R", "S", "F");
   while (packet = pcap_next(handle, &header)) {
        ip_hdr = (struct ip*)(packet + sizeof(struct ethhdr));
        tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
        
      if (ip_hdr->ip_p == IPPROTO_TCP && tcp_header->rst) {
        printf("%-6d ",packet_count);
        printf("%-15s ", inet_ntoa(ip_hdr->ip_src));
        printf("%-15s ", inet_ntoa(ip_hdr->ip_dst));
        printf("%-10d ", ntohs(tcp_header->source));
        printf("%-10d ", ntohs(tcp_header->dest));
        printf("%-10u ", ntohl(tcp_header->seq));
        printf("%-10u ", ntohl(tcp_header->ack_seq));
        printf("%-10d ", ntohs(tcp_header->window));
        printf("%-10u ", ntohs(tcp_header->check));
        printf("%-1d ", tcp_header->urg);
        printf("%-1d ", tcp_header->ack);
        printf("%-1d ", tcp_header->psh);
        printf("%-1d ", tcp_header->rst);
        printf("%-1d ", tcp_header->syn);
        printf("%-1d\n", tcp_header->fin);
        rst_count++;
      }
      packet_count++;
    }

    printf("\nTotal number of TCP RST packets: %d\n", rst_count);
}
//....................................................................................................................


//display total duplicate tcp ack packets
void display_total_duplicate_tcp_ack_packets(pcap_t *handle)
{
    // TODO: Implement function to display total number of duplicate TCP ack packets
    // Variables to keep track of packet counts
    int total_packets = 0;
    int total_dup_ack_packets = 0;
    // Loop to process each packet in the capture file
    struct pcap_pkthdr header;
    const u_char *packet;
    while ((packet = pcap_next(handle, &header)) != NULL)
     {
        total_packets++;
        // Extract IP and TCP header from the packet
        struct ip *iph = (struct ip *)(packet + 14);
        struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ip_hl * 4);
        // Check if the packet is TCP ACK packet
        if (tcph->ack == 1 && tcph->syn == 0 && tcph->fin == 0 && tcph->rst == 0 && tcph->psh == 0 && tcph->urg == 0)
        {
            // Extract ACK number from the TCP header
            uint32_t ack_num = ntohl(tcph->ack_seq);
            // Check if the ACK number is same as the previous ACK number
            static uint32_t prev_ack_num = 0;
            if (ack_num == prev_ack_num)
            {
                total_dup_ack_packets++;
            }
            prev_ack_num = ack_num;
         }
      }
    // Display the total number of duplicate TCP ACK packets
    //printf("Total Packets: %d\n", total_packets);
    printf("Total Duplicate TCP ACK Packets: %d\n", total_dup_ack_packets);
}
//....................................................................................................................


//display duplicate tcp ack packets with packet numbers
void display_duplicate_tcp_ack_packets_with_packet_numbers(pcap_t *handle)
{
    // TODO: Implement function to display total number of duplicate TCP ack packets with packet numbers
    // Variables to keep track of packet counts and ACK numbers
    int total_packets = 0;
    int total_dup_ack_packets = 0;

    // Loop to process each packet in the capture file
    struct pcap_pkthdr header;
    const u_char *packet;
    printf("\n%-6s %-15s %-15s %-10s %-10s %-10s %-10s %-10s %-10s %-1s %-1s %-1s %-1s %-1s %-1s\n",
        "Packet", "SrcIP", "DstIP", "SrcPort", "DstPort", "seqno", "ackno", "wndsize", "chcksum", "U", "A", "P", "R", "S", "F");
    while ((packet = pcap_next(handle, &header)) != NULL)
     {
         total_packets++;
        // Extract IP and TCP header from the packet
        struct ip *iph = (struct ip *)(packet + 14);
        struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ip_hl * 4);
        // Check if the packet is TCP ACK packet
        if (tcph->ack == 1 && tcph->syn == 0 && tcph->fin == 0 && tcph->rst == 0 && tcph->psh == 0 && tcph->urg == 0)
        {
            // Extract ACK number from the TCP header
            uint32_t ack_num = ntohl(tcph->ack_seq);
            // Check if the ACK number is same as the previous ACK number
            static uint32_t prev_ack_num = 0;
            if (ack_num == prev_ack_num)
            {
                total_dup_ack_packets++;
                // Print packet number, source and destination IP addresses and port numbers
                          printf("%-6d ", total_packets);
                          printf("%-15s ", inet_ntoa(iph->ip_src));
                          printf("%-15s ", inet_ntoa(iph->ip_dst));
                          printf("%-10d ", ntohs(tcph->source));
                          printf("%-10d ", ntohs(tcph->dest));
                          printf("%-10u ", ntohl(tcph->seq));
                          printf("%-10u ", ntohl(tcph->ack_seq));
                          printf("%-10d ", ntohs(tcph->window));
                          printf("%-10u ", ntohs(tcph->check));
                          printf("%-1d ", tcph->urg);
                          printf("%-1d ", tcph->ack);
                          printf("%-1d ", tcph->psh);
                          printf("%-1d ", tcph->rst);
                          printf("%-1d ", tcph->syn);
                          printf("%-1d\n", tcph->fin);
            }
            prev_ack_num = ack_num;
       }
    }
    // Display the total number of duplicate TCP ACK packets
    printf("Total Duplicate TCP ACK Packets: %d\n", total_dup_ack_packets);
}
//....................................................................................................................


//dump specific range of tcp packets
void dump_tcp_packets(pcap_t *handle, int start, int end) {
    if (start > end || start < 1) {
        printf("Invalid range. Please provide valid start and end values.\n");
        return;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int packet_count = start;
    //printf("\nstart=%d, end=%d\n", start, end);
    printf("\n%-6s %-15s %-15s %-10s %-10s %-10s %-10s %-10s %-10s %-1s %-1s %-1s %-1s %-1s %-1s\n",
        "Packet", "SrcIP", "DstIP", "SrcPort", "DstPort", "seqno", "ackno", "wndsize", "chcksum", "U", "A", "P", "R", "S", "F");

    for (int i = 1; i <= end; i++) {
        if (pcap_next_ex(handle, &header, &packet) == 0) {
            break;
        }
        if (i < start) {
            continue;
        }
        printf("%-6d ", packet_count);
        packet_count++;

        /* Check if packet is TCP */
        struct iphdr *ip_header;
        ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
        if (ip_header->protocol != IPPROTO_TCP) {
           continue;
        }

        /* Print source and destination IP addresses */
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = ip_header->saddr;
        dst_addr.s_addr = ip_header->daddr;
        printf("%-15s ", inet_ntoa(src_addr));
        printf("%-15s ", inet_ntoa(dst_addr));
        /* Print the TCP header */
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));
        printf("%-10d ", ntohs(tcp_header->source));
        printf("%-10d ", ntohs(tcp_header->dest));
        printf("%-10u ", ntohl(tcp_header->seq));
        printf("%-10u ", ntohl(tcp_header->ack_seq));
        printf("%-10d ", ntohs(tcp_header->window));
        printf("%-10u ", ntohs(tcp_header->check));
        printf("%-1d ", tcp_header->urg);
        printf("%-1d ", tcp_header->ack);
        printf("%-1d ", tcp_header->psh);
        printf("%-1d ", tcp_header->rst);
        printf("%-1d ", tcp_header->syn);
        printf("%-1d\n", tcp_header->fin);
    }
}
//....................................................................................................................


//Start dumping packets with specified IP port
void dump_tcp_packets_with_ip_port(pcap_t *handle, char *ip_port) {
    struct pcap_pkthdr header;
    const u_char *packet;
    int packet_count = 1;
    char *ip_param = NULL;
    short port_param = 0;
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    char *token = NULL;
    if((token = strtok(ip_port, ":"))){
      //ip_param = (unsigned int)inet_addr(token);
      ip_param = token;
      token = strtok(NULL, ":");
      port_param = atoi(token);
    }
    //printf("\n %s:%d\n", ip_param, port_param);
    printf("\n%-6s %-15s %-15s %-10s %-10s %-10s %-10s %-10s %-10s %-1s %-1s %-1s %-1s %-1s %-1s\n",
        "Packet", "SrcIP", "DstIP", "SrcPort", "DstPort", "seqno", "ackno", "wndsize", "chcksum", "U", "A", "P", "R", "S", "F");
    while ((packet = pcap_next(handle, &header)) != NULL) {
        struct iphdr *ip_header = NULL;
        ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
        if (ip_header->protocol != IPPROTO_TCP){
          continue;
        }
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = ip_header->saddr;
        dst_addr.s_addr = ip_header->daddr;
        
        //printf("\nport=%d\n", ntohs(tcp_header->source));
        //printf("\nip=%s\n", inet_ntoa(src_addr));
        struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
        if (((ntohs(tcp_header->dest) == port_param) || 
            (ntohs(tcp_header->source) == port_param)) &&
            ((strcmp(inet_ntoa(src_addr), ip_param) == 0) ||
             (strcmp(inet_ntoa(dst_addr), ip_param) == 0))) {
            inet_ntop(AF_INET, &ip_header->saddr, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &ip_header->daddr, dest_ip, sizeof(dest_ip));
            printf("%-6d ", packet_count);
            printf("%-15s ", inet_ntoa(src_addr));
            printf("%-15s ", inet_ntoa(dst_addr));
            printf("%-10d ", ntohs(tcp_header->source));
            printf("%-10d ", ntohs(tcp_header->dest));
            printf("%-10u ", ntohl(tcp_header->seq));
            printf("%-10u ", ntohl(tcp_header->ack_seq));
            printf("%-10d ", ntohs(tcp_header->window));
            printf("%-10u ", ntohs(tcp_header->check));
            printf("%-1d ", tcp_header->urg);
            printf("%-1d ", tcp_header->ack);
            printf("%-1d ", tcp_header->psh);
            printf("%-1d ", tcp_header->rst);
            printf("%-1d ", tcp_header->syn);
            printf("%-1d\n", tcp_header->fin);
            packet_count += header.len;
        }
    }
}
//....................................................................................................................



//Start dumping packets with specified TCP flag
void dump_tcp_packets_with_tcp_flag(pcap_t *handle, u_int8_t tcp_flag) {
  // TODO: Implement function to dump TCP packets with specified TCP flag
  struct pcap_pkthdr header;
  const u_char *packet;
  int packet_count = 1;
  int flag_count = 0;
  u_int ip_header_length;
  struct iphdr *ip_hdr;
  struct tcphdr *tcp_hdr;
  printf("\n%-6s %-15s %-15s %-10s %-10s %-10s %-10s %-10s %-10s %-1s %-1s %-1s %-1s %-1s %-1s\n",
      "Packet", "SrcIP", "DstIP", "SrcPort", "DstPort", "seqno", "ackno", "wndsize", "chcksum", "U", "A", "P", "R", "S", "F");
  while (packet = pcap_next(handle, &header)) {
    ip_hdr = (struct iphdr*)(packet + sizeof(struct ethhdr));
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip_hdr->saddr;
    dst_addr.s_addr = ip_hdr->daddr;
    tcp_hdr = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header_length);
    if ((ip_hdr->protocol == IPPROTO_TCP) && (tcp_hdr->th_flags & tcp_flag)) {
      //printf("\nflag=%x, tcp_flag=%x\n", tcp_hdr->th_flags, tcp_flag);
      printf("%-6d ", packet_count);
      printf("%-15s ", inet_ntoa(src_addr));
      printf("%-15s ", inet_ntoa(dst_addr));
      printf("%-10d ", ntohs(tcp_hdr->source));
      printf("%-10d ", ntohs(tcp_hdr->dest));
      printf("%-10u ", ntohl(tcp_hdr->seq));
      printf("%-10u ", ntohl(tcp_hdr->ack_seq));
      printf("%-10d ", ntohs(tcp_hdr->window));
      printf("%-10u ", ntohs(tcp_hdr->check));
      printf("%-1d ", tcp_hdr->urg);
      printf("%-1d ", tcp_hdr->ack);
      printf("%-1d ", tcp_hdr->psh);
      printf("%-1d ", tcp_hdr->rst);
      printf("%-1d ", tcp_hdr->syn);
      printf("%-1d\n", tcp_hdr->fin);
      flag_count++;
    }
    packet_count++;
  }
}
//....................................................................................................................



//TCP PARAMETERS READING FROM PCAP FILE
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
static int count = 0;
    struct tcphdr *tcp_header;
    int tcp_header_length;
     struct iphdr *ip;
     struct iphdr *iphdr = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));

    // Extract the TCP header
    tcp_header = (struct tcphdr *)(pkt_data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    tcp_header_length = tcp_header->doff * 4;
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    // Extract the IP header
    iphdr = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));

    // Extract the source and destination IP addresses
    inet_ntop(AF_INET, &(iphdr->saddr), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iphdr->daddr), dest_ip, INET_ADDRSTRLEN);

     // Print the source and destination IP addresses
    printf("%d\t", ++count);
    printf("%s\t", source_ip);
    printf("%s\t", dest_ip);

    // Extract all TCP parameters
   // printf("Source address:%d\n", inet_ntoa(*(struct in_addr *)&iphdr->saddr));
   // printf("Destination address:%d\n",inet_ntoa(*(struct in_addr *)&iphdr->daddr));
    printf("%d\t", ntohs(tcp_header->source));
    printf("\t%d\t", ntohs(tcp_header->dest));
    printf("\t%u\t", ntohl(tcp_header->seq));
    printf("%u\t", ntohl(tcp_header->ack_seq));
    printf("%d\t", tcp_header->urg);
    printf("%d\t",tcp_header->ack);
    printf("%d\t", tcp_header->psh);
    printf("%d\t", tcp_header->rst);
    printf("%d\t", tcp_header->syn);
    printf("%d\t", tcp_header->fin);
    printf("%d\t", ntohs(tcp_header->window));
    printf("%d\t", ntohs(tcp_header->check));
    //printf("%d\t", ntohs(tcp_header->urg_ptr));
    printf("\n");
}

// Funtion removing spaces from string
char * removeSpacesFromStr(char *string)
{
    // non_space_count to keep the frequency of non space characters
    int non_space_count = 0;
 
    //Traverse a string and if it is non space character then, place it at index non_space_count
    for (int i = 0; string[i] != '\0'; i++)
    {
        if (string[i] != ' ')
        {
            string[non_space_count] = string[i];
            non_space_count++;//non_space_count incremented
        }    
    }
    
    //Finally placing final character at the string end
    string[non_space_count] = '\0';
    return string;
}

// MAIN FUNCTION
int main(int argc, char **argv) {
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program filter;
  bpf_u_int32 mask;
  bpf_u_int32 net;
  struct iphdr *ip;
  pcap_t *handle = NULL;
  char *filename=argv[1];
  char *option = argv[2];
  char *packet_range = NULL;

  if (option == NULL || (strcmp(argv[1], "-h") == 0)) {
    display_help();
    return -1;
  }
  // Open the pcap file
  handle = pcap_open_offline(argv[1], errbuf);
  if (pcap_compile(handle, &filter, "tcp", 0, net) == -1) {
    fprintf(stderr, "Error compiling filter expression: %s\n", pcap_geterr(handle));
    return 1;
  }
  if (handle == NULL) {
    fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
    return 1;
  }
#if 0
  if(option==NULL)
  {
    if(strcmp(filename,argv[1]) == 0) {
      if (pcap_compile(handle, &filter, "tcp", 0, net) == -1) {
        fprintf(stderr, "Error compiling filter expression: %s\n", pcap_geterr(handle));
        return 1;
      }

      // Apply the filter expression
      if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Error setting filter expression: %s\n", pcap_geterr(handle));
        return 1;
      }

      // Loop through the packets in the pcap file
      printf("PkNo\tSrc IP\t\tDst IP\t\tSrc port\tDst port\tSeqnum\t\tAcknum\t\tURG\tACK\tPSH\tRST\tSYN\tFIN\tWnd\tChk\n");
      if (pcap_loop(handle,0, packet_handler, NULL) == -1) {
        fprintf(stderr, "Error reading packets: %s\n", pcap_geterr(handle));
        //return 1;
      }
    }
  }
#endif
  {
    if (strcmp(option, "-t") == 0) {
      display_total_tcp_packets(handle);
    } else if (strcmp(option, "-i") == 0) {
      display_total_incomplete_tcp_sessions(handle);
    } else if (strcmp(option, "-in") == 0) {
      display_incomplete_tcp_sessions_with_packet_numbers(handle);
    } else if (strcmp(option, "-r") == 0) {
      display_total_rst_packets(handle);
    } else if (strcmp(option, "-rn") == 0) {
      display_rst_packets_with_packet_numbers(handle);
    } else if (strcmp(option, "-a") == 0) {
      display_total_duplicate_tcp_ack_packets(handle);
    } else if (strcmp(option, "-an") == 0) {
      display_duplicate_tcp_ack_packets_with_packet_numbers(handle);
    } else if (strncmp(option, "-p", 2) == 0) {
      //printf("\noption=%s, strlen=%d\n", option, (int)strlen(option));
      /* Parse command line arguments */
      if (argc < 3 || argc > 4) {
        printf("Usage: %s <filename> -p <start>-<end>\n", argv[0]);
        return 1;
      }
      int start, end;
      char *token = NULL;
      if (strlen(option) == 2) {
        packet_range = argv[3];
      } else {
        packet_range = argv[2] + 2;
      }
      removeSpacesFromStr(packet_range);
      //printf("\n(%s)\n", packet_range);

      if(strchr(packet_range, ':')!=NULL) {
        dump_tcp_packets_with_ip_port(handle, packet_range);
        return 0;
      }
      /* Extract start and end packet numbers from packet_range */
      token = strtok(packet_range, "-");
      if(token){
        //printf("\nstart=%s\n", token);
        start = atoi(token);
        token = strtok(NULL, "-");
        if (token == NULL) {
          if (strchr("UAPRSF", *packet_range)) {
            u_int8_t tcp_flag_bit;
            if(*packet_range == 'U'){
              tcp_flag_bit = TH_URG; 
            } else if(*packet_range == 'A'){
              tcp_flag_bit = TH_ACK; 
            } else if(*packet_range == 'P'){
              tcp_flag_bit = TH_PUSH; 
            } else if(*packet_range == 'R'){
              tcp_flag_bit = TH_RST; 
            } else if(*packet_range == 'S'){
              tcp_flag_bit = TH_SYN; 
            } else if(*packet_range == 'F'){
              tcp_flag_bit = TH_FIN; 
            }
            //printf("\nTCP_FLAG=%x\n", tcp_flag_bit);
            dump_tcp_packets_with_tcp_flag(handle, tcp_flag_bit);
            return 0;
          }
          printf("Invalid packet range: %s\n", packet_range);
          return 1;
        }
        else {
          end = atoi(token);
        }
        dump_tcp_packets(handle, start,end);
      }
    }
    else {
      fprintf(stderr, "Invalid option: %s\n", option);
      return 1;
    }
  }
  // Close the pcap file
  pcap_close(handle);
 

  return 0;
}
