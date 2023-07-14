/* This code is used to generate your own pcap file from the available interface in your system.*/

#include <pcap.h>
void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
int main(int argc, char **argv)
{
char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
pcap_t *handle; /*packet capture handle */
/* open capture device */
handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);/*any is the capture device and changes depending upon the computer which is used*/
if (handle == NULL) {
fprintf(stderr, "Error opening device: %s\n", errbuf);
return 1;
}
/* open PCAP file for writing */
pcap_dumper_t *dumper;
dumper = pcap_dump_open(handle, "cap.pcap");
if (dumper == NULL) {
fprintf(stderr, "Error opening PCAP file for writing: %s\n", pcap_geterr(handle));
pcap_close(handle);
return 1;
}
/* start packet capture loop */
if (pcap_loop(handle, -1, packet_handler, (u_char *)dumper) < 0) {
fprintf(stderr, "Error in packet capture loop: %s\n", pcap_geterr(handle));
pcap_dump_close(dumper);
pcap_close(handle);
return 1;
}
/* close PCAP file */
pcap_dump_close(dumper);
/* close capture device */
pcap_close(handle);
return 0;
}/* packet handler function */

void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
pcap_dump((u_char *)user, pkt_header, pkt_data);
}
