//$Id$
// system includes
#include <pcap.h>
#include <cstdio>

// C++ includes
#include <iostream>

using namespace std;

void 
h(u_char * useless, const struct pcap_pkthdr * pkthdr, const u_char * pkt)
{
	int             i;
	for (i = 0; i < 6; i++)
		printf("%02x:", pkt[i]);
	printf(" -> ");
	for (i = 0; i < 6; i++)
		printf("%02x:", pkt[i + 6]);

	printf("\n");

	return;
}
int 
main(void)
{
	int             pkt_cnt = 20;
	char           *pcap_dev = "em2";
	bpf_u_int32     net, mask;
	char            errbuff[1024];

	int             pcap_net = pcap_lookupnet(pcap_dev, &net, &mask, errbuff);
	pcap_t         *pcap_desc = pcap_open_live(pcap_dev, 100, 1, 1000, errbuff);
	perror("pcap_open_live");
	pcap_loop(pcap_desc, pkt_cnt, h, NULL);
}
