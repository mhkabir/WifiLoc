#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>
#include "radiotap-parser.h"

static int pcount = 1;
int i = 0;
int pwr = 0;

uint8_t smac[6];
uint8_t dmac[6];
char* device = "mon0";
char* bpfstr = "wlan subtype probe-req"; 

char errbuf[PCAP_ERRBUF_SIZE];
pcap_t* pd;
uint32_t srcip, netmask;
struct bpf_program bpf;

void callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	struct ieee80211_radiotap_iterator rti;
	struct ieee80211_radiotap_header *rth = ( struct ieee80211_radiotap_header * ) packet;
	int ret = ieee80211_radiotap_iterator_init(&rti, rth, rth->it_len);
	uint16_t mac_len = rth->it_len + 4;

	printf("\nPacket number [%d], length of this packet is: %d\n", pcount++, pkthdr->len);

	while(i < 6)
	{
		dmac[i++] = packet[mac_len++];
	}
	i=0;
	mac_len = rth->it_len + 10;
	while(i < 6)
	{
		smac[i++] = packet[mac_len++];
	}
	printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
         smac[0] & 0xff, smac[1] & 0xff, smac[2] & 0xff,
         smac[3] & 0xff, smac[4] & 0xff, smac[5] & 0xff);
	printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
         dmac[0] & 0xff, dmac[1] & 0xff, dmac[2] & 0xff,
         dmac[3] & 0xff, dmac[4] & 0xff, dmac[5] & 0xff);


while(ret != -1) {
  ret = ieee80211_radiotap_iterator_next(&rti);
	
  switch(rti.this_arg_index) {
	case IEEE80211_RADIOTAP_RX_FLAGS:
	{
		if(*rti.this_arg == IEEE80211_RADIOTAP_F_RX_BADFCS)
		{
			return;
		}
	break;
	}
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
	{
        	pwr = (uint8_t)*rti.this_arg-256;
		printf("Power dBm: %d\n", pwr);
                break;
	}

  default:
       break;
  }
}


}

void initSniffer()
{
if ((pd = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL)
{
system("sudo airmon-ng start wlan0");
if ((pd = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL)
{
printf("pcap_open_live(): %s\n", errbuf);
return ;
}
}
printf("Opened capture\n");
if (pcap_compile(pd, &bpf, (char*)bpfstr, 0, PCAP_NETMASK_UNKNOWN))
{
printf("pcap_compile(): %s\n", pcap_geterr(pd));
return ;
}
// Assign the packet filter to the given libpcap socket.
if (pcap_setfilter(pd, &bpf) < 0)
{
printf("pcap_setfilter(): %s\n", pcap_geterr(pd));
return ;
}
printf("Packet filtering started\n");
printf("Starting main sniffer thread\n");
pcap_loop(pd, 1000, callback, NULL);
}


int main(int argc,char **argv)
{

	initSniffer();
	
}




