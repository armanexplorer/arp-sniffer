/*
Simple ARP sniffer to detect ip conflict
*/

#include "stdio.h"
#include "winsock2.h"	// To use inet_ntoa and ntohs functions
#include "ws2tcpip.h"   // To use socklen_t type and getnameinfo function

#define MAC_IP_START        22      // Start byte of MAC and IP address in ARP packet
#define ETHERTYPE_ARP		0x0806	// Arch Ethernet Type
#define MAC_FORMAT          "%02X:%02X:%02X:%02X:%02X:%02X"
#define IP_FORMAT           "%d.%d.%d.%d"
#define MAC_PARTS(a)        a[0], a[1], a[2], a[3], a[4], a[5]
#define IP_PARTS(a)         a[0], a[1], a[2], a[3]
#define MAC_EQUAL(a,b)      (a[0]==b[0])&&(a[1]==b[1])&&(a[2]==b[2])&&(a[3]==b[3])&&(a[4]==b[4])&&(a[5]==b[5])
#define IP_EQUAL(a,b)       (a[0]==b[0])&&(a[1]==b[1])&&(a[2]==b[2])&&(a[3]==b[3])

#define HAVE_REMOTE
#include "pcap.h"   // Winpcap package


// Ethernet Header
typedef struct ethernet_header
{
	UCHAR dest[6];
	UCHAR source[6];
	USHORT type;
}   ETHER_HDR , *PETHER_HDR , FAR * LPETHER_HDR , ETHERHeader;

// Host Mac and IP address
typedef struct host_mac_and_ip {
    u_char mac[6];
    u_char	ip[4];
} Host;


// Functions declaration
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);           
void DumpDevices(pcap_if_t*);
void DumpAddresses(pcap_addr_t*);
void ProcessPacket (u_char*);
void PrintARPPacket(u_char*);
void PrintHostsList();
void PrintHost(Host);
void VerboseDumpDevices(pcap_if_t*);
char* iptos(u_short, struct sockaddr*, char*, int);
void IFPrint(pcap_if_t*);
void NtopIFPrint(pcap_if_t*);

// Global variables
FILE *logfile;
Host hosts[256];
u_int hosts_counter=0, i;
pcap_if_t *d;


int main()
{
	u_int res , inum ;
	u_char errbuf[PCAP_ERRBUF_SIZE] , buffer[100];
	u_char *pkt_data;
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	struct pcap_pkthdr *header;

	fopen_s(&logfile , "log.txt" , "w");
	
	if(logfile == NULL) 
	{
		printf("Unable to create file.");
	}

	// The user didn't provide a packet source: Retrieve the local device list
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        return -1;
    }

    // Print devices (you can use 'DumpDevices' function instead)
    VerboseDumpDevices(alldevs);

    if (i==0)
    {
        fprintf(stderr,"No interfaces found! Exiting.\n");
        return -1;
    }
    
	printf("Enter the interface number you would like to sniff : ");
	scanf("%d" , &inum);

	
	// Jump to the selected adapter
    for (d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
        

    // Open the device 
    if ( (fp= pcap_open(d->name,
                        100 , // snaplen
                        PCAP_OPENFLAG_PROMISCUOUS, // flags
                        20, // read timeout
                        NULL, // remote authentication
                        errbuf)
                        ) == NULL)
    {
        fprintf(stderr,"\nError opening adapter\n");
        return -1;
    }

	// Read packets in a loop
    while((res = pcap_next_ex( fp, &header, (const u_char **)&pkt_data)) >= 0)
    {
        if(res == 0)
		{
            // Timeout elapsed
            continue;
		}
		ProcessPacket(pkt_data);
    }
	
	if(res == -1)
    {
        fprintf(stderr, "Error reading the packets: %s\n" , pcap_geterr(fp) );
        return -1;
    }
	
    pcap_freealldevs(alldevs);
	return 0;
}

void DumpDevices(pcap_if_t *devs){
    i = 0;
    for(d=devs; d; d=d->next)
    {
        printf("%d. %s\n    ", ++i, d->name);
        if (d->description)
        {
            printf(" (%s)\n", d->description);
        }
        else
        {
            printf(" (No description available)\n    ");
        }
        printf("\tAddresses:\n");
        DumpAddresses(d->addresses);
        printf("\n\n");
    }
}

void DumpAddresses(pcap_addr_t *addrs){
    while (addrs){
        struct sockaddr_in *ip = (struct sockaddr_in *)addrs->addr;
        if (ip)
        printf("\t\t%s ",
            inet_ntoa(ip->sin_addr));
        addrs = addrs->next;
    }
}

void ProcessPacket(u_char* Buffer)
{
	// Ethernet header
	ETHER_HDR *ethhdr = (ETHER_HDR *)Buffer;
	
	// Check the received packet type is ARP
	if(ntohs(ethhdr->type) == ETHERTYPE_ARP)  // it's ARP packet
	{
        printf("\n  ------------------------- NEW ARP PACKET  ------------------------- \n");

		int conflict_host_index=-1, mac_found=0, is_equal_ip=0, is_equal_mac=0;
        char buffer[1024];

        // Read host mac and ip address
        Host *host = (Host*)(Buffer+MAC_IP_START);

        // Check the exsistance of the sender IP and MAC
        // Alert if we have new host, new ip for exsiting host, or ip conflicts
        for(int i=0;i<hosts_counter;i++){
            is_equal_ip = IP_EQUAL(hosts[i].ip, host->ip);
            is_equal_mac = MAC_EQUAL(hosts[i].mac, host->mac);

            // We have two host with same ip -> Conflict Alert
            if(is_equal_ip &&  !is_equal_mac)
            {
                snprintf(buffer, sizeof(buffer),
                    "\n****: Conflict detected!: %s and %s both have assigend to %s\n",
                    MAC_FORMAT, MAC_FORMAT, IP_FORMAT);
                printf(buffer, MAC_PARTS(hosts[i].mac), MAC_PARTS(host->mac), IP_PARTS(hosts[i].ip));
            }
            // We had this host before but maybe its IP has changed
            else if(is_equal_mac)
            {
                mac_found=1;
                // A host IP is updated -> Updating Alert
                if (!is_equal_ip){
                    hosts[i] = *host;
                    snprintf(buffer, sizeof(buffer),"\n***: Host %s updated with IP %s\n", MAC_FORMAT, IP_FORMAT);
                    printf(buffer, MAC_PARTS(host->mac), IP_PARTS(host->ip));
                }
            }
        }
        // We have recognized a new host -> Adding Alert
        if(!mac_found){
            snprintf(buffer, sizeof(buffer),"\n***: Host %s Added with IP %s\n", MAC_FORMAT, IP_FORMAT);
            printf(buffer, MAC_PARTS(host->mac), IP_PARTS(host->ip));
            hosts[hosts_counter++] = *host;
        }

        PrintHostsList();
	}	
}

void PrintHostsList(){
    printf("\nHosts:\n");
    for(int i=0;i<hosts_counter;i++)
        PrintHost(hosts[i]);
    printf("\n");
}

void PrintHost(Host host){
    char buffer[1024];
    snprintf(buffer, sizeof(buffer), "\n%s\n%s\n", MAC_FORMAT, IP_FORMAT);
    printf(buffer, MAC_PARTS(host.mac), IP_PARTS(host.ip));
}


// Verbose functions
void VerboseDumpDevices(pcap_if_t *devs){
    i=0;
    printf("\n");
    for(d=devs; d; d=d->next){
        printf("#%d)\n", ++i);
        NtopIFPrint(d); // IFPrint can be used instead
    }
}

void IFPrint(pcap_if_t *d)
{
  pcap_addr_t *a;
  char ip6str[INET6_ADDRSTRLEN];
  char ipstr[INET_ADDRSTRLEN];

  /* Name */
  printf("%s\n",d->name);

  /* Description */
  if (d->description)
    printf("\tDescription: %s\n",d->description);

  /* Loopback Address*/
  printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

  /* IP addresses */
  for(a=d->addresses;a;a=a->next) {
    printf("\tAddress Family: #%d\n",a->addr->sa_family);
  
    switch(a->addr->sa_family)
    {
      case AF_INET:
        printf("\tAddress Family Name: AF_INET\n");
        if (a->addr)
          printf("\tAddress: %s\n",iptos(AF_INET, a->addr, ipstr, sizeof(ipstr)));
        if (a->netmask)
          printf("\tNetmask: %s\n",iptos(AF_INET, a->netmask, ipstr, sizeof(ipstr)));
        if (a->broadaddr)
          printf("\tBroadcast Address: %s\n",iptos(AF_INET, a->broadaddr, ipstr, sizeof(ipstr)));
        if (a->dstaddr)
          printf("\tDestination Address: %s\n",iptos(AF_INET, a->dstaddr, ipstr, sizeof(ipstr)));
        break;

      case AF_INET6:
        printf("\tAddress Family Name: AF_INET6\n");
        if (a->addr)
          printf("\tAddress: %s\n", iptos(AF_INET6, a->addr, ip6str, sizeof(ip6str)));
       break;

      default:
        printf("\tAddress Family Name: Unknown\n");
        break;
    }
  }
  printf("\n");
}

void NtopIFPrint(pcap_if_t *d)
{
  pcap_addr_t *a;
  char ip6str[INET6_ADDRSTRLEN];

  /* Name */
  printf("%s\n",d->name);

  /* Description */
  if (d->description)
    printf("\tDescription: %s\n",d->description);

  /* Loopback Address*/
  printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

  /* IP addresses */
  for(a=d->addresses;a;a=a->next) {
    printf("\tAddress Family: #%d\n",a->addr->sa_family);
  
    switch(a->addr->sa_family)
    {
      case AF_INET:
        printf("\tAddress Family Name: %s\n", a->addr->sa_family == AF_INET ? "AF_INET":"AF_INET6");
      case AF_INET6:      
        if (a->addr)
          printf("\tAddress: %s\n",inet_ntop(AF_INET, &(((struct sockaddr_in *)a->addr)->sin_addr), ip6str, sizeof(ip6str)));
        if (a->netmask)
          printf("\tNetmask: %s\n",inet_ntop(AF_INET, &(((struct sockaddr_in *)a->netmask)->sin_addr), ip6str, sizeof(ip6str)));
        if (a->broadaddr)
          printf("\tBroadcast Address: %s\n",inet_ntop(AF_INET, &(((struct sockaddr_in *)a->broadaddr)->sin_addr), ip6str, sizeof(ip6str)));
        if (a->dstaddr)
          printf("\tDestination Address: %s\n",inet_ntop(AF_INET, &(((struct sockaddr_in *)a->dstaddr)->sin_addr), ip6str, sizeof(ip6str)));
        break;

      default:
        printf("\tAddress Family Name: Unknown\n");
        break;
    }
  }
  printf("\n");
}

char* iptos(u_short family, struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;
    if(family == AF_INET)
        sockaddrlen = sizeof(struct sockaddr_in6);
    else if(family == AF_INET6)
        sockaddrlen = sizeof(struct sockaddr_in);
    else
        return "";
    

    if(getnameinfo(sockaddr,    // A pointer to a socket address structure (sa_family +  sa pointed to sockaddr_in or sockaddr_in6)
        sockaddrlen,            // The length of the structure pointed to by the sa param of socket address
        address,                // Buffer to store host_name from ip address of sa
        addrlen,                // Size of buffer
        NULL,                   // Buffor to store service_name from port of sa
        0,                      // Size of buffer
        NI_NUMERICHOST          // To set host_name format to Numeric instead of FQDN (default)
    ) != 0) address = NULL;

    return address;
}