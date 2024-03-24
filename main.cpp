#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp-test wlan0 172.20.10.3 172.20.10.1\n");
}

const std::string get_mac_address(const char *interface_name) {
    std::string mac_address;
    std::ifstream file("/sys/class/net/" + std::string(interface_name) + "/address");
    if (file.is_open()) {
        std::getline(file, mac_address);
    } else {
        std::cerr << "Error: Failed to open file for interface " << interface_name << std::endl;
    }
    return mac_address;
}


int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char* sender_ip = argv[2];
    char* target_ip = argv[3];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("00:00:00:00:00:00"); // sender_MAC_address
    packet.eth_.smac_ = Mac(get_mac_address(dev));
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(get_mac_address(dev));
    packet.arp_.sip_ = htonl(Ip(target_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // sender_MAC_address
    packet.arp_.tip_ = htonl(Ip(sender_ip));


    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
}
