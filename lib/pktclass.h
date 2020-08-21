#pragma once
#include <pcap.h>
#include "pkttypes.h"
#include "others.h"

class PKT{
    private:
        ////// for pcap.h //////
        char* dev;
        pcap_t* pcap_handler;
        char errbuf[PCAP_ERRBUF_SIZE];
        int pcap_res;
        
        ////// packet pointer /////
        const uint8_t* pkt_ptr;
        ETHIPTCP* tcp;
        ETHIPUDP* udp;
        ETHIPICMP* icmp;
        
        ////// 패킷 속성 //////
        int pkttype;
        int pktsize;

        // 패킷 만들기 내부 함수 //
        void make_common_part(mac_t* target_mac, ip_t target_ip, ETHIPHDR* common);
        void make_tcp_packet(ETHIPTCP* tcp_ptr, int flagtype, int datalen);
        void make_udp_packet();
        void make_icmp_packet();
    public:
        // initialize
        PKT(char* dev);
        ~PKT();

        // functions for setting, make, send packets
        void set_pcap();
        
        // target의 맥주소 받아올 함수
        void set_attackinfo(ip_t target_ip, mac_t* storage);
        
        // 패킷 만드는 함수
        void make_packet(mac_t* target_mac, uint32_t target_ip, int pkttype, int flagtype, int datalen);
        void send_packet();

        // TCP connection 용 패킷 만드는 함수
        void PKT::make_specific_packet(
            mac_t* target_mac,
            uint16_t id,
            uint32_t sender_ip, 
            uint32_t target_ip, 
            uint16_t src_port, 
            uint16_t dst_port,
            uint32_t seq,
            uint32_t ack,
            uint16_t window,
            int pkttype, 
            int flagtype, 
            int datalen
        );
};