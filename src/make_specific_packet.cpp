#include "../lib/pktclass.h"

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
    )
{
    this->pkttype = pkttype;
    
    tcp = new(ETHIPTCP);
    memset(tcp, 0, sizeof(ETHIPTCP));
    make_common_part(target_mac, target_ip, (ETHIPHDR*)tcp);
    make_tcp_packet(tcp, flagtype, datalen);


    // 몇 가지 세부 지정

    // IP 재지정
    tcp->ip_hdr.ip_src.s_addr = htonl(sender_ip);

    tcp->tcp_hdr.th_sport = htons(src_port);
    tcp->tcp_hdr.th_dport = htons(dst_port);
    tcp->tcp_hdr.th_seq = htonl(seq);
    tcp->tcp_hdr.th_ack = htonl(ack);
    tcp->tcp_hdr.th_win = htons(window);

    switch(flagtype){
        case SYN:
            tcp->tcp_hdr.th_ack = 0;  // wireshark에서 syn 일 땐 ack는 0이라서
            tcp->tcp_hdr.th_flags = TH_SYN;
            break;
        case SYN_ACK:
            tcp->tcp_hdr.th_flags = TH_SYN | TH_ACK;
            break;
        case ACK:
            tcp->tcp_hdr.th_flags = TH_ACK;
            break;
    }

    // filling final part
    tcp->ip_hdr.ip_len = htons(LIBNET_IPV4_H + tcp->tcp_hdr.th_off * 4 + datalen);
    tcp->ip_hdr.ip_sum = Checksum((uint16_t*)(&tcp->ip_hdr), tcp->ip_hdr.ip_len);
    tcp->tcp_hdr.th_sum = Checksum((uint16_t*)(&tcp->tcp_hdr), tcp->tcp_hdr.th_off);

    this->pktsize = sizeof(ETHIPTCP) + datalen;
    this->pkt_ptr = (const uint8_t*)tcp;
}