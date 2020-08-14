#include "../lib/pktclass.hpp"

template <typename PKTTYPE>
PKT<PKTTYPE>::PKT(char* dev){
    device = dev;
}

template <typename PKTTYPE>
PKT<PKTTYPE>::~PKT(){
	pcap_close(pcap_handler);
}

template <typename PKTTYPE>
void PKT<PKTTYPE>::set_pcap(){
	pcap_handler = pcap_open_live(device, BUFSIZ, 1, 1, errbuf);
	if (pcap_handler == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
		exit(-1);
	}
}

template <typename PKTTYPE>
void PKT<PKTTYPE>::send_packet(){
    pcap_res = pcap_sendpacket(pcap_handler, reinterpret_cast<const u_char*>(&pkt), sizeof(pkt));
	if (pcap_res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", pcap_res, pcap_geterr(pcap_handler));
		exit(-1);
	}
}

/* TCP packet */
template <>
void PKT<ETHIPTCP>::make_packet(uint32_t target_ip){

    libnet_seed_prand(NULL);
    
    // random source mac
    for(int i = 0 ; i < ETHER_ADDR_LEN; i++){
        pkt.eth_hdr.ether_shost[i] = (uint8_t)libnet_get_prand(LIBNET_PR8);
    }

    get_gateMAC(pkt.eth_hdr.ether_dhost);

    pkt.eth_hdr.ether_type = htons(ETHERTYPE_IP);

    pkt.ip_hdr.ip_sum = 0x0000;                          // initial checksum
    
    pkt.ip_hdr.ip_v = 4;                                 // version
    pkt.ip_hdr.ip_hl = 5;                                // header length                 
    pkt.ip_hdr.ip_tos = IPTOS_LOWDELAY;                  // random or fix?
    
    // 추후 확인
    pkt.ip_hdr.ip_len = htons(20);                         // total length

    pkt.ip_hdr.ip_id = libnet_get_prand(LIBNET_PRu16);   // random ID
    pkt.ip_hdr.ip_off = IP_DF;                           // don't fragment
    pkt.ip_hdr.ip_ttl = libnet_get_prand(LIBNET_PR8);    // random TTL
    pkt.ip_hdr.ip_p = IPPROTO_TCP;                       // protocol = TCP
    pkt.ip_hdr.ip_src.s_addr = libnet_get_prand(LIBNET_PRu32);  // random source IP
    pkt.ip_hdr.ip_dst.s_addr = target_ip;


    // uint16_t ipChecksum(u_int16_t *addr, int len)
    pkt.ip_hdr.ip_sum = ipChecksum((uint16_t*)(&pkt.ip_hdr), pkt.ip_hdr.ip_len);                        // 체크섬, 모르겠음
}