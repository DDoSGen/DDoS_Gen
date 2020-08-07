#include "../lib/pktclass.hpp"

template <typename PKTTYPE>
PKT<PKTTYPE>::PKT(char* dev){
    device = dev;
}

template <typename PKTTYPE>
PKT<PKTTYPE>::~PKT(){
	close(pcap_handler);
}

template <typename PKTTYPE>
void PKT<PKTTYPE>::set_pcap(){
    device = argv[1];
	pcap_handler = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
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