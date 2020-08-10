#pragma once
#include <pcap.h>
#include <string>
#include <stdlib.h>
#include "pkttypes.h"

/* class for packet managing
 * 1. Choose the type of packet (in pkttypes)
 * 2. pcap functions - open, send
 * 3. 
 */

template <typename PKTTYPE>
class PKT{
    private:
        ////// for pcap.h //////
        char* device;
        pcap_t* pcap_handler;
        char errbuf[PCAP_ERRBUF_SIZE];
        int pcap_res;

        ////// for internal var //////
        PKTTYPE pkt;

    public:
        // initialize
        PKT(char* dev);

        // functions for pcap_open_live, pcap_sendpacket
        void set_pcap();
        void send_packet();
        static PKT make_packet(PKT pk);
        ~PKT();

};