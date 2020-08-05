#pragma once
#include <pcap.h>
#include <string>
#include "pkttypes.h"

/* class for packet managing
 * 1. Choose the type of packet (in pkttypes)
 * 2. pcap functions
 * 3. 
 */

template <typename PKTTYPE>
class PKT{
    private:
        ////// for pcap.h //////
        std::string device;
        pcap_t* pcap_handler;
        char errbuf[PCAP_ERRBUF_SIZE];
        int pcap_res;

        ////// for internal var //////
        PKTTYPE pkt;

    public:
        // functions for pcap_open_live, pcap_sendpacket

        // initialize
        PKT();
};