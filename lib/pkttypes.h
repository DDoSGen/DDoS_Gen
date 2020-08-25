#pragma once
#include "macros.h"
#include <libnet.h>
#include <cstdint>
#include <string.h>

// redefine structures in libnet.h
typedef struct libnet_ethernet_hdr ETHHDR;
typedef struct libnet_arp_hdr ARPHDR;
typedef struct libnet_ipv4_hdr IPv4HDR;
typedef struct libnet_icmpv4_hdr ICMPHDR;
typedef struct libnet_tcp_hdr TCPHDR;
typedef struct libnet_udp_hdr UDPHDR;
typedef uint8_t mac_t;
typedef uint32_t ip_t;
typedef uint8_t DATATYPE;

enum L4_TYPE{
    TCP = IPPROTO_TCP,
    UDP = IPPROTO_UDP,
    ICMP = IPPROTO_ICMP,
    HTTP = 10
};

enum ATK_TCP_TPYE{
    SYN = TH_SYN,
    ACK = TH_ACK,
    SYN_ACK = TH_SYN | TH_ACK
};

enum ATK_HTTP_TYPE{
    GET = 1,
    POST = 2,
    SLOWLORIS = 3,
    SLOWREAD = 4,
    DYNAMIC_HTTP_REQ = 5,
    RUDY = 6
};


#pragma pack(push, 1)
struct ETHARPHDR{
    ETHHDR eth_hdr;
    ARPHDR arp_hdr;
    mac_t srcmac[ETHER_ADDR_LEN];
    ip_t srcip;
    mac_t dstmac[ETHER_ADDR_LEN];
    ip_t dstip;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ETHIPHDR{
    ETHHDR eth_hdr;
    IPv4HDR ip_hdr;
};
#pragma pack(pop)

// define packet types
#pragma pack(push, 1)
struct ETHIPTCP{
    ETHHDR eth_hdr;
    IPv4HDR ip_hdr;
    TCPHDR tcp_hdr;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ETHIPUDP{
    ETHHDR eth_hdr;
    IPv4HDR ip_hdr;
    UDPHDR udp_hdr;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ETHIPICMP{
    ETHHDR eth_hdr;
    IPv4HDR ip_hdr;
    ICMPHDR icmp_hdr;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct HTTPPKT{
    ETHHDR eth_hdr;
    IPv4HDR ip_hdr;
    TCPHDR tcp_hdr;
    DATATYPE data[BUFSIZ];
};
#pragma pack(pop)