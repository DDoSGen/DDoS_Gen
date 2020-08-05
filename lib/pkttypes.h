#pragma once
#include <libnet.h>
#include <stdint.h>

// redefine structures in libnet.h
typedef struct libnet_ethernet_hdr ETHHDR;
typedef struct libnet_ipv4_hdr IPv4HDR;
typedef struct libnet_icmpv4_hdr ICMPHDR;
typedef struct libnet_tcp_hdr TCPHDR;
typedef struct libnet_udp_hdr UDPHDR;
typedef uint8_t DATATYPE;

// define packet types
#pragma pack(push, 1)
struct ETHIPTCP{
    ETHHDR eth_hdr;
    IPv4HDR ip_hdr;
    TCPHDR tcp_hdr;
    DATATYPE* data;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ETHIPUDP{
    ETHHDR eth_hdr;
    IPv4HDR ip_hdr;
    UDPHDR udp_hdr;
    DATATYPE* data;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ETHIPICMP{
    ETHHDR eth_hdr;
    IPv4HDR ip_hdr;
    ICMPHDR icmp_hdr;
    DATATYPE* data;
};
#pragma pack(pop)