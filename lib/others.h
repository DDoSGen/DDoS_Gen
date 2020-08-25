#pragma once
#include <netinet/in.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>
#include <fstream>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <pcap.h>
#include <unistd.h>
#include <cstring>
#include <libnet/libnet-macros.h>
#include "macros.h"
#include "pkttypes.h"


uint16_t Checksum(uint16_t *addr, uint16_t len);
uint8_t make_byte_rand(int seed);
void fill_rand(uint8_t* storage, int byte_size);

void get_my_mac(char* dev, mac_t* mac);
uint32_t get_my_ip(char* dev);

void get_gateMAC(uint8_t* storage);
void make_MAC_byte(std::string r, uint8_t* storage);
char* getRandUserAgent();