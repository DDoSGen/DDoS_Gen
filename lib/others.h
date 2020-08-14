#pragma once
#include <netinet/in.h>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <libnet/libnet-macros.h>

uint16_t ipChecksum(uint16_t *addr, uint16_t len);
void get_gateMAC(uint8_t* storage);
void make_MAC_byte(std::string r, uint8_t* storage);