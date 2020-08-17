#include "../lib/others.h"

uint16_t Checksum(uint16_t *addr, uint16_t len){
    uint32_t sum = 0;
    uint16_t odd = 0;
    uint16_t checkSum = 0;

    while(len > 1){
        sum += *addr++;
        len -= 2;
    }

    if(len == 1){
		*(uint8_t*)(&odd) = *(uint8_t*)addr;
		sum += odd;
	}

    while (sum >> 16){
        sum = (sum & 0xffff) + (sum >> 16);
    }

    checkSum = (uint16_t)~sum;

    return htons(checkSum);
}

void fill_rand(uint8_t* storage, int byte_size){
    for(int i = 0; i < byte_size; i++){
        *storage = make_byte_rand(rand());
        storage++;
    }
}

uint8_t make_byte_rand(int seed){
    srand(seed);
    return (uint8_t)(rand() & 0x000000FF);
}

void get_my_mac(char* dev, mac_t* mac){
	int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
    strncpy((char *)ifr.ifr_name , (const char *)dev, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	
	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(sockfd);
}

uint32_t get_my_ip(char* dev){
	int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
    strncpy((char *)ifr.ifr_name , (const char *)dev, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFADDR, &ifr);
	close(sockfd);
	
	return ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
}

/* get gate MAC by opening /proc/net/arp */
void get_gateMAC(uint8_t* storage){
    std::ifstream readinfo("/proc/net/arp");
    
    std::string tmp;
    std::string hw_addr;
    
    while(readinfo.peek() != EOF){
        std::getline(readinfo, tmp);
        if(std::isdigit(tmp.front())){
            std::ofstream gatearp;
            gatearp.open("tmp.txt");
            gatearp.write(tmp.c_str(), tmp.size());
            gatearp.close();
        }
    }
    readinfo.close();

    readinfo.open("tmp.txt");
    std::vector<std::string> internals;
    std::vector<std::string>::iterator iter;

    while(readinfo.peek() != EOF){
        std::getline(readinfo, tmp, ' ');
        if(tmp != "") internals.push_back(tmp);
    }
    readinfo.close();
    
    for(iter = internals.begin(); iter != internals.end(); iter++){
        int idx = (*iter).size()-1;
        if((*iter).substr(idx-1, idx) == ".1"){
            hw_addr = *(iter+3);
            break;
        }
    }

    std::remove("tmp.txt");

    make_MAC_byte(hw_addr, storage);
}

void make_MAC_byte(std::string r, uint8_t* storage){
    uint32_t a, b, c, d, e, f;
    sscanf(r.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X", &a, &b, &c, &d, &e, &f);
    *storage = (uint8_t)a;
    *(storage+1) = (uint8_t)b;
    *(storage+2) = (uint8_t)c;
    *(storage+3) = (uint8_t)d;
    *(storage+4) = (uint8_t)e;
    *(storage+5) = (uint8_t)f;
}