#include "../lib/others.h"
#include <random>

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

std::string getRandUserAgent(){
    // User Agent ref : https://deviceatlas.com/blog/mobile-browser-user-agent-strings
    
    std::default_random_engine generator;
    std::uniform_int_distribution<int> distribution(0,17);

    std::string userAgentList[18] = {
        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_1 like Mac OS X) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.0 Mobile/14E304 Safari/602.1",
        "Mozilla/5.0 (Linux; U; Android 4.4.2; en-us; SCH-I535 Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
        "Mozilla/5.0 (Linux; Android 7.0; SM-A310F Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.91 Mobile Safari/537.36 OPR/42.7.2246.114996",
        "Opera/9.80 (Android 4.1.2; Linux; Opera Mobi/ADR-1305251841) Presto/2.11.355 Version/12.10",
        "Opera/9.80 (J2ME/MIDP; Opera Mini/5.1.21214/28.2725; U; ru) Presto/2.8.119 Version/11.10",
        "Mozilla/5.0 (Linux; Android 7.0; SM-G930V Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.125 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) OPiOS/10.2.0.93022 Mobile/11D257 Safari/9537.53",
        "Mozilla/5.0 (Android 7.0; Mobile; rv:54.0) Gecko/54.0 Firefox/54.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_2 like Mac OS X) AppleWebKit/603.2.4 (KHTML, like Gecko) FxiOS/7.5b3349 Mobile/14F89 Safari/603.2.4",
        "Mozilla/5.0 (Linux; U; Android 7.0; en-US; SM-G935F Build/NRD90M) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 UCBrowser/11.3.8.976 U3/0.8.0 Mobile Safari/534.30",
        "Mozilla/5.0 (Linux; Android 6.0.1; SM-G920V Build/MMB29K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.98 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 5.1.1; SM-N750K Build/LMY47X; ko-kr) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Mobile Safari/537.36 Puffin/6.0.8.15804AP",
        "Mozilla/5.0 (Linux; Android 5.1.1; SM-N750K Build/LMY47X; ko-kr) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Mobile Safari/537.36 Puffin/6.0.8.15804AP",
        "Mozilla/5.0 (Linux; Android 7.0; SAMSUNG SM-G955U Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/5.4 Chrome/51.0.2704.106 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 6.0; Lenovo K50a40 Build/MRA58K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.137 YaBrowser/17.4.1.352.00 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; U; Android 7.0; en-us; MI 5 Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/53.0.2785.146 Mobile Safari/537.36 XiaoMi/MiuiBrowser/9.0.3",
        "Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0; Trident/6.0; IEMobile/10.0; ARM; Touch; Microsoft; Lumia 950)",
        "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; Lumia 950) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.14977",

    };
    return userAgentList[distribution(generator)];
}

std::string getRandDir(){

    int idx;
    fill_rand((uint8_t*)&idx, 1);
    idx = idx % 6;

    std::string serverDirList[6] = {
        "/index.html ",
        "/secret/test.html",
        "/tmp/hello.html",
        "/priv/files.html",
        "/home/hello.html",
        "/bob/1.html" 
    };

    return serverDirList[idx];
}