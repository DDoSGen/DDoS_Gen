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

    ATTACKMODULE* module = (ATTACKMODULE*)arg;

    // get my mac, ip
    // send arp request to get target mac
    
    // packet for TCP SYN ATTACK
    PKT<ETHIPTCP> packet;

    // set packet
    packet.pkt.eth_hdr.ether_dhost = target mac;
    packet.pkt.eth_hdr.ether_shost = random mac;
    packet.pkt.eth_hdr.ether_type = htons(ETHERTYPE_IP);

    packet.pkt.ip_hdr.ip_src = random ip;
    packet.pkt.ip_hdr.ip_dst = target ip;


    return NULL;
}