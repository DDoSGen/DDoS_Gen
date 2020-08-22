#pragma once
#include "attacktable.h"
#include "pktclass.h"
#include <arpa/inet.h>
#include <thread>
#include <mutex>
#include <memory>

// TODO: make attack module class
class ATTACKMODULE{
    private:        
        uint16_t bps;
        char* dev;
        int atktype;
        int speed;
        int dur;

        // attack information structure //
        mac_t target_mac[ETHER_ADDR_LEN];
        ip_t target_ip;

        // private functions
        void attack_routine();

        // TCP connection attack 용 함수
        void tcp_connection_attack(PKT* packet, int ctrl);
        
        // target의 맥주소 받기
        void get_targetinfo(std::string tip);
    public:
        ATTACKMODULE(char* dev, std::string tip, int type, int speed, int dur);
        
        // 외부에서 호출될 함수
        void attack();
};