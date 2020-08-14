#pragma once
#include "macros.h"
#include "attacktable.h"
#include "pktclass.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <thread>
#include <string>
#include <memory>

// TODO: make attack module class
class ATTACKMODULE{
    private:        
        uint16_t bps;
        uint32_t tip;
        char* dev;
        int type;
        int speed;
        int dur;

        // private functions
        void attack_routine();
    public:
        ATTACKMODULE(char* dev, std::string tip, int type, int speed, int dur);
        
        void attack();
};