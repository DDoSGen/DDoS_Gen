#pragma once
#include "macros.h"
#include "attacktable.h"
#include "pktclass.hpp"
#include <stdint.h>
#include <pthread.h>
#include <string>

void* attack_routine(void* arg);

// TODO: make attack module class
class ATTACKMODULE{
    private:        
        uint16_t bps;

        // args from main

        // private functions

    public:
        ATTACKMODULE(char* dev, std::string tip, int type, int speed, int dur);
        void attack();
        
        std::string tip;
        char* dev;
        int type;
        int speed;
        int dur;
};