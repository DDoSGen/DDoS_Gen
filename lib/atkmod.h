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
        std::string tip;
        char* dev;
        int type;
        int speed;
        int dur;

        // private functions

    public:
        ATTACKMODULE(std::string tip, int type, int speed, int dur);
        void attack();
};