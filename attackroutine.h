// here is the routine for thread

#pragma once
#include <pthread.h>
#include <stdio.h> // for printf -> can be removed when useless
#include "attack.h"

void* attack_routine(void* arg){
    int attacktype = atoi((char*)arg);
    // attack(attacktype);  <- this should be activated when attack function is made
    printf("attacking,,,\n"); // -> this should be removed after making attack()
    return NULL;
}