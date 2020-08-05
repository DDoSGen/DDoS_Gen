/* Last Update : 2020.07.20
 * Best Of Best 9th team project
 * Team DDoS Gen.
 */

// main loop for ddos
#pragma once
#include "../lib/atkmod.h"
#include <iostream>
#include <stdlib.h>
#include <string>
using namespace std;

int main(int argc, char* argv[]){
    
    if(argc != 1){
        printf("Usage: %s\n", argv[0]);
        exit(1);
    }
    
    string tip;
    int type;
    int speed;
    int dur;
    char check;

    cout << "DDoS Attack Program by BoB 9th\n";
    
    cout << "Enter target IP - ex) 192.168.0.1\n";
    cout << "target IP: ";
    cin >> tip;
    
    cout << "Enter attack type in number\n";
    print_attacktable();
    cout << "attack type: ";
    cin >> type;
    
    cout << "Enter attack speed in [Mbps]\n";
    cout << "attack speed: ";
    cin >> speed;
    
    cout << "Enter attack time in [sec]\n";
    cout << "attacking time: "; 
    cin >> dur;

    cout << "\nCheck your DDoS Attack settings\n";
    
    cout << "target IP: " << tip << '\n';
    cout << "attack type: " << '#' << type << '(' << attacktable[type] << ")\n";
    cout << "attack speed: " << speed << " [Mbps]\n";
    cout << "attacking time: " << dur << " [sec]\n";

    cout << "Are they all right?(y/n)\n";
    cin >> check;
/*
    if(check == 'y'){
        cout << "DDoS Attack Starting...\n";
        ATTACKMODULE DDoS = ATTACKMODULE(tip, type, speed, dur);
        DDoS.attack();
    }
*/
    cout << "attack done" << endl;
    return 0;
}