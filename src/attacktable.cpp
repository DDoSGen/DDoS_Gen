#include "../lib/attacktable.h"

void print_attacktable(){
    printf("<<<< ATTACK TYPE NUMBER TABLE >>>>\n");
    std::map<int, std::string>::iterator iter;
    for(iter = attacktable.begin(); iter != attacktable.end(); iter++){
        printf("#%2d.\t%s\n", iter->first, iter->second.c_str());
    }
}