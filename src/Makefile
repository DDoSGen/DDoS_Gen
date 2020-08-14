all: ddos

#ddos: attacktable.o others.o pktclass.o atkmod.o main.o
#	g++ -o ddos attacktable.o others.o pktclass.o atkmod.o main.o -lnet -lpcap -lpthread

#atkmod.o: ../lib/atkmod.h atkmod.cpp
#	g++ -c -o atkmod.o atkmod.cpp

#attacktable.o: ../lib/attacktable.h attacktable.cpp pktclass.cpp
#	g++ -o attacktable.o attacktable.cpp pktclass.cpp -lpthread -lnet

#pktclass.o: ../lib/pktclass.hpp pktclass.cpp
#	g++ -c -o pktclass.o pktclass.cpp -lpcap -lnet

#others.o: ../lib/others.h others.cpp
#	g++ -c -o others.o others.cpp

#main.o: ../lib/atkmod.h main.cpp
#	g++ -c -o main.o main.cpp

#clean:
#	rm -f ddos *.o
#

ddos: attacktable.cpp others.cpp pktclass.cpp atkmod.cpp main.cpp
	g++ main.cpp atkmod.cpp pktclass.cpp others.cpp attacktable.cpp -o ddos -lpthread -lpcap -lnet

clean:
	rm -f ddos *.o
