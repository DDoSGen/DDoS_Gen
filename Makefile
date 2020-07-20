all: ddos

ddos: main.cpp
	g++ -o ddos main.cpp -lpthread
