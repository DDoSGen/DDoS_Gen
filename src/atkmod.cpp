#include "../lib/atkmod.h"

ATTACKMODULE::ATTACKMODULE(char* dev, std::string tip, int type, int speed, int dur){
    this->dev = dev;
    this->tip = tip;
    this->type = type;
    this->speed = speed;
    this->dur = dur;
}

void ATTACKMODULE::attack(){
    pthread_t AttackThreads[THREADS];
    
    for(int i = 0; i < THREADS; i++){
        pthread_create(&AttackThreads[i], NULL, attack_routine, (void*)this);
    }
    
    for(int i = 0; i < THREADS; i++){
        pthread_join(AttackThreads[i], NULL);
    }
}

// uint16_t ipChecksum(libnet_ipv4_hdr *addr, int len)
// {

//     int count = len;
//     register uint32_t sum = 0;
//     uint16_t checkSum = 0;

//     while (count > 1) {
//         sum += *(addr++);
//         count -= 2;
//     }

//     if (count > 0) {
//         sum += (IPv4HDR *) addr;
//     }

//     while (sum >> 16) {
//         sum = (sum & 0xffff) + (sum >> 16);
//     }

//     checkSum = ~sum;

//     return (checkSum);
// }

unsigned short in_checksum(unsigned short *ptr,int nbytes) {
        register long sum;
        unsigned short oddbyte;
        register short answer;
 
        sum=0;
        while(nbytes>1) {
                sum+=*ptr++;
                nbytes-=2;
        }
        if(nbytes==1) {
                oddbyte=0;
                *((u_char*)&oddbyte)=*(u_char*)ptr;
                sum+=oddbyte;
        }
 
        sum = (sum>>16)+(sum & 0xffff);
        sum = sum + (sum>>16);
        answer=(short)~sum;
       
        return(answer);
}


PKT<ETHIPTCP> PKT<ETHIPTCP>::make_packet(PKT<ETHIPTCP> packet){



    libnet_seed_prand(NULL);
    /* TCP */
    // random source mac
    for (int i = 0 ; i < 6 ; i++){
        packet.pkt.eth_hdr.ether_shost[i] = libnet_get_prand(LIBNET_PR8);
    }

    // 이더넷 헤더
    /*
    타겟이 내부 네트워크면
    ARP 리퀘스트를 해서 맥을 받아와야 하고
    타겟이 외부 네트워크면
    그냥 게이트웨이 맥 주소
    */

    // packet.pkt.eth_hdr.ether_dhost[i] = target mac

    packet.pkt.eth_hdr.ether_type = htons(ETHERTYPE_IP);

    packet.pkt.ip_hdr.ip_sum = 0x0000;                          // initial checksum
    
    packet.pkt.ip_hdr.ip_v = 4 << 4;                            // version
    packet.pkt.ip_hdr.ip_hl = 5;                                // header length
    // packet.pkt.ip_hdr.ip_tos = IPTOS_LOWDELAY;                 
    packet.pkt.ip_hdr.ip_tos = 0xe0;                            // random or fix?
    packet.pkt.ip_hdr.ip_len = htons(20);                         // total length
    packet.pkt.ip_hdr.ip_id = libnet_get_prand(LIBNET_PRu16);   // random ID
    packet.pkt.ip_hdr.ip_off = IP_DF;                           // don't fragment
    packet.pkt.ip_hdr.ip_ttl = libnet_get_prand(LIBNET_PR8);    // random TTL
    packet.pkt.ip_hdr.ip_p = IPPROTO_TCP;                       // protocol = TCP
    packet.pkt.ip_hdr.ip_src.s_addr = libnet_get_prand(LIBNET_PRu32);  // random source IP
    // packet.pkt.ip_hdr.ip_dst = <target_ip>;

    packet.pkt.ip_hdr.ip_sum = in_checksum(packet.pkt.ip_hdr, packet.pkt.ip_hdr.ip_len);                        // 체크섬, 모르겠음
    
    // libnet_do_checksum(libnet_t *l, uint8_t *iphdr, int protocol, int h_len);
    // libnet_do_checksum(packet.pkt , *(packet.pkt.ip_hdr), );
    return packet;
}

// PKT<ETHIPUDP> PKT<ETHIPUDP>::make_packet(PKT<ETHIPUDP> packet){


//     /* TCP */
//     // random source mac
//     for (int i = 0 ; i < 6 ; i++){
//         packet.pkt.eth_hdr.ether_shost[i] = libnet_get_prand(LIBNET_PR8);
//     }

//     // packet.pkt.eth_hdr.ether_dhost[i] = target mac
//     packet.pkt.eth_hdr.ether_type = htons(ETHERTYPE_IP);


//     packet.pkt.ip_hdr.ip_v = 4 << 4;                           // version
//     packet.pkt.ip_hdr.ip_hl = 5;                               // header length
//     // packet.pkt.ip_hdr.ip_tos = IPTOS_LOWDELAY;                 // 뭔지 모르겠음
//     packet.pkt.ip_hdr.ip_tos = 0xe0;                            // 
//     packet.pkt.ip_hdr.ip_len = htons();                        // total length
//     packet.pkt.ip_hdr.ip_id = libnet_get_prand(LIBNET_PRu16);  // random ID
//     packet.pkt.ip_hdr.ip_off = IP_DF;                          // don't fragment
//     packet.pkt.ip_hdr.ip_ttl = libnet_get_prand(LIBNET_PR8);   // random TTL
//     packet.pkt.ip_hdr.ip_p = IPPROTO_TCP;                      // protocol = TCP
//     packet.pkt.ip_hdr.ip_src.s_addr = libnet_get_prand(LIBNET_PRu32);  // random source IP
//     packet.pkt.ip_hdr.ip_dst = <target_ip>;
//     packet.pkt.ip_hdr.ip_sum = htons();                        // 체크섬, 모르겠음

//     return packet;
// }

// TODO:make attack_routine function
void* attack_routine(void* arg){

    ATTACKMODULE* ddos = (ATTACKMODULE*)arg;

    PKT<ETHIPTCP> packet= PKT<ETHIPTCP>(ddos->dev);

    // 시드 생성
    libnet_seed_prand(NULL);


    switch (ddos->type){
    
    // TCP_SYN_ATTACK
    case 1:

        break;
    
    // TCP_ACK_ATTACK
    case 2:

        break;

    // TCP_SYN-ACK_ATTACK
    case 3:

        break;
    
    // TCP_CONNECTION_ATTACK
    case 4:

        break;

    // TCP_CONGESTION_CONTROL_ATTACK
    case 5:

        break;

    // TCP_TSNAMI_ATTACK
    case 6:

        break;

    // UDP_ATTACK
    case 7:

        break;

    // ICMP_ATTACK
    case 8:

        break;

    // GET_FLOODING_ATTACK
    case 9:

        break;
    
    // POST_FLOODING_ATTACK
    case 10:

        break;
    
    // DYNAMIC_HTTP_REQ_FLOODING
    case 11:

        break;
    
    // SLOWLORIS_ATTACK
    case 12:

        break;
    
    // SLOWREAD_ATTACK
    case 13:

        break;

    // R-U-D-Y_ATTACK
    case 14:

        break;

    // BIG1_ATTACK
    case 15:

        break;
        
    default:
        printf("type error");
        break;
    }
    
    return NULL;
}