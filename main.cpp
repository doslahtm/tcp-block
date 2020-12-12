#include <stdio.h>
#include <libnet.h>
#include <pcap.h>
#include <stdint.h>
#include "ethhdr.h"
#include <string.h>
#include <netinet/ether.h> //
#include "tcp-block.h"

#define HTTP 80
#define HTTPS 443
#define EthHdrLen 14

uint8_t MyMac[Mac::SIZE];
uint8_t* FailTable;

void MakeFailTable(char* ptn);
uint32_t KMP(char* pkt, char* ptn);

uint32_t KMP(char* pkt, char* ptn)
{
    printf("A");
    char *Pkt_ = pkt + EthHdrLen; // IP Packet
    uint32_t IpPktLen = ntohs(((struct libnet_ipv4_hdr *)Pkt_) -> ip_len); 
    uint32_t IpHdrLen = ((struct libnet_ipv4_hdr *)Pkt_) -> ip_hl << 2;
    uint32_t TcpHdrLen = ((struct libnet_tcp_hdr *)(Pkt_ + IpHdrLen)) -> th_off << 2; // tcp header length
    Pkt_ = Pkt_ + IpHdrLen + TcpHdrLen; // data
    uint32_t DataSize = IpPktLen - IpHdrLen - TcpHdrLen;
    uint32_t PktIdx = 0;
    uint32_t PtnIdx = 0;
    uint32_t PtnLen = strlen(ptn);
    while (PktIdx < DataSize)
    {
        if (PtnIdx == -1 || Pkt_[PktIdx] == ptn[PtnIdx])
        {
            PktIdx++;
            PtnIdx++;
        }
        else
        {
            PtnIdx = FailTable[PtnIdx];
        }
        if (PtnIdx == PtnLen)
        {
            printf("I found it!!\n");
            return 1;
        }
    }
    printf("I did not Found it!!\n");
    return 0;
}

void MakeFailTable(char *ptn)
{
    uint32_t PtnIdx = 0;
    uint32_t k = -1;
    uint32_t PtnLen = strlen(ptn);
    FailTable = (uint8_t*)malloc(PtnLen + 1);
    memset(FailTable, 0, PtnLen + 1);
    FailTable[0] = -1;
    while (PtnIdx < PtnLen )
    {
        if (k == -1 || ptn[PtnIdx] == ptn[k])
        {
            PtnIdx++;
            k++;
            FailTable[PtnIdx] = k;
        }
        else
        {
            k = FailTable[k];
        }
    }
}


void usage()
{
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

int getmymac(char *eth)
{
    struct ifreq ifr;
    int32_t sockfd, ret;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if ( sockfd < 0 )
    {
        printf("Failed to get interface MAC address - socket failed\n");
        return -1;
    }
        
    strncpy(ifr.ifr_name, eth, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if ( ret < 0 )
    {
        printf("ioctl failed!\n");
        close(sockfd);
        return -1;
    }
    memcpy(MyMac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
    return 0;
}

int CheckPattern(char *data, char *pattern) // data is ethernet layer
{
    char *Pkt_ = data + EthHdrLen; // IP Packet
    uint32_t IpPktLen = ntohs(((struct libnet_ipv4_hdr *)Pkt_) -> ip_len); 
    uint32_t IpHdrLen = ((struct libnet_ipv4_hdr *)Pkt_) -> ip_hl << 2;
    uint32_t TcpHdrLen = ((struct libnet_tcp_hdr *)(Pkt_ + IpHdrLen)) -> th_off << 2; // tcp header length
    uint32_t PatternLen = strlen(pattern);
    int flag = 0;
    for (uint32_t i = IpHdrLen + TcpHdrLen; i < IpPktLen; i++)
    {
        flag = !memcmp(&(Pkt_[i]), pattern, PatternLen);
        if (flag) {
            break;
        }
    }
    return flag;
}



int main(int argc, char *argv[])
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
    if (argc != 3)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
    if ( handle == nullptr )
    {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s", dev, errbuf);
        return -1;
    }
    getmymac(argv[1]);
    MakeFailTable(argv[2]);
    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        // TCP IPv4 check!!
        if ( ((struct EthHdr *)packet) -> type_ == htons(EthHdr::Ip4)
            && ((struct libnet_ipv4_hdr *)(packet + EthHdrLen)) -> ip_p == LIBNET_DHCP_DNS 
        )
        {
            if ( KMP((char *)packet, argv[2]) )
            {
                //SendForward(handle, (char *)packet, MyMac);
                //SendBackward();
            }

        }


    }

    pcap_close(handle);
    return 0;
}