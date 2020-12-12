#include "ethhdr.h"
#include <libnet.h>
#include <pcap.h>
#include <stdint.h>
#include "ip.h"


#pragma pack(push, 1)
struct FdPkt {
    EthHdr eth_;
    libnet_ipv4_hdr ip_;
    libnet_tcp_hdr tcp_;
};
struct BkPkt {
    EthHdr eth_;
    libnet_ipv4_hdr ip_;
    libnet_tcp_hdr tcp_;
    char BlockMsg[11] = "blocked!!!";
};
struct PsuedoHdr {
    libnet_ipv4_hdr sip;
    libnet_ipv4_hdr dip;
    uint8_t zero = 0;
    uint8_t pro = 0x6;
    uint16_t TcpLen;
};
#pragma pack(pop)

void SendForward(pcap_t* handle, char *OrgPkt, uint8_t *mymac);

void SendBackward(pcap_t* handle, char *OrgPkt, uint8_t *mymac);

uint16_t CalcTcpSum(char *packet);

uint16_t CalcIpSum(char *packet);