#include "tcp-block.h"
/*
uint16_t CalcTcpSum(char *packet)
{
    uint32_t sum = 0;
    struct PsuedoHdr Pkt;
    uint32_t TcpLen = ((struct libnet_ipv4_hdr *)(packet + sizeof(EthHdr))) -> ip_len - ((struct libnet_ipv4_hdr *)(packet + sizeof(EthHdr))) -> ip_off << 2; 
    Pkt.dip = ((struct libnet_ipv4_hdr *)(packet + sizeof(EthHdr))) -> ip_dst;
    Pkt.sip = ((struct libnet_ipv4_hdr *)(packet + sizeof(EthHdr))) -> ip_src;
    Pkt.TcpLen = htons(ntohs(((struct libnet_tcp_hdr *)(packet + sizeof(EthHdr) + sizeof(libnet_ipv4_hdr))) -> th_off) << 1);
    printf("%x\n", ((struct libnet_tcp_hdr *)(packet + sizeof(EthHdr) + sizeof(libnet_ipv4_hdr))) -> th_off);
    uint16_t *ptr = (uint16_t *)&Pkt;
    for(int i = 0; i < sizeof(PsuedoHdr) >> 1; i++)
    {
        sum += ntohs(*ptr++);
    }
    ptr = (uint16_t *)(packet + sizeof(EthHdr) + sizeof(libnet_ipv4_hdr)); // from TCP
    if (TcpLen % 2 == 1)
    {
        for (int i = 0; i < TcpLen >> 1; i++)
        {
            sum += ntohs(*ptr++);
        }
        sum += (*ptr) & 0x00ff;
    }
    else
    {
        for (int i = 0; i < TcpLen >> 1; i++)
        {
            sum += *ptr++;
        }
    }
    sum = ((sum >> 16) + (sum & 0x0000ffff));
    return ~((uint16_t)sum);
}

uint16_t CalcIpSum(char *packet)
{
    uint32_t sum = 0;
    uint32_t IpLen = ((struct libnet_ipv4_hdr *)(packet + sizeof(EthHdr))) -> ip_len; 
    uint16_t *ptr = (uint16_t*)packet;
    for (int i = 0; i < ((struct libnet_ipv4_hdr *)(packet + sizeof(EthHdr))) -> ip_off << 1; i++ )
    {
        sum += ntohs(*ptr++);
    }
    sum = ((sum >> 16) + (sum & 0x0000ffff));
    return ~((uint16_t)sum);
}
*/

void SendForward(pcap_t* handle, char *OrgPkt, uint8_t *mymac)
{
    struct FdPkt MyPkt;
    // printf("%u %u %u", (unsigned int)sizeof(EthHdr), (uint32_t)sizeof(libnet_ipv4_hdr), (uint32_t)sizeof(libnet_tcp_hdr));
    //uint32_t OrgDataSize = ntohs(((struct libnet_ipv4_hdr *)(OrgPkt + sizeof(EthHdr))) -> ip_len) - ((struct libnet_ipv4_hdr *)(OrgPkt + sizeof(EthHdr))) -> ip_off << 2;
    //char *TcpPkt = OrgPkt + (((struct libnet_ipv4_hdr *)(OrgPkt + sizeof(EthHdr))) -> ip_off << 2);
    //OrgDataSize -= ((libnet_tcp_hdr *)TcpPkt) -> th_off << 2;
    printf("0x%x", ntohs(((struct libnet_ipv4_hdr *)(OrgPkt + sizeof(EthHdr))) -> ip_len) );  
    /*
    MyPkt.eth_.smac_ = Mac(mymac);
    MyPkt.eth_.dmac_ = ((struct EthHdr *)OrgPkt) -> dmac_;
    MyPkt.eth_.type_ = htons(EthHdr::Ip4);

    MyPkt.ip_.ip_hl = 0x05;
    MyPkt.ip_.ip_v = 0x04;
    MyPkt.ip_.ip_tos = 0x44;
    MyPkt.ip_.ip_len = htons(sizeof(struct libnet_tcp_hdr) + sizeof(struct libnet_ipv4_hdr));
    MyPkt.ip_.ip_ttl = ((struct libnet_ipv4_hdr*)(OrgPkt + sizeof(EthHdr))) -> ip_ttl;
    MyPkt.ip_.ip_src = ((struct libnet_ipv4_hdr*)(OrgPkt + sizeof(EthHdr))) -> ip_src;
    MyPkt.ip_.ip_dst = ((struct libnet_ipv4_hdr*)(OrgPkt + sizeof(EthHdr))) -> ip_dst;
    MyPkt.ip_.ip_p = LIBNET_DHCP_DNS;
    MyPkt.ip_.ip_sum = 0;

    MyPkt.tcp_.th_seq = htons(ntohs(((struct libnet_tcp_hdr *)(OrgPkt + sizeof(EthHdr) + sizeof(libnet_ipv4_hdr))) -> th_seq) + OrgDataSize);
    MyPkt.tcp_.th_flags = 0;
    MyPkt.tcp_.th_flags |= 0x14;
    MyPkt.tcp_.th_off = htons(0x20 >> 2);
    MyPkt.tcp_.th_ack = ((struct libnet_tcp_hdr *)(OrgPkt + sizeof(EthHdr) + sizeof(libnet_ipv4_hdr))) -> th_ack;
    MyPkt.tcp_.th_sport = ((struct libnet_tcp_hdr *)(OrgPkt + sizeof(EthHdr) + sizeof(libnet_ipv4_hdr))) -> th_sport;
    MyPkt.tcp_.th_dport = ((struct libnet_tcp_hdr *)(OrgPkt + sizeof(EthHdr) + sizeof(libnet_ipv4_hdr))) -> th_dport;
    MyPkt.tcp_.th_sum = 0;
    MyPkt.tcp_.th_sum = htons(CalcTcpSum((char *)&MyPkt));

    MyPkt.ip_.ip_sum = htons(CalcIpSum((char *)&MyPkt));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&MyPkt), sizeof(FdPkt));

    if (res != 0) 
    {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}*/
}

void SendBackward(pcap_t* handle, char *OrgPkt, uint8_t *mymac)
{

}