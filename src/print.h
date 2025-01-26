#pragma once

char* my_ether_ntoa_r(const u_char* hwaddr, char* buf, socklen_t size);
char* arp_ip2str(const u_int8_t* ip, char* buf, socklen_t size);
char* ip_ip2str(u_int32_t ip, char* buf, socklen_t size);
void PrintEtherHeader(const ether_header* eh, FILE* fp);

void PrintArp(const ether_arp* arp, FILE* fp);
void PrintIpHeader(const iphdr* iphdr, const u_char* option, int optionLen, FILE* fp);
void PrintIp6Header(const ip6_hdr* ip6, FILE* fp);
void PrintIcmp(const icmp* icmp, FILE* fp);
void PrintIcmp6(const icmp6_hdr* icmp6, FILE* fp);
void PrintTcp(const tcphdr* tcphdr, FILE* fp);
void PrintUdp(const udphdr* udphdr, FILE* fp);
