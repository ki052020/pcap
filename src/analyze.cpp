#include "pch.h"  // プリコンパイル済みヘッダ

#include "analyze.h"
#include	"checksum.h"
#include	"print.h"
#include "KException.h"

//static_assert(sizeof(iphdr) == 20, "sizeof(iphdr) != 20");

// --------------------------------------------------------------------
namespace
{
int AnalyzeIp(const u_char* pbuf, int len);
int AnalyzeIpv6(const u_char* pbuf, int len);

void AnalyzeArp(const u_char* pbuf, const int size);
void AnalyzeIcmp(const u_char* pbuf, int size);
void AnalyzeIcmp6(const u_char* pbuf, int size);
void AnalyzeTcp(const u_char* pbuf, int size);
void AnalyzeUdp(const u_char* pbuf, int size);
}

// --------------------------------------------------------------------
// AnalyzePacket
int AnalyzePacket(const u_char* pbuf, int len)
{
	if (len < (int)sizeof(ether_header))
	{
		printf("len(%d) < sizeof(ether_header)\n", len);
		return -1;
	}

	// ---------------------------------------
	const ether_header* const p_eh = (const ether_header*)pbuf;
	pbuf += sizeof(ether_header);
	len -= sizeof(ether_header);

	if	(ntohs(p_eh->ether_type) == ETHERTYPE_ARP)
	{
		printf("\nArp [%d bytes]\n", len);
		AnalyzeArp(pbuf, len);
	}
	else if (ntohs(p_eh->ether_type) == ETHERTYPE_IP)
	{
		printf("\nIPv4 [%d bytes]\n", len);
		AnalyzeIp(pbuf, len);
	}
	else if (ntohs(p_eh->ether_type) == ETHERTYPE_IPV6)
	{
		printf("\nIPv6 [%d bytes]\n",len);
		AnalyzeIpv6(pbuf, len);
	}
	return 0;
}

namespace
{
// --------------------------------------------------------------------
// AnalyzeArp
void AnalyzeArp(const u_char* pbuf, const int size)
{
	if (size < (int)sizeof(ether_arp))
	{
		fprintf(stderr, "size(%d) < sizeof(iphdr)\n" , size);
		return;
	}
	PrintArp((const ether_arp*)pbuf, stdout);
}

// --------------------------------------------------------------------
// AnalyzeIcmp
void AnalyzeIcmp(const u_char* pbuf, const int size)
{
	if (size < (int)sizeof(icmp))
	{
		fprintf(stderr, "size(%d) < sizeof(icmp)\n", size);
		return;
	}
	PrintIcmp((const icmp*)pbuf, stdout);
}

// --------------------------------------------------------------------
// AnalyzeIcmp6
void AnalyzeIcmp6(const u_char* pbuf, const int size)
{
	if (size < (int)sizeof(icmp6_hdr))
	{
		fprintf(stderr, "size(%d) < sizeof(icmp6_hdr)\n", size);
		return;
	}
	PrintIcmp6((const icmp6_hdr*)pbuf, stdout);
}

// --------------------------------------------------------------------
// AnalyzeTcp
void AnalyzeTcp(const u_char* pbuf, const int size)
{
	if (size < (int)sizeof(tcphdr))
	{
		fprintf(stderr, "size(%d) < sizeof(tcphdr)\n", size);
		return;
	}
	PrintTcp((const tcphdr*)pbuf, stdout);
}

// --------------------------------------------------------------------
// AnalyzeUdp
void AnalyzeUdp(const u_char* pbuf, const int size)
{
	if(size < (int)sizeof(udphdr))
	{
		fprintf(stderr, "size(%d) < sizeof(udphdr)\n", size);
		return;
	}
	PrintUdp((const udphdr*)pbuf, stdout);
}

// --------------------------------------------------------------------
// AnalyzeIp
int AnalyzeIp(const u_char* pbuf, int len)
{
	if (len < (int)sizeof(iphdr))
	{
		printf("len(%d) < sizeof(iphdr)\n", len);
		return -1;
	}

	// ---------------------------------------
	const iphdr* p_iphdr = (const iphdr*)pbuf;
	pbuf += sizeof(iphdr);
	len -= sizeof(iphdr);

	const u_char* p_option = NULL;
	const int optionLen = p_iphdr->ihl * 4 - sizeof(iphdr);
	if (optionLen > 0){
		if (optionLen >= 1500)
		{
			printf("IP optionLen(%d):too big\n", optionLen);
			return -1;
		}

		p_option = pbuf;
		pbuf += optionLen;
		len -= optionLen;
	}

	checkIPchecksum(p_iphdr, p_option, optionLen);
	PrintIpHeader(p_iphdr, p_option, optionLen,stdout);

	if(p_iphdr->protocol == IPPROTO_ICMP)
	{
		u_int16_t icmp_len = ntohs(p_iphdr->tot_len) - p_iphdr->ihl * 4;
		if (checksum(pbuf, len) != 0)
			{ THROW("!!! IPv4 -> ICMP -> checksum(pbuf, len) != 0"); }
		AnalyzeIcmp(pbuf, len);
	}
#if false
	else if(p_iphdr->protocol == IPPROTO_TCP)
	{
		len = ntohs(p_iphdr->tot_len) - p_iphdr->ihl * 4;
		if(checkIPDATAchecksum(iphdr,ptr,len)==0){
			fprintf(stderr,"bad tcp checksum\n");
			return(-1);
		}
		AnalyzeTcp(ptr,lest);
	}
	else if(iphdr->protocol==IPPROTO_UDP){
		struct udphdr	*udphdr;
		udphdr=(struct udphdr *)ptr;
		len=ntohs(iphdr->tot_len)-iphdr->ihl*4;
		if(udphdr->check!=0&&checkIPDATAchecksum(iphdr,ptr,len)==0){
			fprintf(stderr,"bad udp checksum\n");
			return(-1);
		}
		AnalyzeUdp(ptr,lest);
	}
#endif

	return 0;
}

// --------------------------------------------------------------------
// AnalyzeIpv6
int AnalyzeIpv6(const u_char* data, int size)
{
const u_char	*ptr;
int	lest;
struct ip6_hdr	*ip6;

	ptr=data;
	lest=size;

	if(lest < (int)sizeof(struct ip6_hdr)){
		fprintf(stderr,"lest(%d)<sizeof(struct ip6_hdr)\n",lest);
		return(-1);
	}
	ip6=(struct ip6_hdr *)ptr;
	ptr+=sizeof(struct ip6_hdr);
	lest-=sizeof(struct ip6_hdr);

	PrintIp6Header(ip6,stdout);

#if false
int	len;
	if(ip6->ip6_nxt==IPPROTO_ICMPV6){
		len=ntohs(ip6->ip6_plen);
		if(checkIP6DATAchecksum(ip6,ptr,len)==0){
			fprintf(stderr,"bad icmp6 checksum\n");
			return(-1);
		}
		AnalyzeIcmp6(ptr,lest);
	}
	else if(ip6->ip6_nxt==IPPROTO_TCP){
		len=ntohs(ip6->ip6_plen);
		if(checkIP6DATAchecksum(ip6,ptr,len)==0){
			fprintf(stderr,"bad tcp6 checksum\n");
			return(-1);
		}
		AnalyzeTcp(ptr,lest);
	}
	else if(ip6->ip6_nxt==IPPROTO_UDP){
		len=ntohs(ip6->ip6_plen);
		if(checkIP6DATAchecksum(ip6,ptr,len)==0){
			fprintf(stderr,"bad udp6 checksum\n");
			return(-1);
		}
		AnalyzeUdp(ptr,lest);
	}
#endif

	return(0);
}

}
