#include "pch.h"  // プリコンパイル済みヘッダ

#include "print.h"

// --------------------------------------------------------------------
// my_ether_ntoa_r
// MAC を文字列に変換する
char* my_ether_ntoa_r(const u_char* hwaddr, char* buf, const socklen_t size)
{
	snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
		hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
	return buf;
}

// --------------------------------------------------------------------
// arp_ip2str
// ipv4 を文字列に変換する
char* arp_ip2str(const u_int8_t* ip, char* buf, const socklen_t size)
{
	snprintf(buf, size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
	return buf;
}

// --------------------------------------------------------------------
// ip_ip2str
// ipv4 を文字列に変換する
char* ip_ip2str(u_int32_t ip, char* buf, const socklen_t size)
{
	inet_ntop(AF_INET, (in_addr*)&ip, buf, size);
	return buf;
}

// --------------------------------------------------------------------
// PrintEtherHeader
// イーサヘッドをデバッグ表示する
void PrintEtherHeader(const ether_header* eh, FILE* fp)
{
	char buf[80];
	fprintf(fp, "ether_header----------------------------\n");
	fprintf(fp, "ether_dhost = %s\n", my_ether_ntoa_r(eh->ether_dhost, buf, sizeof(buf)));
	fprintf(fp, "ether_shost = %s\n", my_ether_ntoa_r(eh->ether_shost, buf, sizeof(buf)));

	// ether_type : 16 bit値
	fprintf(fp, "ether_type = %02X", ntohs(eh->ether_type));

	switch (ntohs(eh->ether_type))
	{
	case	ETH_P_IP:
		fprintf(fp,"(IP)\n");
		break;
	case	ETH_P_IPV6:
		fprintf(fp,"(IPv6)\n");
		break;
	case	ETH_P_ARP:
		fprintf(fp,"(ARP)\n");
		break;
	default:
		fprintf(fp,"(unknown)\n");
		break;
	}
}

// --------------------------------------------------------------------
// PrintArp
void PrintArp(const ether_arp* arp, FILE *fp)
{
static const char* hrd[] = {
	"From KA9Q: NET/ROM pseudo.",
	"Ethernet 10/100Mbps.",
	"Experimental Ethernet.",
	"AX.25 Level 2.",
	"PROnet token ring.",
	"Chaosnet.",
	"IEEE 802.2 Ethernet/TR/TB.",
	"ARCnet.",
	"APPLEtalk.",
	"undefine",
	"undefine",
	"undefine",
	"undefine",
	"undefine",
	"undefine",
	"Frame Relay DLCI.",
	"undefine",
	"undefine",
	"undefine",
	"ATM.",
	"undefine",
	"undefine",
	"undefine",
	"Metricom STRIP (new IANA id)."
};

static const char *op[] = {
	"undefined",
	"ARP request.",
	"ARP reply.",
	"RARP request.",
	"RARP reply.",
	"undefined",
	"undefined",
	"undefined",
	"InARP request.",
	"InARP reply.",
	"(ATM)ARP NAK."
};

	fprintf(fp, "arp-------------------------------------\n");
	fprintf(fp, "arp_hrd=%u", ntohs(arp->arp_hrd));

	if(ntohs(arp->arp_hrd) <= 23)
		{ fprintf(fp, "(%s),", hrd[ntohs(arp->arp_hrd)]); }
	else
		{ fprintf(fp, "(undefined),"); }

	fprintf(fp, "arp_pro=%u", ntohs(arp->arp_pro));
	switch (ntohs(arp->arp_pro))
	{
	case	ETHERTYPE_IP:
		fprintf(fp, "(IP)\n");
		break;
	case	ETHERTYPE_ARP:
		fprintf(fp, "(Address resolution)\n");
		break;
	case	ETHERTYPE_REVARP:
		fprintf(fp, "(Reverse ARP)\n");
		break;
	case	ETHERTYPE_IPV6:
		fprintf(fp, "(IPv6)\n");
		break;
	default:
		fprintf(fp, "(unknown)\n");
		break;
	}

	fprintf(fp, "arp_hln=%u,", arp->arp_hln);
	fprintf(fp, "arp_pln=%u,", arp->arp_pln);
	fprintf(fp, "arp_op=%u", ntohs(arp->arp_op));
	if (ntohs(arp->arp_op) <= 10)
		{ fprintf(fp, "(%s)\n", op[ntohs(arp->arp_op)]); }
	else
		{ fprintf(fp,"(undefine)\n"); }

	char	buf[80];
	fprintf(fp, "arp_sha=%s\n", my_ether_ntoa_r(arp->arp_sha, buf, sizeof(buf)));
	fprintf(fp, "arp_spa=%s\n", arp_ip2str(arp->arp_spa, buf, sizeof(buf)));
	fprintf(fp, "arp_tha=%s\n", my_ether_ntoa_r(arp->arp_tha, buf, sizeof(buf)));
	fprintf(fp, "arp_tpa=%s\n", arp_ip2str(arp->arp_spa, buf, sizeof(buf)));
}

// --------------------------------------------------------------------
static const char* Proto[] = {
	"undefined",
	"ICMP",
	"IGMP",
	"undefined",
	"IPIP",
	"undefined",
	"TCP",
	"undefined",
	"EGP",
	"undefined",
	"undefined",
	"undefined",
	"PUP",
	"undefined",
	"undefined",
	"undefined",
	"undefined",
	"UDP"
};

// --------------------------------------------------------------------
// PrintIpHeader
void PrintIpHeader(const iphdr *iphdr, const u_char *option, const int optionLen, FILE *fp)
{
	fprintf(fp, "IPv4 ヘッダ ----------\n");
	fprintf(fp, "version=%u,", iphdr->version);
	fprintf(fp, " ihl=%u,", iphdr->ihl);
	fprintf(fp, " tos=%x,", iphdr->tos);
	fprintf(fp, " tot_len=%u,", ntohs(iphdr->tot_len));
	fprintf(fp, " id=%u\n", ntohs(iphdr->id));
	fprintf(fp, "frag_off=%x, %u,", (ntohs(iphdr->frag_off)>>13)&0x07,ntohs(iphdr->frag_off)&0x1FFF);
	fprintf(fp, " ttl=%u,", iphdr->ttl);
	fprintf(fp, " protocol=%u", iphdr->protocol);

	if(iphdr->protocol<=17)
		{ fprintf(fp, "(%s),", Proto[iphdr->protocol]); }
	else
		{ fprintf(fp,"(undefined),"); }

	char	buf[80];
	fprintf(fp, " check=%x\n", iphdr->check);
	fprintf(fp, "saddr=%s,", ip_ip2str(iphdr->saddr, buf, sizeof(buf)));
	fprintf(fp, " daddr=%s\n", ip_ip2str(iphdr->daddr, buf, sizeof(buf)));

	if (optionLen > 0)
	{
		fprintf(fp, "option:");
		fprintf(fp,"%02x",option[0]);
		for (int i = 1; i < optionLen; i++)
			{ fprintf(fp, ":%02x", option[i]); }
	}
}

// --------------------------------------------------------------------
// PrintIp6Header
void PrintIp6Header(const ip6_hdr* ip6, FILE* fp)
{
	fprintf(fp, "ip6-------------------------------------\n");
	fprintf(fp, "ip6_flow=%x,", ip6->ip6_flow);
	fprintf(fp, "ip6_plen=%d,", ntohs(ip6->ip6_plen));
	fprintf(fp, "ip6_nxt=%u", ip6->ip6_nxt);

	if (ip6->ip6_nxt <= 17)
		{ fprintf(fp, "(%s),", Proto[ip6->ip6_nxt]); }
	else
		{ fprintf(fp, "(undefined),"); }

	fprintf(fp, "ip6_hlim=%d,", ip6->ip6_hlim);

	char buf[80];
	fprintf(fp, "ip6_src=%s\n", inet_ntop(AF_INET6, &ip6->ip6_src, buf, sizeof(buf)));
	fprintf(fp, "ip6_dst=%s\n", inet_ntop(AF_INET6, &ip6->ip6_dst, buf, sizeof(buf)));
}

// --------------------------------------------------------------------
// PrintIcmp
void PrintIcmp(const icmp* icmp, FILE* fp)
{
static const char* icmp_type[]={
	"Echo Reply",
	"undefined",
	"undefined",
	"Destination Unreachable",
	"Source Quench",
	"Redirect",
	"undefined",
	"undefined",
	"Echo Request",
	"Router Adverisement",
	"Router Selection",
	"Time Exceeded for Datagram",
	"Parameter Problem on Datagram",
	"Timestamp Request",
	"Timestamp Reply",
	"Information Request",
	"Information Reply",
	"Address Mask Request",
	"Address Mask Reply"
};

	fprintf(fp, "icmp------------------------------------\n");
	fprintf(fp, "icmp_type=%u", icmp->icmp_type);

	if (icmp->icmp_type <= 18)
		{ fprintf(fp, "(%s),", icmp_type[icmp->icmp_type]); }
	else
		{ fprintf(fp,"(undefined),"); }

	fprintf(fp, "icmp_code=%u,", icmp->icmp_code);
	fprintf(fp, "icmp_cksum=%u\n", ntohs(icmp->icmp_cksum));

	if(icmp->icmp_type == 0 || icmp->icmp_type == 8)
	{
		fprintf(fp, "icmp_id=%u,", ntohs(icmp->icmp_id));
		fprintf(fp, "icmp_seq=%u\n", ntohs(icmp->icmp_seq));
	}
}

// --------------------------------------------------------------------
// PrintIcmp6
#pragma GCC diagnostic ignored "-Wformat-security"
void PrintIcmp6(const icmp6_hdr* icmp6, FILE* fp)
{
	fprintf(fp, "icmp6-----------------------------------\n");
	fprintf(fp, "icmp6_type=%u", icmp6->icmp6_type);

	fprintf(fp,
		[](const uint8_t icmp6_type) -> const char* {
			switch (icmp6_type)
			{
			case 1:
				return "(Destination Unreachable),";
			case 2:
				return "(Packet too Big),";
			case 3:
				return "(Time Exceeded),";
			case 4:
				return "(Parameter Problem),";
			case 128:
				return "(Echo Request),";
			case 129:
				return "(Echo Reply),";
			default:
				return "(undefined),";
			}
		}(icmp6->icmp6_type)
	);

	fprintf(fp, "icmp6_code=%u,", icmp6->icmp6_code);
	fprintf(fp, "icmp6_cksum=%u\n", ntohs(icmp6->icmp6_cksum));

	if(icmp6->icmp6_type == 128 || icmp6->icmp6_type == 129)
	{
		fprintf(fp,"icmp6_id=%u,",ntohs(icmp6->icmp6_id));
		fprintf(fp,"icmp6_seq=%u\n",ntohs(icmp6->icmp6_seq));
	}
}

// --------------------------------------------------------------------
// PrintTcp
void PrintTcp(const tcphdr* tcphdr, FILE* fp)
{
	fprintf(fp, "tcp-------------------------------------\n");
	fprintf(fp, "source=%u,", ntohs(tcphdr->source));
	fprintf(fp, "dest=%u\n", ntohs(tcphdr->dest));
	fprintf(fp, "seq=%u\n", ntohl(tcphdr->seq));
	fprintf(fp, "ack_seq=%u\n", ntohl(tcphdr->ack_seq));
	fprintf(fp, "doff=%u,", tcphdr->doff);
	fprintf(fp, "urg=%u,", tcphdr->urg);
	fprintf(fp, "ack=%u,", tcphdr->ack);
	fprintf(fp, "psh=%u,", tcphdr->psh);
	fprintf(fp, "rst=%u,", tcphdr->rst);
	fprintf(fp, "syn=%u,", tcphdr->syn);
	fprintf(fp, "fin=%u,", tcphdr->fin);
	fprintf(fp, "th_win=%u\n", ntohs(tcphdr->window));
	fprintf(fp, "th_sum=%u,", ntohs(tcphdr->check));
	fprintf(fp, "th_urp=%u\n", ntohs(tcphdr->urg_ptr));
}

// --------------------------------------------------------------------
// PrintUdp
void PrintUdp(const udphdr* udphdr, FILE* fp)
{
	fprintf(fp,"udp-------------------------------------\n");
	fprintf(fp, "source=%u,", ntohs(udphdr->source));
	fprintf(fp, "dest=%u\n", ntohs(udphdr->dest));
	fprintf(fp, "len=%u,", ntohs(udphdr->len));
	fprintf(fp, "check=%x\n", ntohs(udphdr->check));
}

