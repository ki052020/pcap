#include "pch.h"  // プリコンパイル済みヘッダ

#include <string>
#include "KException.h"

struct pseudo_ip
{
	struct in_addr  ip_src;
	struct in_addr  ip_dst;
	unsigned char   dummy;
	unsigned char   ip_p;
	unsigned short  ip_len;
};

struct pseudo_ip6_hdr
{
	struct in6_addr src;
	struct in6_addr dst;
	unsigned long   plen;
	unsigned short  dmy1;
	unsigned char   dmy2;
	unsigned char   nxt;
};

static inline u_int32_t Wrap_to_17b(const u_int32_t sum)
{
	if((int32_t)sum >= 0)
		{ return sum; }
	else
		{ return (sum >> 16) + (sum & 0xFFFF); }
}

// --------------------------------------------------------------------
// checksum
// 16 bit 毎に、１の補数和をとる（RFC1071）
u_int16_t checksum(const u_char *data, int len)
{
	u_int32_t sum = 0;
	const u_int16_t *ptr = (const u_int16_t*)data;

	// ----------------------------------
	for(; len >= 2; len -= 2)
		{ sum = Wrap_to_17b(sum + *ptr++); }
	
	// little endian の場合のみを考慮した補数和
	if (len == 1)
		{ sum = Wrap_to_17b(sum + *(const u_int8_t*)ptr); }

	// ----------------------------------
	if (const u_int32_t up = sum >> 16; up > 0)
	{
		// ここに来る場合、up の値は 1 のはず
		sum = up + (sum & 0xFFFF);
		// carry の処理（パイプラインを考慮して if の利用は避けた）
		sum = (sum >> 16) + (sum & 0xFFFF);
	}
	return ~sum;
}

// --------------------------------------------------------------------
// Checksum2
namespace
{
u_int16_t Checksum2(const u_char *data1, int len1, const u_char *data2, int len2)
{
	u_int32_t sum = 0;
	const u_int16_t* ptr = (const u_int16_t*)data1;

	// ----------------------------------
	for(; len1 >= 2; len1 -= 2)
		{ sum = Wrap_to_17b(sum + *ptr++); }

	// len1 == 1 となった場合は、ネットワークバイトオーダーで処理する？？
	if (len1 == 1)
	{
		sum = Wrap_to_17b(sum + (u_int16_t(*(u_int8_t*)ptr) << 8) + *data2);

		ptr = (const u_int16_t*)(data2 + 1);
		len2--;
	}
	else
	{
		ptr = (const u_int16_t*)data2;
	}

	// ----------------------------------
	for (; len2 >= 2; len2 -= 2)
		{ sum = Wrap_to_17b(sum + *ptr++); }

	// little endian の場合のみを考慮した補数和
	if (len2 == 1)
		{ sum = Wrap_to_17b(sum + *(const u_int8_t*)ptr); }

	// ----------------------------------
	if (const u_int32_t up = sum >> 16; up > 0)
	{
		// ここに来る場合、up の値は 1 のはず
		sum = up + (sum & 0xFFFF);
		// carry の処理（パイプラインを考慮して if の利用は避けた）
		sum = (sum >> 16) + (sum & 0xFFFF);
	}
	return ~sum;
}
}

// --------------------------------------------------------------------
// checkIPchecksum
void checkIPchecksum(const iphdr* p_iphdr, const u_char* p_option, const int optionLen)
{
	const u_int16_t chk_sum = (optionLen == 0) ?
		checksum((const u_char*)p_iphdr, sizeof(iphdr))
		: Checksum2((const u_char*)p_iphdr, sizeof(iphdr), p_option, optionLen);
	
	if (chk_sum == 0) { return; }

	std::string err_msg = "!!! failed -> checkIPchecksum() / chk_sum = ";
	char buf[10];  // 本当は 5 で良いはず
	sprintf(buf, "%04x", chk_sum);
	err_msg += buf;

	THROW(err_msg);
}

#if false
// --------------------------------------------------------------------
int checkIPDATAchecksum(struct iphdr *iphdr,unsigned char *data,int len)
{
	struct pseudo_ip p_ip;
	unsigned short  sum;

	memset(&p_ip,0,sizeof(struct pseudo_ip));
	p_ip.ip_src.s_addr=iphdr->saddr;
	p_ip.ip_dst.s_addr=iphdr->daddr;
	p_ip.ip_p=iphdr->protocol;
	p_ip.ip_len=htons(len);

	sum=checksum2((unsigned char *)&p_ip,sizeof(struct pseudo_ip),data,len);
	if(sum==0||sum==0xFFFF){
		return(1);
	}
	else{
		return(0);
	}
}
#endif

// --------------------------------------------------------------------
// checkIP6DATAchecksum
int checkIP6DATAchecksum(struct ip6_hdr *ip,unsigned char *data,int len)
{
struct pseudo_ip6_hdr   p_ip;
unsigned short  sum;

memset(&p_ip,0,sizeof(struct pseudo_ip6_hdr));

memcpy(&p_ip.src,&ip->ip6_src,sizeof(struct in6_addr));
memcpy(&p_ip.dst,&ip->ip6_dst,sizeof(struct in6_addr));
p_ip.plen=ip->ip6_plen;
p_ip.nxt=ip->ip6_nxt;

sum=Checksum2((unsigned char *)&p_ip,sizeof(struct pseudo_ip6_hdr),data,len);
if(sum==0||sum==0xFFFF){
return(1);
}
else{
return(0);
}
}


