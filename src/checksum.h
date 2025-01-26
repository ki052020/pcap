#pragma once

u_int16_t checksum(const u_char* data, int len);

// エラーがあれば、例外を throw する
void checkIPchecksum(const iphdr* iphdr, const u_char* option, int optionLen);

//int checkIPDATAchecksum(struct iphdr *iphdr,unsigned char *data,int len);
int checkIP6DATAchecksum(struct ip6_hdr *ip,unsigned char *data,int len);

