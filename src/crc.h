#if !defined(__CRC_H__)
#define __CRC_H__

#define UPDC32(octet, crc)\
	(unsigned)((crc_32_tab[(((unsigned)(crc)) ^ ((unsigned char)(octet))) & 0xff] ^ (((unsigned)(crc)) >> 8)))

unsigned crc32(unsigned char* data, unsigned length);
unsigned crc32int(unsigned *data);
bool crc32_selftests();
	
extern unsigned crc_32_tab[];
	
#endif
