#if !defined(__XOR_H__)
#define __XOR_H__

unsigned PolyXorKey(unsigned dwKey);
void XorArray(unsigned dwKey, unsigned char* pPoint, 
			  unsigned char* pOut, unsigned iLength);
void XorCoder(unsigned char* pKey, unsigned char* pBuffer, unsigned iLength);
void XorKey32Bits(unsigned dwKeyContext, unsigned char* pKey, 
				  unsigned iKeyLength);

#endif
