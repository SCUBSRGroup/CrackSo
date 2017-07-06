#include "xor.h"

unsigned PolyXorKey(unsigned dwKey) {
	int i = 0, j = 0, n = 0;
	unsigned char* pKey = (unsigned char*)&dwKey;
	unsigned char bVal = 0, bTmp = 0, bTmp2 = 0;
	dwKey ^= 0x19831210;
	for (i = 0; i < (int)sizeof(unsigned); i++, pKey++) {
		bVal = *pKey;
		/*
		* 第一位与第二位异或放到第一位,依次类推
		* 到达第八位,与第一位异或放到第八位
		* 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01
		*/
		for (j = 0x80, n = 7; j > 0x01; j /= 2, n--) {
			bTmp = (bVal & j) >> n;
			bTmp2 = (bVal & j / 2) >> (n - 1);
			bTmp ^= bTmp2;
			bTmp <<= n;
			bVal |= bTmp;
		}
		bTmp = bVal & 0x01;
		bTmp2 = bVal & 0x80 >> 7;
		bTmp ^= bTmp2;

		*pKey = bVal;
	}/* end for */
	return dwKey;
}

void XorArray(unsigned dwKey, unsigned char* pPoint, 
			  unsigned char* pOut, unsigned iLength) {
	unsigned dwNextKey = dwKey;
	unsigned char* pKey = (unsigned char*)&dwNextKey;
	int i = 0, j = 0;
	for (i = 0; i < (int)iLength; i++) {
		pOut[i] = pPoint[i] ^ pKey[j];
		if (j == (sizeof(unsigned)-1)) {
			// 变换Key
			dwNextKey = PolyXorKey(dwNextKey);
			j = 0;
		} else j++;
	}
}

void XorCoder(unsigned char* pKey, unsigned char* pBuffer, unsigned iLength) {
	for (int i = 0; i < (int)iLength; i++)
		pBuffer[i] = pBuffer[i] ^ pKey[i];
}

void XorKey32Bits(unsigned dwKeyContext, unsigned char* pKey, 
				  unsigned iKeyLength) {
	int iCount = 0;
	unsigned dwKey = dwKeyContext;
	unsigned char* pOutPut = pKey;
	iCount = (iKeyLength % sizeof(unsigned) != 0) ? iKeyLength / sizeof(unsigned) + 1 : iKeyLength / sizeof(unsigned);

	while (iCount--) {
		dwKey = PolyXorKey(dwKey);
		*(unsigned*)(void*)pOutPut ^= dwKey;
		pOutPut += sizeof(unsigned);
	}
}

