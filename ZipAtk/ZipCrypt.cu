#include <cuda_runtime.h>
#include "CRC32.cu"

#define rep(idx, max)	for(int idx = 0, idx##Max = max; idx < idx##Max; idx ++)
#define erep(idx, min, max)	for(int idx = min, idx##Max = max; idx <= idx##Max; idx ++)

#define MAX_BRUTE_LEN	54
#define MAX_CHARSET	256
__constant__ char gd_charset[MAX_CHARSET];
__constant__ int	gd_charsetLen;
__constant__ u8	gd_cryptHeader[CRYPTHEADER_SIZE];
__device__ char	gd_word[MAX_BRUTE_LEN];


__device__ u32	GetCRC32(u32 n1, u8 n2)
{	return(gd_crc32Tbl[(n1 ^ n2) & 0xFF] ^ (n1 >> 8));	}


__device__ void	UpdateKeys(ZIPKEY &key, u8 n)
{
	key.x	= ::GetCRC32(key.x, n);
	key.y	= (key.y + (key.x & 0xFF)) * 0x08088405 + 1;
	key.z	= ::GetCRC32(key.z, key.y >> 24);
}

__device__ u8	Dec(ZIPKEY &key, u8 n)
{
	u16 t	= ((key.z & 0xFFFF) | 2);
	t	= ((t * (t ^ 1)) >> 8) & 0xFF;
	::UpdateKeys(key, n ^= t);
	return n;
}

__device__ void	InitDecrypt(ZIPKEY &key, char *lpszPassword)
{
	key.x	= 0x12345678;
	key.y	= 0x23456789;
	key.z	= 0x34567890;
	
	for(char *p = lpszPassword; *p; ::UpdateKeys(key, *(p ++)));
	for(int i = 0; i < CRYPTHEADER_SIZE; ::Dec(key, gd_cryptHeader[i ++]));
}

__device__ u32	GetCRC32(ZIPKEY &key, u8 *lpBuf, u32 len, u32 initVal)
{
	u32 ret = initVal;
	for (u32 i = 0; i < len; i ++)	{	ret = (ret >> 8) ^ gd_crc32Tbl[ ::Dec(key, lpBuf[i]) ^ (ret & 0xFF)];	}
	return ~ret;
}

// 3 -> 000 100 200 010 110 210 020 120 220 ... 
__device__ __host__ bool	Increment(u8 *indices, int wordLen, int charsetLen, int incBy)
{
	for(int i = 0; i < wordLen && incBy > 0; i ++)
	{
		int add = incBy + indices[i];
		indices[i] = add % charsetLen;
		incBy = add / charsetLen;
	}
	return incBy != 0;
}

__global__ void	KerCrack(u8 *lpData, int size, int wordLen, int charsetLen, u32 crc32)
{
	int idx = blockDim.x * blockIdx.x + threadIdx.x;
	u8	indices[MAX_BRUTE_LEN] = {};
	char szPassword[MAX_BRUTE_LEN];
	ZIPKEY	key;
	
	::Increment(indices, wordLen, charsetLen, idx);
	
	for(int i = 0; i < wordLen; i ++)
	{
		szPassword[i]	= gd_charset[indices[i]];
	}
	szPassword[wordLen] = '\0';
	
	::InitDecrypt(key, szPassword);
	if(crc32 == ::GetCRC32(key, lpData, size, 0xFFFFFFFF))
	{
		for(char *d = gd_word, *s = szPassword; *(d ++) = *(s ++); );
	}
}
