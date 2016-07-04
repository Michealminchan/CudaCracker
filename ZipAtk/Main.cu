#include <cstdio>
#include <iostream>
#include <vector>
#include <string>
#include "Typedefs.h"
#include "ZipCrypt.cu"

#define CEILDIV(n, d)	(((n) + (d) - 1) / (d))
#define BLOCK_SIZE	128
#define GRID_SIZE	256

int main(int nArgs, char **lplpszArgs)
{
	std::vector<u8>	buf;
	char	szFileName[0x200];
	::printf("FileName: \n");
	::scanf("%s", szFileName);
	FILE	*hFile = ::fopen(szFileName, "rb");
	if(!hFile)	{	return(-1);	}

	ZIP_HEADER	header;
	while(::fread(&header, sizeof(ZIP_HEADER) - sizeof(void *) * 2, 1, hFile), 
		header.signature == ZIP_SIGNATURE)
	{
		/* Load ZIP */
		u8	cryptHeader[CRYPTHEADER_SIZE];
		
		::fread(szFileName,  header.filenameLen, 1, hFile);
		szFileName[header.filenameLen] = 0;
		::fseek(hFile,  header.extraLen, SEEK_CUR);
		
		u32	size	= header.compSize - CRYPTHEADER_SIZE;
		int bPasworded = header.option & 0x01;
		
		if(bPasworded)	{ ::fread(cryptHeader, CRYPTHEADER_SIZE, 1, hFile); }
		else
		{
			::fseek(hFile,  size, SEEK_CUR);
			continue;
		}
		::printf("[%s]: Passworded: %d\n", szFileName, bPasworded);
		
		buf.resize(size);
		::fread(&buf[0], size, 1, hFile);

		/* Construct CUDA kernel */
		std::string	charset = "abcdefghijklmnopqrstuvwxyz";
		int		charsetLen	= charset.size();
		u8	*d_lpData;
		::cudaMalloc((void **)&d_lpData, size);
		::cudaMemcpy(d_lpData, &buf[0], size, cudaMemcpyHostToDevice);
		::cudaMemcpyToSymbol(&gd_charsetLen, &charsetLen, sizeof(int), 0, cudaMemcpyHostToDevice);
		::cudaMemcpyToSymbol(gd_charset, &charset[0], charsetLen, 0, cudaMemcpyHostToDevice);
		::cudaMemcpyToSymbol(gd_cryptHeader, cryptHeader, sizeof(cryptHeader), 0, cudaMemcpyHostToDevice);
		
		int zero = '\0';
		for(int wordLen = 1; wordLen < 4; wordLen ++)
		{
			char	szFound[MAX_BRUTE_LEN];
			u64	all = ::pow((double)charsetLen, (double)wordLen);
			::cudaMemcpyToSymbol(gd_word, &zero, 1, 0, cudaMemcpyHostToDevice);
			::KerCrack<<<CEILDIV(all, BLOCK_SIZE), BLOCK_SIZE>>>(d_lpData, size, wordLen, charsetLen, header.crc32);
			::cudaDeviceSynchronize();
			::cudaMemcpyFromSymbol(&szFound, gd_word, sizeof(szFound), 0, cudaMemcpyDeviceToHost);
			if(szFound[0] )
			{	::printf("[*] Found!\t%s\n", szFound);	}
		}
		::cudaFree(d_lpData);
	}
	
	::fclose(hFile);
}
