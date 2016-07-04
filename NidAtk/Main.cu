#include <cuda.h>
#include <cuda_runtime.h>
#include <cstdio>
#include <cmath>
#include <vector>
#include <iostream>
#include <fstream>

#define rep(idx, max)	for(int idx = 0, idx##Max = max; idx < idx##Max; idx ++)
#define erep(idx, min, max)	for(int idx = min, idx##Max = max; idx <= idx##Max; idx ++)

#define MAX_BRUTE_LEN	128
#define MAX_DIC_NUM	300
#define MAX_DICTXT	32

typedef unsigned char	u8;
typedef unsigned int	u32;
typedef unsigned long long int	u64;
typedef struct _DICT
{
	char	szText[MAX_DICTXT];
} DICT;

#include "SHA1.cu"

__device__ char	gd_word[MAX_BRUTE_LEN];
__constant__ DICT gd_dicts[MAX_DIC_NUM];
__constant__ int	gd_dictNum;

__device__ void	Increment(u8 *indices, int wordNum, int incBy)
{
	for(int i = 0; i < wordNum && incBy > 0; i ++)
	{
		int add = incBy + indices[i];
		indices[i] = add % gd_dictNum;
		incBy = add / gd_dictNum;
	}
}

__constant__ char gd_szLibName[MAX_DICTXT];

#define MAX_IDX_NUM	16
__global__ void	KerCrack(int wordNum, u32 nid)
{
	int idx = blockDim.x * blockIdx.x + threadIdx.x;

	u8	indices[MAX_IDX_NUM] = {};
	char szText[MAX_BRUTE_LEN];
	
	::Increment(indices, wordNum, idx);
	
	char *lpszWord		= szText;
	char *lpszBegin	= lpszWord;
	
	for(char *p = gd_szLibName; *(lpszWord ++) = *p; p ++);
	lpszWord --;

	rep(i, wordNum)
	{
		for(char *p = gd_dicts[indices[i]].szText; *(lpszWord ++) = *p; p ++);
		lpszWord --;
	}
	
	u32 found = ::FastSHA1((u8 *)lpszBegin, lpszWord - lpszBegin);
	
	if(nid == found)
	{
		lpszWord		= gd_word;
		for(char *p = lpszBegin; *(lpszWord ++) = *p; p ++);
	}
}

#define BLOCK_SIZE	512
#define CEILDIV(n, d)	(((n) + (d) - 1) / (d))

int main()
{
	std::vector<DICT>	dicts;
	std::vector<u32>	nids;
	std::ifstream	dictFile("dict.txt");
	std::ifstream	nidFile("nid.txt");
	
	::printf("Dictionary file:\n");
	for(DICT dict; dictFile.getline(dict.szText, sizeof(dict.szText)); )
	{	dicts.push_back(dict);	}
	
	::printf("NID file:\n");
	for(u32 nid; nidFile >> std::hex >> nid; )
	{	nids.push_back(nid);	}
	
	::printf("Library name:\n");
	std::string libName = "sceUsb1Seg";
	//std::cin >> libName;
	
	int dictNum = dicts.size();
	::cudaMemcpyToSymbol(gd_szLibName, &libName[0], libName.size() + 1, 0, cudaMemcpyHostToDevice);
	::cudaMemcpyToSymbol(&gd_dictNum, &dictNum, sizeof(int), 0, cudaMemcpyHostToDevice);
	::cudaMemcpyToSymbol(gd_dicts, &dicts[0], dictNum * sizeof(DICT), 0, cudaMemcpyHostToDevice);
	
	::printf("Dict: %d, NID: %d\n", dicts.size(), nids.size());
	
	int zero = '\0';
	erep(wordNum, 1, 4)
	{
		rep(n, nids.size())
		{
			char	szFound[MAX_BRUTE_LEN];
			u64	all = ::pow((double)dictNum, (double)wordNum);
			// Clear the found string
			::cudaMemcpyToSymbol(gd_word, &zero, 1, 0, cudaMemcpyHostToDevice);
			
			::KerCrack<<<CEILDIV(all, BLOCK_SIZE), BLOCK_SIZE>>>(wordNum, nids[n]);
			::cudaThreadSynchronize();
			::cudaMemcpyFromSymbol(&szFound, gd_word, sizeof(szFound), 0, cudaMemcpyDeviceToHost);
		
			if(szFound[0])
			{	::printf("[%08X]\t%s\n", nids[n], szFound);	}
		}
	}
}

// nvcc -Xcompiler "/wd 4819" Main.cu