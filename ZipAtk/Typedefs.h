#pragma once

typedef signed char		s8;
typedef unsigned char	u8;
typedef signed short		s16;
typedef unsigned short	u16;
typedef signed int		s32;
typedef unsigned int		u32;
typedef signed long long	s64;
typedef unsigned long long	u64;

typedef struct _ZIPKEY
{
	u32	x, y, z;
} ZIPKEY;

#define CRYPTHEADER_SIZE	12
#define ZIP_SIGNATURE						0x04034B50
#define CENTRALDIR_SIGNATURE			0x02014B50
#define CENTRALDIR_TERM_SIGNATURE	0x06054B50

#pragma pack(1)
typedef struct _CRYPTHEADER
{
	u8	x[12];
} CRYPTHEADER;

typedef struct _ZIP_HEADER
{
	u32	signature;
	
	u16	reqVer;
	u16	option;
	u16	method;
	u16	time;
	u16	date;
	u32	crc32;
	u32	compSize;
	u32	actSize;
	u16	filenameLen;
	u16	extraLen;	// 30 bytes
	
	const char	*lpszFilename;
	u8		*lpExtra;
} ZIP_HEADER;

typedef struct _CENTRALDIR_HEADER
{
	u32	signature;
	u16	createdVer;
	
	u16	reqVer;
	u16	option;
	u16	method;
	u16	time;
	u16	date;
	u32	crc32;
	u32	compSize;
	u32	actSize;
	u16	filenameLen;
	u16	extraLen;
	
	u16	commentLen;
	u16	diskNo;
	u16	intAttrib;
	u32	extAttrib;
	u32	headerRelPos;	// 46 bytes
	
	const char	*lpszFilename;
	u8		*lpExtra;
	char	*lpszComment;
	
	void	Merge(ZIP_HEADER &o)
	{
		reqVer	= o.reqVer;
		option	= o.option;
		method	= o.method;
		time		= o.time;
		date		= o.date;
		crc32		= o.crc32;
		compSize	= o.compSize;
		actSize		= o.actSize;
		filenameLen	= o.filenameLen;
		extraLen		= o.extraLen;
		lpszFilename	= o.lpszFilename;
		lpExtra			= o.lpExtra;
	}
} CENTRALDIR_HEADER;

typedef struct _CENTRALDIR_TERM_HEADER
{
	u32	signature;
	u16	diskNum;
	u16	startDiskNo;
	u16	diskDirEntry;
	u16	dirEntry;
	u32	dirSize;
	u32	startOffset;
	u16	commentLen;
	char	*lpszComment;
} CENTRALDIR_TERM_HEADER;
#pragma pack()
