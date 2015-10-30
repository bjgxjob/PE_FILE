// 2015_03_19.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

int main(int argc, char* argv[])
{
	//FBS：FileBuffer的大小
	unsigned uFileBufferSize = 0;
	//FB:FileBuffer
	LPVOID lpFileBuffer = NULL;
	//IB:ImageBuffer
	LPVOID lpImageBuffer = NULL;
	//IBS:ImageBuffer的大小
	unsigned uImageBufferSize = 0;
	//Pointer of PE_OPTIONAL_HEADER
	PE_NT_HEADER* pPE_NT_Header = NULL;
	bool blStatus = FALSE;
	//pNewFileBuffer
	LPVOID lpNewFileBuffer = NULL;
	//pNewFileBuffer
	unsigned uNewFileBuffer = 0;
	//获得FB大小
	blStatus = fnReadFileToMemory(
		PATH_READ,
		NULL,
		&uFileBufferSize
		);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnReadFileToMemory \r\n");
		}
		goto RET;
	}
	//分配FB空间
	lpFileBuffer = malloc(uFileBufferSize);
	if (lpFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("lpFileBuffer \r\n");
		}
		goto RET;
	}
	//Initialized FileBuffer
	memset(lpFileBuffer, 0x0, uFileBufferSize);

	//Copy File
	blStatus = fnReadFileToMemory(PATH_READ, lpFileBuffer, &uFileBufferSize);
	if (blStatus == NULL)
	{
		if (__DEBUG)
		{
			printf("fnReadFileToMemory \r\n");
		}
		goto RET;
	}
	//Get PE_NT_HEADER
	blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(lpFileBuffer, &pPE_NT_Header);
	if (blStatus == NULL)
	{
		if (__DEBUG)
		{
			printf("fnGet_PE_NT_Header_Address_By_FileBuffer \r\n");
		}
		goto RET;
	}
	//Add Section
	blStatus = fnAdd_Section(lpFileBuffer, uFileBufferSize, 0x1000, &lpNewFileBuffer, &uNewFileBuffer, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ , ".Quinn");
	//回写
	fnWriteFileFromMemory(PATH_WRITE, lpNewFileBuffer, uNewFileBuffer);

	
RET:
	return 0;
}

