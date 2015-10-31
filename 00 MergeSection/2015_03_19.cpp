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
	pPE_NT_Header->OptionalHeader.DataDirectory[0].Size;
	//Add Section
	//Status = fnAdd_Section(lpFileBuffer, uFileBufferSize, 0x1000, &lpNewFileBuffer, &uNewFileBuffer, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE , ".Quinn");
	//申请ImageBuffer地址
	lpImageBuffer = fnAllocate_ImageBuffer(lpFileBuffer);
	//把FileBuffer拉伸成ImageBuffer
	blStatus = fnFileBuffer_Convert_ImageBuffer(lpFileBuffer, lpImageBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("Main : fnFileBuffer_Convert_ImageBuffer 失败.\r\n");
		}
		goto RET;
	}

	//合并第1 2 个节区
	blStatus = fnMergeSection(lpImageBuffer, 0, 1);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("Main : fnMergeSection 失败.\r\n");
		}
		goto RET;
	}
	//得到新的FileBuffer的大小
	uNewFileBuffer = fnGet_FileBuffer_Size_By_ImageBuffer(lpImageBuffer );
	if (uNewFileBuffer == 0)
	{
		if (__DEBUG)
		{
			printf("Main : uNewFileBuffer 为0.\r\n");
		}
		goto RET;
	}
	//分配NewFileBuffer的空间
	lpNewFileBuffer = malloc(uNewFileBuffer);
	if (lpNewFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("Main : lpNewFileBuffer 为NULL.\r\n");
		}
		goto RET;

	}
	//初始化NewFileBuffer
	memset(lpNewFileBuffer, 0x0, uNewFileBuffer);
	//把ImageBuffer压缩回FileBuffer
	blStatus = fnImageBuffer_Convert_FileBuffer(lpImageBuffer, lpNewFileBuffer);
	


	//回写
	fnWriteFileFromMemory(PATH_WRITE, lpNewFileBuffer, uNewFileBuffer);





	
RET:
	if (lpFileBuffer != NULL)
	{
		free(lpFileBuffer);
		lpFileBuffer = NULL;
	}
	if (lpImageBuffer != NULL)
	{
		free(lpImageBuffer);
		lpFileBuffer = NULL;
	}
	if (lpNewFileBuffer != NULL)
	{
		free(lpNewFileBuffer);
		lpNewFileBuffer = NULL;
	}
	return 0;
}

