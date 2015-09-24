// 2015_03_12.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "PEFILESTRUCTURE.h"
#include "FILEOPERATION.h"



//定义PE_DOS_HEADER
PE_DOS_HEADER* pPE_DOS_HEADER;

//定义PE_NT_HEADER
PE_NT_HEADER* pPE_NT_HEADER;

//定义PE_OPTIONAL_HEADER
PE_OPTIONAL_HEADER* pPE_OPTIONAL_HEADER;

//定义PE_FILE_HEADER
PE_FILE_HEADER* pPE_FILE_HEADER;


int main(int argc, char* argv[])
{
	void* pFileBuffer = NULL;
	unsigned unFileSize = 0;
	bool blStatus = FALSE;

	//得到FileBuffer的大小
	blStatus = fnReadFileToMemory("c:\\windows\\system32\\notepad.exe", NULL, &unFileSize);
	if (blStatus !=TRUE)
	{
		if (__DEBUG)
		{
			printf("得到FileBuffer失败。\r\n");
		}
		goto RET;
	}

	//分配FileBuffer内存空间
	pFileBuffer = malloc(unFileSize * sizeof(char));
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("分配FileBuffer内存空间失败.\r\n");
		}
		goto RET;
	}
	
	//初始化FileBuffer内存空间
	memset(pFileBuffer, 0x0, unFileSize);

	//读取文件
	blStatus = fnReadFileToMemory("C:\\windows\\system32\\notepad.exe", pFileBuffer, &unFileSize);

	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("读取文件失败。\r\n");
		}
		goto RET;
	}

	//得到PE_DOS_HEADER指针
	pPE_DOS_HEADER = (PE_DOS_HEADER*)pFileBuffer;

	blStatus = fnBlIsVaildWindowsExecutiveFile(pPE_DOS_HEADER);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("不是有效的PE文件。\r\n");
		}
		goto RET;
	}
	//打印PE_DOS_HEADER的信息
	fnPrintPE_DOS_HEADER_Info(pPE_DOS_HEADER);

	//得到PE_NT头的地址
	pPE_NT_HEADER = (PE_NT_HEADER *)((int)pFileBuffer + pPE_DOS_HEADER->e_lfanew);
	
	//判断是否是有效的PE_NT头地址
	blStatus = fnBlIsVaildNTHeaderAddress(pPE_NT_HEADER);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("不是有效的NT头地址，或者不是有效的PE文件。\r\n");
		}
		goto RET;
	}
	//打印PE_FILE_HEADER的信息
	fnPrintPE_NT_HEADER_Info(pPE_NT_HEADER);

	//得到PE_FILE_HEADER的地址
	pPE_FILE_HEADER = (PE_FILE_HEADER*)((int)pPE_NT_HEADER + sizeof(DWORD));

	//打印PE_FILE_HEADER的信息
	fnPrintPE_FILE_HEADER_Info(pPE_FILE_HEADER);

	//得到PE_OPTIONAL_HEADER的信息
	pPE_OPTIONAL_HEADER = (struct PE_OPTIONAL_HEADER *)((int)pPE_FILE_HEADER + (sizeof(DWORD) * 3 + sizeof(WORD) * 4));

	//打印PE_OPTIONAL_HEADER的信息
	fnPrintfPE_OPTIONAL_HEADER_Info(pPE_OPTIONAL_HEADER);


	










	


RET:
	if (pFileBuffer != NULL)
	{
		free(pFileBuffer);
		pFileBuffer = NULL;
	}

	return 0;
}

