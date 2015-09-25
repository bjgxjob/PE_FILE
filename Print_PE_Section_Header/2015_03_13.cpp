// 2015_03_13.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


PE_DOS_HEADER* pPE_DOS_HEADER;
PE_NT_HEADER* pPE_NT_HEADER;
PE_IMAGE_SECTION_HEADER* pPE_IMAGE_SECTION_HEADER;

int main(int argc, char* argv[])
{
	void* pFileBuffer = NULL;
	int nBufferSize = 0;
	bool blStatus = FALSE;
	
	//获取文件大小：
	blStatus = fnReadFileToMemory("c:\\windows\\system32\\notepad.exe", NULL, (unsigned*)&nBufferSize);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取文件大小失败.\r\n");
		}
		goto RET;
	}
	//分配pFileBuffer内存空间
	pFileBuffer = malloc(nBufferSize * sizeof(char));
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("分配内存空间失败。\r\n");
		}
		goto RET;
	}
	
	//读取文件
	blStatus = fnReadFileToMemory("c:\\windows\\system32\\notepad.exe", pFileBuffer, (unsigned*)&nBufferSize);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("读取文件到内存中失败");
		}
		goto RET;
	}
	
	//获取PEDOS头地址
	pPE_DOS_HEADER = (PE_DOS_HEADER *)pFileBuffer;
	//判断是否是有效的Windows文件
	blStatus = fnBlIsVaildWindowsExecutiveFile(pPE_DOS_HEADER);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("不是有效的WINDOWS_PE文件。\r\n");
		}
		goto RET;
	}
	//获取PE_NT_HEADER的地址
	pPE_NT_HEADER = (PE_NT_HEADER *)((int)pFileBuffer + pPE_DOS_HEADER->e_lfanew);
	//判断是否是有效的PE_NT_HEADER地址
	blStatus = fnBlIsVaildNTHeaderAddress(pPE_NT_HEADER);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("不是有效的NT_HEADER地址。\r\n");
		}
		goto RET;
	}
	//获取SECTION_HEADER的初始地址
	pPE_IMAGE_SECTION_HEADER = (PE_IMAGE_SECTION_HEADER *)((int)(&pPE_NT_HEADER->OptionalHeader) + pPE_NT_HEADER->FileHeader.SizeOfOptionalHeader);
	//打印SECTION_HEADER的值
	fnPrintPE_SECTION_HEADER_Info(pPE_IMAGE_SECTION_HEADER, pPE_NT_HEADER->FileHeader.NumberOfSections);

RET:
	if (pFileBuffer != NULL)
	{
		free(pFileBuffer);
		pFileBuffer = NULL;
	}
	return 0;
}

