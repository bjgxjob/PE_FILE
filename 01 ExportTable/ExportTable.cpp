// ExportTable.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "FileOperation.h"
#include "PEFileStructure.h"

#define READ_PATH "C:\\windows\\system32\\ntoskrnl.exe"

int main(int argc, char* argv[])
{
	//FileBuffer
	LPVOID lpFileBuffer = NULL;
	unsigned uSizeOfFileBuffer = 0;
	bool blStatus = FALSE;
	LPVOID lptowupper = NULL;
	LPVOID lpwctomb = NULL;

	blStatus = fnReadFile(READ_PATH, &lpFileBuffer, &uSizeOfFileBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("main: fnReadFile 失败。\r\n");
		}
		goto RET;
	}
	//打印Export Table
	fnPrint_ExportTable_Info(lpFileBuffer);
	//根据名字获取地址
	lptowupper = fnGet_Function_RVA_Address_By_Name(lpFileBuffer, "towupper");
	//根据编号获取函数地址
	lpwctomb = fnGet_Function_RVA_Address_By_Ordinals(lpFileBuffer, 0x05cf);

	printf("towupper RVA:%08X\r\nlpwctomb RVA:%08X \r\n", (unsigned)lptowupper, (unsigned)lpwctomb);

	
RET:
	if (lpFileBuffer != NULL)
	{
		free(lpFileBuffer);
		lpFileBuffer = NULL;
	}
	return 0;
}

