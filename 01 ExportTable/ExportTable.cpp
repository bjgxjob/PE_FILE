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
			printf("main: fnReadFile ʧ�ܡ�\r\n");
		}
		goto RET;
	}
	//��ӡExport Table
	fnPrint_ExportTable_Info(lpFileBuffer);
	//�������ֻ�ȡ��ַ
	lptowupper = fnGet_Function_RVA_Address_By_Name(lpFileBuffer, "towupper");
	//���ݱ�Ż�ȡ������ַ
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

