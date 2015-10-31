// 2015_03_19.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

int main(int argc, char* argv[])
{
	//FBS��FileBuffer�Ĵ�С
	unsigned uFileBufferSize = 0;
	//FB:FileBuffer
	LPVOID lpFileBuffer = NULL;
	//IB:ImageBuffer
	LPVOID lpImageBuffer = NULL;
	//IBS:ImageBuffer�Ĵ�С
	unsigned uImageBufferSize = 0;
	//Pointer of PE_OPTIONAL_HEADER
	PE_NT_HEADER* pPE_NT_Header = NULL;
	bool blStatus = FALSE;
	//pNewFileBuffer
	LPVOID lpNewFileBuffer = NULL;
	//pNewFileBuffer
	unsigned uNewFileBuffer = 0;


	//���FB��С
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
	//����FB�ռ�
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
	//����ImageBuffer��ַ
	lpImageBuffer = fnAllocate_ImageBuffer(lpFileBuffer);
	//��FileBuffer�����ImageBuffer
	blStatus = fnFileBuffer_Convert_ImageBuffer(lpFileBuffer, lpImageBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("Main : fnFileBuffer_Convert_ImageBuffer ʧ��.\r\n");
		}
		goto RET;
	}

	//�ϲ���1 2 ������
	blStatus = fnMergeSection(lpImageBuffer, 0, 1);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("Main : fnMergeSection ʧ��.\r\n");
		}
		goto RET;
	}
	//�õ��µ�FileBuffer�Ĵ�С
	uNewFileBuffer = fnGet_FileBuffer_Size_By_ImageBuffer(lpImageBuffer );
	if (uNewFileBuffer == 0)
	{
		if (__DEBUG)
		{
			printf("Main : uNewFileBuffer Ϊ0.\r\n");
		}
		goto RET;
	}
	//����NewFileBuffer�Ŀռ�
	lpNewFileBuffer = malloc(uNewFileBuffer);
	if (lpNewFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("Main : lpNewFileBuffer ΪNULL.\r\n");
		}
		goto RET;

	}
	//��ʼ��NewFileBuffer
	memset(lpNewFileBuffer, 0x0, uNewFileBuffer);
	//��ImageBufferѹ����FileBuffer
	blStatus = fnImageBuffer_Convert_FileBuffer(lpImageBuffer, lpNewFileBuffer);
	


	//��д
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

