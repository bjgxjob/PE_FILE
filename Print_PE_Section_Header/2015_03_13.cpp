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
	
	//��ȡ�ļ���С��
	blStatus = fnReadFileToMemory("c:\\windows\\system32\\notepad.exe", NULL, (unsigned*)&nBufferSize);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡ�ļ���Сʧ��.\r\n");
		}
		goto RET;
	}
	//����pFileBuffer�ڴ�ռ�
	pFileBuffer = malloc(nBufferSize * sizeof(char));
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("�����ڴ�ռ�ʧ�ܡ�\r\n");
		}
		goto RET;
	}
	
	//��ȡ�ļ�
	blStatus = fnReadFileToMemory("c:\\windows\\system32\\notepad.exe", pFileBuffer, (unsigned*)&nBufferSize);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡ�ļ����ڴ���ʧ��");
		}
		goto RET;
	}
	
	//��ȡPEDOSͷ��ַ
	pPE_DOS_HEADER = (PE_DOS_HEADER *)pFileBuffer;
	//�ж��Ƿ�����Ч��Windows�ļ�
	blStatus = fnBlIsVaildWindowsExecutiveFile(pPE_DOS_HEADER);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("������Ч��WINDOWS_PE�ļ���\r\n");
		}
		goto RET;
	}
	//��ȡPE_NT_HEADER�ĵ�ַ
	pPE_NT_HEADER = (PE_NT_HEADER *)((int)pFileBuffer + pPE_DOS_HEADER->e_lfanew);
	//�ж��Ƿ�����Ч��PE_NT_HEADER��ַ
	blStatus = fnBlIsVaildNTHeaderAddress(pPE_NT_HEADER);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("������Ч��NT_HEADER��ַ��\r\n");
		}
		goto RET;
	}
	//��ȡSECTION_HEADER�ĳ�ʼ��ַ
	pPE_IMAGE_SECTION_HEADER = (PE_IMAGE_SECTION_HEADER *)((int)(&pPE_NT_HEADER->OptionalHeader) + pPE_NT_HEADER->FileHeader.SizeOfOptionalHeader);
	//��ӡSECTION_HEADER��ֵ
	fnPrintPE_SECTION_HEADER_Info(pPE_IMAGE_SECTION_HEADER, pPE_NT_HEADER->FileHeader.NumberOfSections);

RET:
	if (pFileBuffer != NULL)
	{
		free(pFileBuffer);
		pFileBuffer = NULL;
	}
	return 0;
}

