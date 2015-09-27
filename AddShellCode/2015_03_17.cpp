// 2015_03_17.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

PE_DOS_HEADER* pPE_DOS_Header = NULL;

PE_NT_HEADER* pPE_NT_Header = NULL;

char ShellCode[] = 
{
		0x6A, 0x00,		//push 0
		0x6A, 0x00,		//push 0
		0x6A, 0x00,		//push 0
		0x6A, 0x00,		//push 0
		0xE8, 0x00, 0x00, 0x00, 0x00,	//Call MessageBoxA
		0xE9, 0x00, 0x00, 0x00, 0x00,	//JMP OEP
};



int main(int argc, char* argv[])
{
	//״̬�ź�ֵ
	bool blStatus = FALSE;
	//FileBuffer������
	void* pFileBuffer = NULL;
	//ImageBuffer������
	void* pImageBuffer = NULL;
	//FileBuffer��������С
	unsigned int unFileBufferSize = 0;
	//ImageBuffer��������С
	unsigned int unImageBufferSize = 0;
	//����0���ĵ�ַ
	void* pZeroAddress = NULL;
	//E8��Ҫ��ת��ֵ��
	unsigned int unE8Address = 0;
	//E9��Ҫ��ת��ֵ
	unsigned int unE9Address = 0;
	//��ǰָ����ImageBuffer�ĵ�ַ
	unsigned int unCodeCurrentAddress = 0;
	//��OEP
	unsigned int unNewOEP = 0;

	//�õ��ļ���С
	blStatus = fnReadFileToMemory(READ_FILE_PATH, NULL, &unFileBufferSize);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡunFileBufferSizeʧ��\r\n");
		}
		goto RET;
	}
	//����FileBuffer
	pFileBuffer = malloc(unFileBufferSize * sizeof(char));
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pFileBuffer����ʧ��\r\n");
		}
		goto RET;
	}
	//��ʼ��FileBuffer
	memset(pFileBuffer, 0x0, unFileBufferSize * sizeof(char));
	//��ȡ�ļ���pFileBuffer������
	blStatus = fnReadFileToMemory(READ_FILE_PATH, pFileBuffer, &unFileBufferSize);
	//��ȡDOSͷ
	blStatus = fnGet_PE_DOS_Header_Address(pFileBuffer, &pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡpPE_DOS_Headerʧ��\r\n");
		}
		goto RET;
	}
	//��ȡNTͷ
	blStatus = fnGet_PE_NT_Header_Address(pPE_DOS_Header, &pPE_NT_Header);

	//����0��
	blStatus = fnFind_FileBuffer_Zero_Area_in_Section(
		pFileBuffer, 
		IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE, 
		16, 
		&pZeroAddress);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡ������ʧ��\r\n");
		}
		goto RET;
	}
	//д��ShellCode���
	blStatus = fnWrite_ShellCode_To_FileImage(pZeroAddress, ShellCode, sizeof(ShellCode));
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("д��ShellCodeʧ��.\r\n");
		}
		goto RET;
	}
	//����pImageBuffer�ռ�
	pImageBuffer = malloc(pPE_NT_Header->OptionalHeader.SizeOfImage);
	if (pImageBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("����ImageBufferʧ��.\r\n");
		}
		goto RET;
	}
	//��ʼ��pImageBuffer
	memset(pImageBuffer, 0x0, pPE_NT_Header->OptionalHeader.SizeOfImage);
	//����EXE
	blStatus = fnFileBuffer_Convert_ImageBuffer(pFileBuffer, pImageBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("ת��ImageBufferʧ��.\r\n");
		}
		goto RET;
	}
	//�õ���ǰָ���RVA��ַ
	blStatus = fnFOA_Convert_RVA((unsigned int)pZeroAddress + 8, &unCodeCurrentAddress, pFileBuffer, pImageBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("д��fnFOA_Convert_RVAʧ��.\r\n");
		}
		goto RET;
	}
	//����E8ָ����Ҫ��ת�ĵ�ַ
	blStatus = fnCalculate_AddressOf_E8_E9(
		unCodeCurrentAddress - (unsigned int)pImageBuffer + pPE_NT_Header->OptionalHeader.ImageBase, 
		0x77D507EA, 
		&unE8Address);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("д�����E8ָ���ַʧ��.\r\n");
		}
		goto RET;
	}
	//��E8��ַд��ShellCode��
	unCodeCurrentAddress++;
	*(int*)unCodeCurrentAddress = unE8Address;
	//��������E9ָ��Ŀ�ͷ��ַ
	unCodeCurrentAddress = unCodeCurrentAddress + sizeof(int);



	//����e9ָ����Ҫ��ת�ĵ�ַ
	blStatus = fnCalculate_AddressOf_E8_E9(
		unCodeCurrentAddress - (unsigned int)pImageBuffer + pPE_NT_Header->OptionalHeader.ImageBase, 
		pPE_NT_Header->OptionalHeader.AddressOfEntryPoint + pPE_NT_Header->OptionalHeader.ImageBase, 
		&unE9Address);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("д�����E8ָ���ַʧ��.\r\n");
		}
		goto RET;
	}
	
	//��E9��ַд��ShellCode��
	unCodeCurrentAddress++;
	*(int*)unCodeCurrentAddress = unE9Address;
	unCodeCurrentAddress = unCodeCurrentAddress + sizeof(int);


	//����OEP
	blStatus = fnCalculate_New_AddressOfEntryPoint(
		pFileBuffer, 
		(unsigned int)pZeroAddress,
		&unNewOEP);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("������OEPʧ��.\r\n");
		}
		goto RET;
	}
	//��ȡImageBase��Ntͷ
	blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(pImageBuffer, &pPE_NT_Header);

	//�޸�OEP
	pPE_NT_Header->OptionalHeader.AddressOfEntryPoint = unNewOEP;

	//ѹ��EXE
	blStatus = fnImageBuffer_Convert_FileBuffer(pImageBuffer, pFileBuffer);

	//д�����
	blStatus = fnWriteFileFromMemory(WRITE_FILE_PATH, pFileBuffer, unFileBufferSize);


RET:
	if (pFileBuffer != NULL)
	{
		free(pFileBuffer);
		pFileBuffer = NULL;
	}
	if (pImageBuffer != NULL)
	{
		free(pImageBuffer);
		pImageBuffer = NULL;
	}
	return 0;
}

