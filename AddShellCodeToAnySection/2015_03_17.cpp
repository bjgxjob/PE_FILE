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
	//ShellCode���׵�ַ
	void* pShellCodeAddress = NULL;
	//E8��Ҫ��ת��ֵ��
	unsigned int unE8Address = 0;
	//E9��Ҫ��ת��ֵ
	unsigned int unE9Address = 0;
	//��OEP
	unsigned int unNewOEP = 0;
	//FOA��ʱ����
	unsigned int unTempFOA = 0;

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
	//����ImageBuffer�ռ�
	pImageBuffer = malloc(pPE_NT_Header->OptionalHeader.SizeOfImage);
	if (pImageBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("����ImageBuffer�ռ�ʧ��\r\n");
		}
		goto RET;
	}
	//��ʼ��ImageBuffer
	memset(pImageBuffer, 0x0, pPE_NT_Header->OptionalHeader.SizeOfImage);
	//����ռ�
	blStatus = fnFileBuffer_Convert_ImageBuffer(pFileBuffer, pImageBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("����ռ�ʧ��\r\n");
		}
		goto RET;
	}
	//�õ���Ҫд��ĵ�ַ
	blStatus = fnFind_ImageBuffer_ShellCode_Space_in_Section(
		pImageBuffer, 
		IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA,
		sizeof(ShellCode),
		0x2,  //д��Ľڱ��
		&pShellCodeAddress);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡpShellCodeAddressʧ��\r\n");
		}
		goto RET;
	}
	//д��ShellCode�������
	blStatus = fnWrite_ShellCode_To_FileImage(pShellCodeAddress, ShellCode, sizeof(ShellCode));
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡд��ShellCodeʧ��\r\n");
		}
		goto RET;
	}
	//����E8��ַ
	blStatus = fnCalculate_AddressOf_E8_E9(
		(unsigned int)pShellCodeAddress - (unsigned)pImageBuffer + pPE_NT_Header->OptionalHeader.ImageBase + 8, 
		0x77D507EA, //MessageBoxA�ĵ�ַ
		&unE8Address);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡunE8Addressʧ��\r\n");
		}
		goto RET;
	}
	//д��E8����
	blStatus = fnWrite_Data_To_Memory((void*)((unsigned int)pShellCodeAddress + 8 + 1), &unE8Address, sizeof(unE8Address));
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnWrite_Data_To_Memoryʧ��\r\n");
		}
		goto RET;
	}
	//����E9������
	blStatus = fnCalculate_AddressOf_E8_E9(
		(unsigned int)pShellCodeAddress - (unsigned)pImageBuffer + pPE_NT_Header->OptionalHeader.ImageBase + 8 + 5, 
		pPE_NT_Header->OptionalHeader.AddressOfEntryPoint + pPE_NT_Header->OptionalHeader.ImageBase, 
		&unE9Address);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡunE9Addressʧ��\r\n");
		}
		goto RET;
	}
	//д��E9����
	blStatus = fnWrite_Data_To_Memory((void*)((unsigned int)pShellCodeAddress + 8 + 5 + 1), &unE9Address, sizeof(unE9Address));
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnWrite_Data_To_Memoryʧ��\r\n");
		}
		goto RET;
	}
	//ת��FOA
	blStatus = fnRVA_Convert_FOA((unsigned)pShellCodeAddress, &unTempFOA, pImageBuffer, pFileBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnRVA_Convert_FOA ʧ��\r\n");
		}
		goto RET;
	}
	//�����ַ
	blStatus = fnCalculate_New_AddressOfEntryPoint(pFileBuffer, (unsigned)unTempFOA, &unNewOEP);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnCalculate_New_AddressOfEntryPoint ʧ��\r\n");
		}
		goto RET;
	}
	//�޸�OEP
	blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(pImageBuffer, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnGet_PE_NT_Header_Address_By_FileBuffer ʧ��\r\n");
		}
		goto RET;
	}

	pPE_NT_Header->OptionalHeader.AddressOfEntryPoint = unNewOEP;
	//ѹ��ImageBuffer
	blStatus = fnImageBuffer_Convert_FileBuffer(pImageBuffer, pFileBuffer);
	//д���ļ�
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

