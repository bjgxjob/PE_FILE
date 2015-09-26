// 2015_03_16.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


//��ȡ�ļ���·��
#define READ_FILE_PATH "c:\\windows\\system32\\notepad.exe"

//�����ļ���·��
#define WRITE_FILE_PATH "e:\\notepad_test.exe"

//PE_DOS_HEADERָ��
PE_DOS_HEADER* pPE_DOS_Header;
//PE_NT_HEADERָ��
PE_NT_HEADER* pPE_NT_Header;
//PE_FILE_HEADERָ��
PE_FILE_HEADER* pPE_FILE_Header;
//PE_OPTIONAL_HEADER
PE_OPTIONAL_HEADER* pPE_Optional_Header;
//PE_IMAGE_Section_Header
PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header;



unsigned int unRAV = 0x12F20;
	unsigned int unFOA = 0;

int main(int argc, char* argv[])
{
	//�ļ�������
	void* pFileBuffer = NULL;
	//ӳ�񻺳���
	void* pImageBuffer = NULL;
	//�ļ���������С
	unsigned int unFileSize = 0;
	//ӳ�񻺳�����С
	unsigned int unImageSize = 0;
	//����������
	unsigned int unNumberOfSection = 0;
	//״̬����
	bool blStatus = FALSE;

	//��ȡ�ļ���������С
	blStatus = fnReadFileToMemory(READ_FILE_PATH, NULL, &unFileSize);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡ�ļ���������Сʧ��.\r\n");
		}
		goto RET;
	}
	//�ļ�����������ռ�
	pFileBuffer = malloc(unFileSize * sizeof(char));
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("�ļ������������ڴ�ʧ�ܡ�\r\n");
		}
		goto RET;
	}
	//��ʼ���ļ�������
	memset(pFileBuffer, 0x0, unFileSize);
	//��ȡ�ļ���FileBuffer
	blStatus = fnReadFileToMemory(READ_FILE_PATH, pFileBuffer, &unFileSize);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡ�ļ����ļ�������ʧ��.\r\n");
		}
		goto RET;
	}
	//���PE_DOS_HEADERָ��
	pPE_DOS_Header = (PE_DOS_HEADER *)pFileBuffer;
	//�ж��Ƿ�����Ч��WindowsPE�ļ�
	blStatus = fnBlIsVaildWindowsPEFile(pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("������Ч��PE�ļ���\r\n");
		}
		goto RET;
	}
	//�õ�PE_NT_HEADERָ��
	pPE_NT_Header = (PE_NT_HEADER *)((int)pPE_DOS_Header + pPE_DOS_Header->e_lfanew);
	//�ж��Ƿ�����Ч��PE_NT_HEADERͷָ��
	blStatus = fnBlIsVaildNTHeaderAddress(pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("������Ч��PE_NT_HEADER.\r\n");
		}
		goto RET;
	}
	//��ȡ����ṹ����
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &unNumberOfSection);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡpPE_Image_Section_Headerʧ�ܡ�\r\n");
		}
		goto RET;
	}
	//��ȡImageBuffer�ռ��С
	unImageSize = pPE_NT_Header->OptionalHeader.SizeOfImage;
	if (unImageSize == 0)
	{
		if (__DEBUG)
		{
			printf("��ȡunImageSizeʧ�ܡ�\r\n");
		}
		goto RET;
	}
	//����ImageBuffer�ռ�
	pImageBuffer = malloc(unImageSize * sizeof(char));
	if (pImageBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("����pImageBufferʧ�ܡ�\r\n");
		}
		goto RET;
	}
	//��ʼ��ImageBuffer�ռ�
	memset(pImageBuffer, 0x0, unImageSize);

	//����ռ�
	blStatus = fnFileBuffer_Convert_ImageBuffer(pFileBuffer, pImageBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("����ռ����\r\n");
		}
		goto RET;
	}
	//ѹ���ռ�
	blStatus = fnImageBuffer_Convert_FileBuffer(pImageBuffer, pFileBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("ѹ���ռ����\r\n");
		}
		goto RET;
	}
	//д�����
	blStatus = fnWriteFileFromMemory(WRITE_FILE_PATH, pFileBuffer, unFileSize);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("д��%s����\r\n", WRITE_FILE_PATH);
		}
		goto RET;
	}

RET:
	//�ͷ�pFileBuffer
	if (pFileBuffer != NULL)
	{
		free(pFileBuffer);
		pFileBuffer = NULL;
	}
	//�ͷ�pImageBuffer
	if (pImageBuffer != NULL)
	{
		free(pImageBuffer);
		pImageBuffer = NULL;
	}
	
	return 0;
}

