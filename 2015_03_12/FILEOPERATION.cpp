// FILEOPERATION.cpp: implementation of the CFILEOPERATION class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "FILEOPERATION.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CFILEOPERATION::CFILEOPERATION()
{

}

CFILEOPERATION::~CFILEOPERATION()
{

}


bool fnReadFileToMemory(char* szPath, //��ȡ�ļ���Ŀ¼
						 void* pReturnBuffer, //�������ļ���ŵ��ڴ�ָ�롣
						 unsigned int* punFileSize //��ȡ����ֽڳ���
						 )
{
	FILE* stream;
	unsigned int unError = 0;
	void* pBuffer = NULL;
	//FILE *fopen( const char *filename, const char *mode );
	stream = fopen(szPath, "rb");

	//Each of these functions returns a pointer to the open file. A null pointer value indicates an error. 
	if (stream == NULL)
	{
		if (__DEBUG)
		{
			printf("���ļ�ָ�����\r\n");
		}
		
		return false;

	}
	//int fseek( FILE *stream, long offset, int origin );
	//Moves the file pointer to a specified location.
	//SEEK_END  End of file
	
	
	//�ƶ��ļ�ָ�뵽�ļ�ĩβ
	unError = fseek(stream, 0, SEEK_END);
	if (unError != NULL)
	{
		fclose(stream);
		if (__DEBUG)
		{
			printf("Ѱ���ļ�β����\r\n");
		}
		return false;
	}
	//�õ��ļ��Ĵ�С
	(*punFileSize) = ftell(stream);
	if ((*punFileSize) < 0)
	{
		fclose(stream);
		if (__DEBUG)
		{
			printf("�õ��ļ���С����������룺%d\r\n", (*punFileSize));
		}
		return false;
	}

	//�ƶ��ļ�ָ�뵽�ļ���
	unError = fseek(stream, 0, SEEK_SET);
	if (unError != NULL)
	{
		fclose(stream);
		if (__DEBUG)
		{
			printf("Ѱ���ļ��׳���\r\n");
		}
		return false;
	}

	//���仺��������ļ�
	pBuffer = malloc((*punFileSize) * sizeof(char));
	if (pBuffer == NULL)
	{
		fclose(stream);
		if (__DEBUG)
		{
			printf("�����ļ���Сʧ�ܡ�\r\n");
		}
		return false;

	}
	//��ʼ��������
	memset(pBuffer, 0x0, (*punFileSize) * sizeof(char));

	//��ȡ�ļ�
	//size_t fread( void *buffer, size_t size, size_t count, FILE *stream );
	unError = fread(pBuffer, sizeof(char), (*punFileSize), stream);
	if (unError != (*punFileSize))
	{
		free(pBuffer);
		fclose(stream);
		if (__DEBUG)
		{
			printf("��ȡ�ļ�ʧ�ܣ�������룺%d.\r\n", ferror(stream));
		}
		return false;
	}
	//copy�ڴ�
	if (pReturnBuffer != NULL)
	{
		memcpy(pReturnBuffer, pBuffer, *punFileSize);
	}
	//�ر��ļ���
	unError = fclose(stream);
	if (unError != 0)
	{
		free(pBuffer);
		if (__DEBUG)
		{
			printf("�ر��ļ���ʧ�ܣ��������:%d.\r\n", unError);
		}
		return false;
	}

	free(pBuffer);
	stream = NULL;



	

	return true;
}

bool fnWriteFileFromMemory(char* szPath, //д���ļ���·��
						   void* pBuffer, //��Ҫд���ļ��Ļ�����·��
						   unsigned int unFileSize //д���ļ��Ĵ�С
						   )
{
	FILE* stream = NULL;
	unsigned int unError = 0;


	//���ļ���������ļ������ھ��½��ļ���������ڣ����Ǹ����ļ���
	stream = fopen(szPath, "w+b");
	if (stream == NULL)
	{
		if (__DEBUG)
		{
			printf("�����ļ�ʧ�ܡ�\r\n");
		}
		return false;
	}

	//д���ļ�
	//size_t fwrite( const void *buffer, size_t size, size_t count, FILE *stream );
	unError = fwrite(pBuffer, sizeof(char), unFileSize, stream);
	if (unError != unFileSize)
	{
		fclose(stream);
		if (__DEBUG)
		{
			printf("д���ļ�����\r\n");
		}
		return false;
	}

	//�ر��ļ���
	unError = fclose(stream);
	if (unError != 0)
	{
		free(pBuffer);
		if (__DEBUG)
		{
			printf("�ر��ļ���ʧ�ܣ��������:%d.\r\n", unError);
		}
		return false;
	}

	return true;

}



