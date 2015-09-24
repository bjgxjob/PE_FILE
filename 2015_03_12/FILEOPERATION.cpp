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


bool fnReadFileToMemory(char* szPath, //读取文件的目录
						 void* pReturnBuffer, //读出来文件存放的内存指针。
						 unsigned int* punFileSize //读取后的字节长度
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
			printf("打开文件指针出错。\r\n");
		}
		
		return false;

	}
	//int fseek( FILE *stream, long offset, int origin );
	//Moves the file pointer to a specified location.
	//SEEK_END  End of file
	
	
	//移动文件指针到文件末尾
	unError = fseek(stream, 0, SEEK_END);
	if (unError != NULL)
	{
		fclose(stream);
		if (__DEBUG)
		{
			printf("寻找文件尾出错。\r\n");
		}
		return false;
	}
	//得到文件的大小
	(*punFileSize) = ftell(stream);
	if ((*punFileSize) < 0)
	{
		fclose(stream);
		if (__DEBUG)
		{
			printf("得到文件大小出错，错误代码：%d\r\n", (*punFileSize));
		}
		return false;
	}

	//移动文件指针到文件首
	unError = fseek(stream, 0, SEEK_SET);
	if (unError != NULL)
	{
		fclose(stream);
		if (__DEBUG)
		{
			printf("寻找文件首出错。\r\n");
		}
		return false;
	}

	//分配缓冲区存放文件
	pBuffer = malloc((*punFileSize) * sizeof(char));
	if (pBuffer == NULL)
	{
		fclose(stream);
		if (__DEBUG)
		{
			printf("分配文件大小失败。\r\n");
		}
		return false;

	}
	//初始化缓冲区
	memset(pBuffer, 0x0, (*punFileSize) * sizeof(char));

	//读取文件
	//size_t fread( void *buffer, size_t size, size_t count, FILE *stream );
	unError = fread(pBuffer, sizeof(char), (*punFileSize), stream);
	if (unError != (*punFileSize))
	{
		free(pBuffer);
		fclose(stream);
		if (__DEBUG)
		{
			printf("读取文件失败，错误代码：%d.\r\n", ferror(stream));
		}
		return false;
	}
	//copy内存
	if (pReturnBuffer != NULL)
	{
		memcpy(pReturnBuffer, pBuffer, *punFileSize);
	}
	//关闭文件流
	unError = fclose(stream);
	if (unError != 0)
	{
		free(pBuffer);
		if (__DEBUG)
		{
			printf("关闭文件流失败，错误代码:%d.\r\n", unError);
		}
		return false;
	}

	free(pBuffer);
	stream = NULL;



	

	return true;
}

bool fnWriteFileFromMemory(char* szPath, //写入文件的路径
						   void* pBuffer, //需要写入文件的缓冲区路径
						   unsigned int unFileSize //写入文件的大小
						   )
{
	FILE* stream = NULL;
	unsigned int unError = 0;


	//打开文件流，如果文件不存在就新建文件，如果存在，就是覆盖文件。
	stream = fopen(szPath, "w+b");
	if (stream == NULL)
	{
		if (__DEBUG)
		{
			printf("建立文件失败。\r\n");
		}
		return false;
	}

	//写入文件
	//size_t fwrite( const void *buffer, size_t size, size_t count, FILE *stream );
	unError = fwrite(pBuffer, sizeof(char), unFileSize, stream);
	if (unError != unFileSize)
	{
		fclose(stream);
		if (__DEBUG)
		{
			printf("写入文件出错。\r\n");
		}
		return false;
	}

	//关闭文件流
	unError = fclose(stream);
	if (unError != 0)
	{
		free(pBuffer);
		if (__DEBUG)
		{
			printf("关闭文件流失败，错误代码:%d.\r\n", unError);
		}
		return false;
	}

	return true;

}



