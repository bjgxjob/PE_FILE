// FileOperation.cpp: implementation of the CFileOperation class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "FileOperation.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////



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

//***********************************
//函数名：bool fnReadFile(char* szPath, LPVOID lpFileBuffer, unsigned* punSizeOfFileBuffer)
//功能：根据szPath读取文件到指定的缓冲区，缓冲区不需要提前分配空间。
//参数1：IN char* szPath
//参数1说明：读取文件的路径
//参数2：LPVOID* plpFileBuffer
//参数2说明: 缓冲区的地址的指针，可以不用提前分配空间。
//参数3：IN OUT unsigned* punSizeOfFileBuffer
//参数3说明：缓冲区的大小
//返回值：如果成功，返回TRUE，如果失败，返回FALSE
//***********************************

bool fnReadFile(IN char* szPath, IN OUT LPVOID* plpFileBuffer, IN OUT unsigned* punSizeOfFileBuffer)
{


	bool blStatus = FALSE;

	if (*plpFileBuffer != NULL)
	{
		if (__DEBUG)
		{
			printf("fnReadFile(): *plpFileBuffer != NULL \r\n");
		}
		goto F;
		
	}
	//获取FileBuffer的大小
	blStatus = fnReadFileToMemory(szPath, NULL, punSizeOfFileBuffer);
	if (blStatus != TRUE || *punSizeOfFileBuffer == 0 )
	{
		if (__DEBUG)
		{
			printf("main(): fnReadFileToMemory() 失败 \r\n");
		}
		goto F;
		
	}
	//分配FileBuffer的大小
	*plpFileBuffer = malloc(*punSizeOfFileBuffer);
	if (*plpFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("main(): lpFileBuffer 分配失败 \r\n");
		}
		goto F;
	}
	//初始化空间
	memset(*plpFileBuffer, 0x0, *punSizeOfFileBuffer);
	//读入文件
	blStatus = fnReadFileToMemory(szPath, *plpFileBuffer, punSizeOfFileBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("main(): fnReadFileToMemory() 失败 \r\n");
		}
		goto F;
		
	}

	return TRUE;
F:
	if (*plpFileBuffer != NULL)
	{
		free(*plpFileBuffer);
		*plpFileBuffer = NULL;
	}
	return FALSE;

}




