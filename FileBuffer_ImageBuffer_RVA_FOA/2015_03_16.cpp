// 2015_03_16.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


//读取文件的路径
#define READ_FILE_PATH "c:\\windows\\system32\\notepad.exe"

//保存文件的路径
#define WRITE_FILE_PATH "e:\\notepad_test.exe"

//PE_DOS_HEADER指针
PE_DOS_HEADER* pPE_DOS_Header;
//PE_NT_HEADER指针
PE_NT_HEADER* pPE_NT_Header;
//PE_FILE_HEADER指针
PE_FILE_HEADER* pPE_FILE_Header;
//PE_OPTIONAL_HEADER
PE_OPTIONAL_HEADER* pPE_Optional_Header;
//PE_IMAGE_Section_Header
PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header;



unsigned int unRAV = 0x12F20;
	unsigned int unFOA = 0;

int main(int argc, char* argv[])
{
	//文件缓冲区
	void* pFileBuffer = NULL;
	//映像缓冲区
	void* pImageBuffer = NULL;
	//文件缓冲区大小
	unsigned int unFileSize = 0;
	//映像缓冲区大小
	unsigned int unImageSize = 0;
	//节区的数量
	unsigned int unNumberOfSection = 0;
	//状态参数
	bool blStatus = FALSE;

	//获取文件缓冲区大小
	blStatus = fnReadFileToMemory(READ_FILE_PATH, NULL, &unFileSize);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取文件缓冲区大小失败.\r\n");
		}
		goto RET;
	}
	//文件缓冲区分配空间
	pFileBuffer = malloc(unFileSize * sizeof(char));
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("文件缓冲区分配内存失败。\r\n");
		}
		goto RET;
	}
	//初始化文件缓冲区
	memset(pFileBuffer, 0x0, unFileSize);
	//读取文件到FileBuffer
	blStatus = fnReadFileToMemory(READ_FILE_PATH, pFileBuffer, &unFileSize);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("读取文件到文件缓冲区失败.\r\n");
		}
		goto RET;
	}
	//获得PE_DOS_HEADER指针
	pPE_DOS_Header = (PE_DOS_HEADER *)pFileBuffer;
	//判断是否是有效的WindowsPE文件
	blStatus = fnBlIsVaildWindowsPEFile(pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("不是有效的PE文件。\r\n");
		}
		goto RET;
	}
	//得到PE_NT_HEADER指针
	pPE_NT_Header = (PE_NT_HEADER *)((int)pPE_DOS_Header + pPE_DOS_Header->e_lfanew);
	//判断是否是有效的PE_NT_HEADER头指针
	blStatus = fnBlIsVaildNTHeaderAddress(pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("不是有效的PE_NT_HEADER.\r\n");
		}
		goto RET;
	}
	//获取链表结构数组
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &unNumberOfSection);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取pPE_Image_Section_Header失败。\r\n");
		}
		goto RET;
	}
	//获取ImageBuffer空间大小
	unImageSize = pPE_NT_Header->OptionalHeader.SizeOfImage;
	if (unImageSize == 0)
	{
		if (__DEBUG)
		{
			printf("获取unImageSize失败。\r\n");
		}
		goto RET;
	}
	//分配ImageBuffer空间
	pImageBuffer = malloc(unImageSize * sizeof(char));
	if (pImageBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("分配pImageBuffer失败。\r\n");
		}
		goto RET;
	}
	//初始化ImageBuffer空间
	memset(pImageBuffer, 0x0, unImageSize);

	//拉伸空间
	blStatus = fnFileBuffer_Convert_ImageBuffer(pFileBuffer, pImageBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("拉伸空间出错。\r\n");
		}
		goto RET;
	}
	//压缩空间
	blStatus = fnImageBuffer_Convert_FileBuffer(pImageBuffer, pFileBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("压缩空间出错。\r\n");
		}
		goto RET;
	}
	//写入磁盘
	blStatus = fnWriteFileFromMemory(WRITE_FILE_PATH, pFileBuffer, unFileSize);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("写入%s出错。\r\n", WRITE_FILE_PATH);
		}
		goto RET;
	}

RET:
	//释放pFileBuffer
	if (pFileBuffer != NULL)
	{
		free(pFileBuffer);
		pFileBuffer = NULL;
	}
	//释放pImageBuffer
	if (pImageBuffer != NULL)
	{
		free(pImageBuffer);
		pImageBuffer = NULL;
	}
	
	return 0;
}

