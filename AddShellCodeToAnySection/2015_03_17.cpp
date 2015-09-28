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
	//状态信号值
	bool blStatus = FALSE;
	//FileBuffer缓冲区
	void* pFileBuffer = NULL;
	//ImageBuffer缓冲区
	void* pImageBuffer = NULL;
	//FileBuffer缓冲区大小
	unsigned int unFileBufferSize = 0;
	//ShellCode的首地址
	void* pShellCodeAddress = NULL;
	//E8需要跳转的值。
	unsigned int unE8Address = 0;
	//E9需要跳转的值
	unsigned int unE9Address = 0;
	//新OEP
	unsigned int unNewOEP = 0;
	//FOA临时变量
	unsigned int unTempFOA = 0;

	//得到文件大小
	blStatus = fnReadFileToMemory(READ_FILE_PATH, NULL, &unFileBufferSize);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取unFileBufferSize失败\r\n");
		}
		goto RET;
	}
	//分配FileBuffer
	pFileBuffer = malloc(unFileBufferSize * sizeof(char));
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pFileBuffer分配失败\r\n");
		}
		goto RET;
	}
	//初始化FileBuffer
	memset(pFileBuffer, 0x0, unFileBufferSize * sizeof(char));
	//读取文件到pFileBuffer缓冲区
	blStatus = fnReadFileToMemory(READ_FILE_PATH, pFileBuffer, &unFileBufferSize);

	//获取DOS头
	blStatus = fnGet_PE_DOS_Header_Address(pFileBuffer, &pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取pPE_DOS_Header失败\r\n");
		}
		goto RET;
	}
	//获取NT头
	blStatus = fnGet_PE_NT_Header_Address(pPE_DOS_Header, &pPE_NT_Header);
	//分配ImageBuffer空间
	pImageBuffer = malloc(pPE_NT_Header->OptionalHeader.SizeOfImage);
	if (pImageBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("分配ImageBuffer空间失败\r\n");
		}
		goto RET;
	}
	//初始化ImageBuffer
	memset(pImageBuffer, 0x0, pPE_NT_Header->OptionalHeader.SizeOfImage);
	//拉伸空间
	blStatus = fnFileBuffer_Convert_ImageBuffer(pFileBuffer, pImageBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("拉伸空间失败\r\n");
		}
		goto RET;
	}
	//得到需要写入的地址
	blStatus = fnFind_ImageBuffer_ShellCode_Space_in_Section(
		pImageBuffer, 
		IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA,
		sizeof(ShellCode),
		0x2,  //写入的节编号
		&pShellCodeAddress);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取pShellCodeAddress失败\r\n");
		}
		goto RET;
	}
	//写入ShellCode框架数据
	blStatus = fnWrite_ShellCode_To_FileImage(pShellCodeAddress, ShellCode, sizeof(ShellCode));
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取写入ShellCode失败\r\n");
		}
		goto RET;
	}
	//计算E8地址
	blStatus = fnCalculate_AddressOf_E8_E9(
		(unsigned int)pShellCodeAddress - (unsigned)pImageBuffer + pPE_NT_Header->OptionalHeader.ImageBase + 8, 
		0x77D507EA, //MessageBoxA的地址
		&unE8Address);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取unE8Address失败\r\n");
		}
		goto RET;
	}
	//写入E8数据
	blStatus = fnWrite_Data_To_Memory((void*)((unsigned int)pShellCodeAddress + 8 + 1), &unE8Address, sizeof(unE8Address));
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnWrite_Data_To_Memory失败\r\n");
		}
		goto RET;
	}
	//计算E9的数据
	blStatus = fnCalculate_AddressOf_E8_E9(
		(unsigned int)pShellCodeAddress - (unsigned)pImageBuffer + pPE_NT_Header->OptionalHeader.ImageBase + 8 + 5, 
		pPE_NT_Header->OptionalHeader.AddressOfEntryPoint + pPE_NT_Header->OptionalHeader.ImageBase, 
		&unE9Address);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取unE9Address失败\r\n");
		}
		goto RET;
	}
	//写入E9数据
	blStatus = fnWrite_Data_To_Memory((void*)((unsigned int)pShellCodeAddress + 8 + 5 + 1), &unE9Address, sizeof(unE9Address));
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnWrite_Data_To_Memory失败\r\n");
		}
		goto RET;
	}
	//转换FOA
	blStatus = fnRVA_Convert_FOA((unsigned)pShellCodeAddress, &unTempFOA, pImageBuffer, pFileBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnRVA_Convert_FOA 失败\r\n");
		}
		goto RET;
	}
	//计算地址
	blStatus = fnCalculate_New_AddressOfEntryPoint(pFileBuffer, (unsigned)unTempFOA, &unNewOEP);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnCalculate_New_AddressOfEntryPoint 失败\r\n");
		}
		goto RET;
	}
	//修改OEP
	blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(pImageBuffer, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnGet_PE_NT_Header_Address_By_FileBuffer 失败\r\n");
		}
		goto RET;
	}

	pPE_NT_Header->OptionalHeader.AddressOfEntryPoint = unNewOEP;
	//压缩ImageBuffer
	blStatus = fnImageBuffer_Convert_FileBuffer(pImageBuffer, pFileBuffer);
	//写入文件
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

