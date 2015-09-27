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
	//ImageBuffer缓冲区大小
	unsigned int unImageBufferSize = 0;
	//搜索0区的地址
	void* pZeroAddress = NULL;
	//E8需要跳转的值。
	unsigned int unE8Address = 0;
	//E9需要跳转的值
	unsigned int unE9Address = 0;
	//当前指令在ImageBuffer的地址
	unsigned int unCodeCurrentAddress = 0;
	//新OEP
	unsigned int unNewOEP = 0;

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

	//搜索0区
	blStatus = fnFind_FileBuffer_Zero_Area_in_Section(
		pFileBuffer, 
		IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE, 
		16, 
		&pZeroAddress);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取空区域失败\r\n");
		}
		goto RET;
	}
	//写入ShellCode框架
	blStatus = fnWrite_ShellCode_To_FileImage(pZeroAddress, ShellCode, sizeof(ShellCode));
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("写入ShellCode失败.\r\n");
		}
		goto RET;
	}
	//分配pImageBuffer空间
	pImageBuffer = malloc(pPE_NT_Header->OptionalHeader.SizeOfImage);
	if (pImageBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("分配ImageBuffer失败.\r\n");
		}
		goto RET;
	}
	//初始化pImageBuffer
	memset(pImageBuffer, 0x0, pPE_NT_Header->OptionalHeader.SizeOfImage);
	//拉伸EXE
	blStatus = fnFileBuffer_Convert_ImageBuffer(pFileBuffer, pImageBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("转换ImageBuffer失败.\r\n");
		}
		goto RET;
	}
	//得到当前指令的RVA地址
	blStatus = fnFOA_Convert_RVA((unsigned int)pZeroAddress + 8, &unCodeCurrentAddress, pFileBuffer, pImageBuffer);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("写入fnFOA_Convert_RVA失败.\r\n");
		}
		goto RET;
	}
	//计算E8指令需要跳转的地址
	blStatus = fnCalculate_AddressOf_E8_E9(
		unCodeCurrentAddress - (unsigned int)pImageBuffer + pPE_NT_Header->OptionalHeader.ImageBase, 
		0x77D507EA, 
		&unE8Address);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("写入计算E8指令地址失败.\r\n");
		}
		goto RET;
	}
	//把E8地址写入ShellCode中
	unCodeCurrentAddress++;
	*(int*)unCodeCurrentAddress = unE8Address;
	//步进到下E9指令的开头地址
	unCodeCurrentAddress = unCodeCurrentAddress + sizeof(int);



	//计算e9指令需要跳转的地址
	blStatus = fnCalculate_AddressOf_E8_E9(
		unCodeCurrentAddress - (unsigned int)pImageBuffer + pPE_NT_Header->OptionalHeader.ImageBase, 
		pPE_NT_Header->OptionalHeader.AddressOfEntryPoint + pPE_NT_Header->OptionalHeader.ImageBase, 
		&unE9Address);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("写入计算E8指令地址失败.\r\n");
		}
		goto RET;
	}
	
	//把E9地址写入ShellCode中
	unCodeCurrentAddress++;
	*(int*)unCodeCurrentAddress = unE9Address;
	unCodeCurrentAddress = unCodeCurrentAddress + sizeof(int);


	//计算OEP
	blStatus = fnCalculate_New_AddressOfEntryPoint(
		pFileBuffer, 
		(unsigned int)pZeroAddress,
		&unNewOEP);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("计算新OEP失败.\r\n");
		}
		goto RET;
	}
	//获取ImageBase的Nt头
	blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(pImageBuffer, &pPE_NT_Header);

	//修改OEP
	pPE_NT_Header->OptionalHeader.AddressOfEntryPoint = unNewOEP;

	//压缩EXE
	blStatus = fnImageBuffer_Convert_FileBuffer(pImageBuffer, pFileBuffer);

	//写入磁盘
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

