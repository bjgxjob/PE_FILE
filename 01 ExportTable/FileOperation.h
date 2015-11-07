// FileOperation.h: interface for the CFileOperation class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_FILEOPERATION_H__5BF6E04F_C932_48AB_A1AC_313B13B88854__INCLUDED_)
#define AFX_FILEOPERATION_H__5BF6E04F_C932_48AB_A1AC_313B13B88854__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <MALLOC.H>
#include <MEMORY.H>
#include <WINDOWS.H>



//从硬盘中读取文件到内存
bool fnReadFileToMemory(char* szPath, //读取文件的目录
						void* pReturnBuffer, //读出来文件存放的内存指针。
						unsigned int* punFileSize //读取后的字节长度
						);

//从内存中写入文件到硬盘
bool fnWriteFileFromMemory(char* szPath, //写入文件的路径
						   void* pBuffer, //需要写入文件的缓冲区路径
						   unsigned int unFileSize //写入文件的大小
						   );

//***********************************
//函数名：bool fnReadFile(char* szPath, LPVOID lpFileBuffer, unsigned* punSizeOfFileBuffer)
//功能：根据szPath读取文件到指定的缓冲区，缓冲区不用提前分配内存。
//参数1：IN char* szPath
//参数1说明：读取文件的路径
//参数2：IN OUT LPVOID lpFileBuffer
//参数2说明: 缓冲区的地址，可以不用提前分配空间。
//参数3：IN unsigned* punSizeOfFileBuffer
//参数3说明：缓冲区的大小
//返回值：如果成功，返回TRUE，如果失败，返回FALSE
//***********************************

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

bool fnReadFile(IN char* szPath, IN OUT LPVOID* plpFileBuffer, IN OUT unsigned* punSizeOfFileBuffer);

#endif // !defined(AFX_FILEOPERATION_H__5BF6E04F_C932_48AB_A1AC_313B13B88854__INCLUDED_)
