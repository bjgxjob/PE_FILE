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

class CFileOperation  
{
public:
	CFileOperation();
	virtual ~CFileOperation();

};

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

#endif // !defined(AFX_FILEOPERATION_H__5BF6E04F_C932_48AB_A1AC_313B13B88854__INCLUDED_)
