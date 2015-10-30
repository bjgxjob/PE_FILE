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

//��Ӳ���ж�ȡ�ļ����ڴ�
bool fnReadFileToMemory(char* szPath, //��ȡ�ļ���Ŀ¼
						void* pReturnBuffer, //�������ļ���ŵ��ڴ�ָ�롣
						unsigned int* punFileSize //��ȡ����ֽڳ���
						);

//���ڴ���д���ļ���Ӳ��
bool fnWriteFileFromMemory(char* szPath, //д���ļ���·��
						   void* pBuffer, //��Ҫд���ļ��Ļ�����·��
						   unsigned int unFileSize //д���ļ��Ĵ�С
						   );

#endif // !defined(AFX_FILEOPERATION_H__5BF6E04F_C932_48AB_A1AC_313B13B88854__INCLUDED_)
