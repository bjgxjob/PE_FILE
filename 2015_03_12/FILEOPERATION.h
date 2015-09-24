// FILEOPERATION.h: interface for the CFILEOPERATION class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_FILEOPERATION_H__4A1D7CBE_E4D6_48E8_A883_2F2D369D790F__INCLUDED_)
#define AFX_FILEOPERATION_H__4A1D7CBE_E4D6_48E8_A883_2F2D369D790F__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#include <MALLOC.H>
#include <MEMORY.H>



class CFILEOPERATION  
{
public:
	CFILEOPERATION();
	virtual ~CFILEOPERATION();

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

#endif // !defined(AFX_FILEOPERATION_H__4A1D7CBE_E4D6_48E8_A883_2F2D369D790F__INCLUDED_)
