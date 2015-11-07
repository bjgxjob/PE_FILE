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

//***********************************
//��������bool fnReadFile(char* szPath, LPVOID lpFileBuffer, unsigned* punSizeOfFileBuffer)
//���ܣ�����szPath��ȡ�ļ���ָ���Ļ�������������������ǰ�����ڴ档
//����1��IN char* szPath
//����1˵������ȡ�ļ���·��
//����2��IN OUT LPVOID lpFileBuffer
//����2˵��: �������ĵ�ַ�����Բ�����ǰ����ռ䡣
//����3��IN unsigned* punSizeOfFileBuffer
//����3˵�����������Ĵ�С
//����ֵ������ɹ�������TRUE�����ʧ�ܣ�����FALSE
//***********************************

//***********************************
//��������bool fnReadFile(char* szPath, LPVOID lpFileBuffer, unsigned* punSizeOfFileBuffer)
//���ܣ�����szPath��ȡ�ļ���ָ���Ļ�����������������Ҫ��ǰ����ռ䡣
//����1��IN char* szPath
//����1˵������ȡ�ļ���·��
//����2��LPVOID* plpFileBuffer
//����2˵��: �������ĵ�ַ��ָ�룬���Բ�����ǰ����ռ䡣
//����3��IN OUT unsigned* punSizeOfFileBuffer
//����3˵�����������Ĵ�С
//����ֵ������ɹ�������TRUE�����ʧ�ܣ�����FALSE
//***********************************

bool fnReadFile(IN char* szPath, IN OUT LPVOID* plpFileBuffer, IN OUT unsigned* punSizeOfFileBuffer);

#endif // !defined(AFX_FILEOPERATION_H__5BF6E04F_C932_48AB_A1AC_313B13B88854__INCLUDED_)
