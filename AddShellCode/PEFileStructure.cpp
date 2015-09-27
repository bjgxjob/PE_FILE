// PEFileStructure.cpp: implementation of the CPEFileStructure class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "PEFileStructure.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CPEFileStructure::CPEFileStructure()
{
	
}

CPEFileStructure::~CPEFileStructure()
{
	
}

//�ж��Ƿ�����Ч��Windows��ִ���ļ�
bool fnBlIsVaildWindowsPEFile(PE_DOS_HEADER* pPE_DOS_HEADER)
{
	//�жϴ����ָ���Ƿ�Ϊ��
	if (pPE_DOS_HEADER == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_DOS_HEADER Ϊ��.\r\n");
		}
		goto F;
	}
	
	//���Ҫ���ַ����жϵĻ���Ҫд'ZM'����Ϊ���ڴ�����С�˴洢��
	if (pPE_DOS_HEADER->e_magic != 0x5a4d)
	{
		if (__DEBUG)
		{
			printf("������Ч��Windows Executive �ļ���\r\n");
		}
		
		goto F;
	}
	else
	{
		if (__DEBUG)
		{
			printf("����Ч��Windows Executive �ļ���\r\n");
		}
		goto T;
		
	}
T:
	return TRUE;
F:
	return FALSE;
};

//��ӡPE_DOS_HEADER��Ϣ
void fnPrintPE_DOS_HEADER_Info(PE_DOS_HEADER* pPE_DOS_HEADER)
{
	int nCount = 0;
	if (pPE_DOS_HEADER == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_DOS_HEADER Ϊ��.\r\n");
		}
		goto RET;
		
	}
	printf("��ʼ��ӡPE DOS Header:\r\n");
	//e_magic
	printf("e_magic:%x\r\n", pPE_DOS_HEADER->e_magic);
	//e_cblp
	printf("e_cblp:%x\r\n", pPE_DOS_HEADER->e_cblp);
	//e_cp
	printf("e_cp:%x\r\n", pPE_DOS_HEADER->e_cp);
	//e_crlc
	printf("e_crlc:%x\r\n", pPE_DOS_HEADER->e_crlc);
	//e_cparhdr
	printf("e_cparhdr:%x\r\n", pPE_DOS_HEADER->e_cparhdr);
	//e_minalloc          
	printf("e_minalloc:%x\r\n", pPE_DOS_HEADER->e_minalloc);
	//e_maxalloc                 
	printf("e_maxalloc:%x\r\n", pPE_DOS_HEADER->e_maxalloc);
	//e_ss
	printf("e_ss:%x\r\n", pPE_DOS_HEADER->e_ss);
	//e_sp
	printf("e_sp:%x\r\n", pPE_DOS_HEADER->e_sp);
	//e_csum
	printf("e_csum:%x\r\n", pPE_DOS_HEADER->e_csum);
	//e_ip
	printf("e_ip:%x\r\n", pPE_DOS_HEADER->e_ip);
	//e_cs
	printf("e_cs:%x\r\n", pPE_DOS_HEADER->e_cs);
	//e_lfarlc
	printf("e_lfarlc:%x\r\n", pPE_DOS_HEADER->e_lfarlc);
	//e_ovno;
	printf("e_ovno:%x\r\n", pPE_DOS_HEADER->e_ovno);
	//e_res[4]
	printf("e_res[4]:%x %x %x %x", pPE_DOS_HEADER->e_res[0], pPE_DOS_HEADER->e_res[1],
		pPE_DOS_HEADER->e_res[2], pPE_DOS_HEADER->e_res[3]);
	//e_oemid;
	printf("e_oemid:%x\r\n", pPE_DOS_HEADER->e_oemid);
	//e_oeminfo;
	printf("e_oeminfo:%x\r\n", pPE_DOS_HEADER->e_oeminfo);
	//e_res2[10];
	printf("e_res2[10]:\r\n");
	for (nCount = 0; nCount < 10; nCount++)
	{
		printf("%x ", pPE_DOS_HEADER->e_res2[nCount]);
	}
	printf("\r\n");
	//e_lfanew;  
	printf("e_lfanew:%x\r\n", pPE_DOS_HEADER->e_lfanew);
	
	//��ӡ���
	printf("PE_DOS_HEADER��ӡ���.\r\n");
	
RET:
	return;
	
}

//�ж��Ƿ�����Ч��NTͷ��ַ
bool fnBlIsVaildNTHeaderAddress(PE_NT_HEADER* pPE_NT_HEADER)
{
	//�жϴ����ָ���Ƿ�Ϊ��
	if (pPE_NT_HEADER == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_NT_HEADER Ϊ��.\r\n");
		}
		goto F;
	}
	//������ַ�ת�����������ж�
	if (pPE_NT_HEADER->Signature != 'EP')
	{
		if (__DEBUG)
		{
			printf("������Ч��NTͷ��ַ�����߲�����Ч��PE�ļ���\r\n");
		}
		goto F;
	}
	else
	{
		if (__DEBUG)
		{
			printf("����Ч��NTͷ��ַ��\r\n");
		}
		goto T;
	}
F:
	return FALSE;
T:
	return TRUE;
}

//��ӡPE_NT_HEADER��Ϣ
void fnPrintPE_NT_HEADER_Info(PE_NT_HEADER* pPE_NT_HEADER)
{
	//�жϴ����ָ���Ƿ�Ϊ��
	if (pPE_NT_HEADER == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_NT_HEADERΪ��.\r\n");
		}
		goto RET;
		
	}
	//��ʼ��ӡPE_NT_Header
	printf("��ʼ��ӡPE_NT_Header\r\n");
	//Signature
	printf("Signature:%x\r\n", pPE_NT_HEADER->Signature);
	//PE_FILE_HEADER����Ϣ��PE_OPTIONAL_HEADER����Ϣ�����������д�ӡ��
	printf("PE_FILE_HEADER����Ϣ��PE_OPTIONAL_HEADER����Ϣ�����������д�ӡ��\r\n");
	//��ӡ����
	printf("PE_NT_Header��ӡ������\r\n");
RET:
	return;
}

//��ӡPE_FILE_HEADER��Ϣ
void fnPrintPE_FILE_HEADER_Info(PE_FILE_HEADER* pPE_FILE_HEADER)
{
	//�жϴ����ָ���Ƿ�Ϊ��
	if (pPE_FILE_HEADER == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_FILE_HEADERΪ��.\r\n");
		}
		goto RET;
	}
	//��ʼ��ӡPE_FILE_HEADER����Ϣ
	printf("��ʼ��ӡPE_FILE_HEADER����Ϣ��\r\n");
	//Machine
	printf("Machine:%x\r\n", pPE_FILE_HEADER->Machine);
	//NumberOfSections
	printf("NumberOfSections:%x\r\n", pPE_FILE_HEADER->NumberOfSections);
	//TimeDateStamp
	printf("TimeDateStamp:%x\r\n", pPE_FILE_HEADER->TimeDateStamp);
	//PointerToSymbolTable
	printf("PointerToSymbolTable:%x\r\n", pPE_FILE_HEADER->PointerToSymbolTable);
	//NumberOfSymbols
	printf("NumberOfSymbols:%x\r\n", pPE_FILE_HEADER->NumberOfSymbols);
	//SizeOfOptionalHeader
	printf("SizeOfOptionalHeader:%x\r\n", pPE_FILE_HEADER->SizeOfOptionalHeader);
	//Characteristics
	printf("Characteristics:%x\r\n", pPE_FILE_HEADER->Characteristics);
	//��ӡ���
	printf("PE_FILE_HEADER��Ϣ��ӡ��ɡ�\r\n");
	
	
RET:
	return;
}

//��ӡPE_OPTIONAL_HEADER��Ϣ
void fnPrintfPE_OPTIONAL_HEADER_Info(PE_OPTIONAL_HEADER* pPE_OPTIONAL_HEADER)
{
	if (pPE_OPTIONAL_HEADER == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_OPTIONAL_HEADERΪ��\r\n");
		}
		goto RET;
	}
	
	printf("��ʼ��ӡPE_OPTIONAL_HEADER����Ϣ��\r\n");
	//Magic
	printf("Magic:%x\r\n", pPE_OPTIONAL_HEADER->Magic);
	if (pPE_OPTIONAL_HEADER->Magic == 0x10B)
	{
		printf("���ļ���32Bit PE�ļ�.\r\n");
	}
	if (pPE_OPTIONAL_HEADER->Magic == 0x20B)
	{
		printf("���ļ���64Bit PE�ļ�.\r\n");
	}
	if ((pPE_OPTIONAL_HEADER->Magic != 0x10B) && (pPE_OPTIONAL_HEADER->Magic != 0x20B))
	{
		printf("���ļ��Ȳ���32Bit PE�ļ�Ҳ����64Bit PE�ļ�\r\n");
	}
	//MajorLinkerVersion
	printf("MajorLinkerVersion:%x\r\n", pPE_OPTIONAL_HEADER->MajorLinkerVersion);
	//MinorLinkerVersion
	printf("MinorLinkerVersion:%x\r\n", pPE_OPTIONAL_HEADER->MinorLinkerVersion);
	//SizeOfCode
	printf("SizeOfCode:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfCode);
	//SizeOfInitializedData
	printf("SizeOfInitializedData:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfInitializedData);
	//SizeOfUninitializedData
	printf("SizeOfUninitializedData:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfUninitializedData);
	//AddressOfEntryPoint
	printf("AddressOfEntryPoint:%x\r\n", pPE_OPTIONAL_HEADER->AddressOfEntryPoint);
	//BaseOfCode
	printf("BaseOfCode:%x\r\n", pPE_OPTIONAL_HEADER->BaseOfCode);
	//BaseOfData
	printf("BaseOfData:%x\r\n", pPE_OPTIONAL_HEADER->BaseOfData);
	//ImageBase
	printf("ImageBase:%x\r\n", pPE_OPTIONAL_HEADER->ImageBase);
	//SectionAlignment
	printf("SectionAlignment:%x\r\n", pPE_OPTIONAL_HEADER->SectionAlignment);
	//FileAlignment
	printf("FileAlignment:%x\r\n", pPE_OPTIONAL_HEADER->FileAlignment);
	//MajorOperatingSystemVersion
	printf("MajorOperatingSystemVersion:%x\r\n", pPE_OPTIONAL_HEADER->MajorOperatingSystemVersion);
	//MinorOperatingSystemVersion
	printf("MinorOperatingSystemVersion:%x\r\n", pPE_OPTIONAL_HEADER->MinorOperatingSystemVersion);
	//MajorImageVersion
	printf("MajorImageVersion:%x\r\n", pPE_OPTIONAL_HEADER->MajorImageVersion);
	//MinorImageVersion
	printf("MinorImageVersion:%x\r\n", pPE_OPTIONAL_HEADER->MinorImageVersion);
	//MajorSubsystemVersion
	printf("MajorSubsystemVersion:%x\r\n", pPE_OPTIONAL_HEADER->MajorSubsystemVersion);
	//MinorSubsystemVersion
	printf("MinorSubsystemVersion:%x\r\n", pPE_OPTIONAL_HEADER->MinorSubsystemVersion);
	//Win32VersionValue
	printf("Win32VersionValue:%x\r\n", pPE_OPTIONAL_HEADER->Win32VersionValue);
	//SizeOfImage
	printf("SizeOfImage:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfImage);
	//SizeOfHeaders
	printf("SizeOfHeaders:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfHeaders);
	//CheckSum
	printf("CheckSum:%x\r\n", pPE_OPTIONAL_HEADER->CheckSum);
	//Subsystem
	printf("Subsystem:%x\r\n", pPE_OPTIONAL_HEADER->Subsystem);
	//DllCharacteristics
	printf("DllCharacteristics:%x\r\n", pPE_OPTIONAL_HEADER->DllCharacteristics);
	//SizeOfStackReserve
	printf("SizeOfStackReserve:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfStackReserve);
	//SizeOfStackCommit
	printf("SizeOfStackCommit:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfStackCommit);
	//SizeOfHeapReserve
	printf("SizeOfHeapReserve:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfHeapReserve);
	//SizeOfHeapCommit
	printf("SizeOfHeapCommit:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfHeapCommit);
	//LoaderFlags
	printf("LoaderFlags:%x\r\n", pPE_OPTIONAL_HEADER->LoaderFlags);
	//NumberOfRvaAndSizes
	printf("NumberOfRvaAndSizes:%x\r\n", pPE_OPTIONAL_HEADER->NumberOfRvaAndSizes);
	
RET:
	return;
}

//������ӡPE_SECTION_HEADER��Ϣ
void fnPrintPE_SECTION_HEADER_Info(PE_IMAGE_SECTION_HEADER* pPE_IMAGE_SECTION_HEADER, int nNumberOfSection)
{
	char szSectionName[9] = {0};
	int i = 0;
	int nTest = sizeof(PE_IMAGE_SECTION_HEADER);
	if (pPE_IMAGE_SECTION_HEADER == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_IMAGE_SECTION_HEADERΪNULL.\r\n");
		}
		goto RET;
	}
	printf("**************************��ʼ��ӡPE_IMAGE_SECTION_HEADER******************\r\n");
	
	for (i = 0; i < nNumberOfSection; pPE_IMAGE_SECTION_HEADER = pPE_IMAGE_SECTION_HEADER++, i++)
	{
		printf("************SectionHeader %x*************\r\n", i + 1);
		memset((void*)szSectionName, 0x0, sizeof(szSectionName));
		//Name
		memcpy(szSectionName, pPE_IMAGE_SECTION_HEADER->Name, sizeof(pPE_IMAGE_SECTION_HEADER->Name));
		printf("Name:%s\r\n", szSectionName);
		//Misc
		printf("Misc:%x\r\n", pPE_IMAGE_SECTION_HEADER->Misc);
		//VirtualAddress
		printf("VirtualAddress:%x\r\n", pPE_IMAGE_SECTION_HEADER->VirtualAddress);
		//SizeOfRawData;
		printf("SizeOfRawData:%x\r\n", pPE_IMAGE_SECTION_HEADER->SizeOfRawData);
		//PointerToRawData;
		printf("PointerToRawData:%x\r\n", pPE_IMAGE_SECTION_HEADER->PointerToRawData);
		//PointerToRelocations;
		printf("PointerToRelocations:%x\r\n", pPE_IMAGE_SECTION_HEADER->PointerToRelocations);
		//PointerToLinenumbers;
		printf("PointerToLinenumbers:%x\r\n", pPE_IMAGE_SECTION_HEADER->PointerToLinenumbers);
		//NumberOfRelocations;
		printf("NumberOfRelocations:%x\r\n", pPE_IMAGE_SECTION_HEADER->NumberOfRelocations);
		//NumberOfLinenumbers;
		printf("NumberOfLinenumbers:%x\r\n", pPE_IMAGE_SECTION_HEADER->NumberOfLinenumbers);
		//Characteristics;
		printf("Characteristics:%x\r\n", pPE_IMAGE_SECTION_HEADER->Characteristics);
		
	}
	printf("**********************PE_IMAGE_SECTION_HEADER��ӡ����***************************\r\n");
	
RET:
	return;
}

//***********************************
//��������fnGetPE_Image_Section_Header_Structure_Array
//���ܣ���ȡ����ṹ���飺
//����1��PE_NT_HEADER* pPE_NT_Header
//����1˵�����������ݣ�ֵ������ΪNULL
//����2��PE_IMAGE_SECTION_HEADER** pPE_Image_Section_Header 
//����2˵������������
//����3��unsigned int* pNumberOfSections
//����3˵������������
//����ֵ��bool����������ɹ�����TRUE�����ʧ�ܷ���FALSE
//***********************************
bool fnGetPE_Image_Section_Header_Structure_Array(PE_NT_HEADER* pPE_NT_Header, 
												  PE_IMAGE_SECTION_HEADER** pPE_Image_Section_Header, 
												  unsigned int* pNumberOfSections
												  )
{
	if (pPE_NT_Header == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_NT_HeaderΪ�ա�\r\n");
		}
		goto F;
	}
	if (pNumberOfSections == NULL)
	{
		if (__DEBUG)
		{
			printf("pNumberOfSectionsΪ�ա�\r\n");
		}
		goto F;
	}
	//��PE_NT_Header�л�ȡNumberOfSections
	(*pNumberOfSections) = pPE_NT_Header->FileHeader.NumberOfSections;
	if (*pNumberOfSections == 0)
	{
		if (__DEBUG)
		{
			printf("*pNumberOfSections��ֵΪ0��������NTͷָ�������߲�����Ч��PE�ļ���\r\n");
		}
		goto F;
	}
	//��ȡPE_IMAGE_SECTION_HEADER��ַ
	*pPE_Image_Section_Header = (PE_IMAGE_SECTION_HEADER *)((unsigned int)&pPE_NT_Header->OptionalHeader + pPE_NT_Header->FileHeader.SizeOfOptionalHeader);
	if (pPE_Image_Section_Header == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_Image_Section_Header��ȡʧ�ܡ�\r\n");
		}
		goto F;
	}
	
	return TRUE;
F:
	return FALSE;
}

//***********************************
//��������fnFileBuffer_Convert_ImageBuffer
//���ܣ�ת��FileBuffer��ImageBuffer, ���칦��
//����1��void* pFileBuffer
//����1˵��������ֵ����ת����FileBuffer�ĵ�ַ
//����2��void* pImageBuffer
//����2˵��������ֵ��ת�����ImageBuffer�ĵ�ַ
//***********************************
bool fnFileBuffer_Convert_ImageBuffer(void* pFileBuffer, 
									  void* pImageBuffer)
{
	//PE_NT_HEADERָ��
	PE_NT_HEADER* pPE_NT_Header = NULL;
	//PE_DOS_HEADERָ��
	PE_DOS_HEADER* pPE_DOS_Header = NULL;
	//PE_Section_Headerָ��
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header = NULL;
	//����������
	unsigned int unNumberOfSections = 0;
	//ѭ������
	unsigned int unCount = 0;
	//״̬��
	bool blStatus = FALSE;
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pFileBufferΪ�ա�\r\n");
		}
		goto F;
	}
	if (pImageBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pImageBuffer��ֵΪNULL��\r\n");
		}
		goto F;
	}
	//��ȡPE_DOS_HEADER
	blStatus =  fnGet_PE_DOS_Header_Address(pFileBuffer, &pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡfnGetPE_DOS_HeaderAddressʧ�ܡ�\r\n");
		}
		goto F;
	}
	//�ж��Ƿ�Ϊ��Ч��WindowsPE�ļ�
	blStatus = fnBlIsVaildWindowsPEFile(pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("������Ч��PE�ļ���\r\n");
		}
		goto F;
	}
	//��ȡPE_NT_HEADER�ĵ�ַ
	blStatus = fnGet_PE_NT_Header_Address(pPE_DOS_Header, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡpPE_NT_Headerʧ�ܡ�\r\n");
		}
		goto F;
	}
	//�ж��Ƿ�Ϊ��Ч��NTͷ��ַ
	blStatus = fnBlIsVaildNTHeaderAddress(pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("������Ч��PE_NT_HEADER��ַ��\r\n");
		}
		goto F;
	}
	//��ȡ�ڱ�����
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &unNumberOfSections);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡpPE_Image_Section_Headerʧ�ܡ�\r\n");
		}
		goto F;
	}
	
	//����PE_DOS_HEADER, PE_NT_HEADER, PE_SECTION_HEADER��ImageBuffer
	memcpy(pImageBuffer, pFileBuffer, pPE_NT_Header->OptionalHeader.SizeOfHeaders * sizeof(char));
	
	
	
	//ѭ����ֵ����
	for (unCount = 0; unCount < unNumberOfSections; unCount++)
	{
		memcpy((void *)((unsigned int)pImageBuffer + pPE_Image_Section_Header[unCount].VirtualAddress),
			(void *)((unsigned int)pFileBuffer + pPE_Image_Section_Header[unCount].PointerToRawData),
			pPE_Image_Section_Header[unCount].SizeOfRawData * sizeof(char));
	}
	
	return TRUE;
	
	
	
F:
	return FALSE;
}


//***********************************
//��������fnGetPE_DOS_HeaderAddress
//���ܣ���ImageBuffer����FileBuffer��ʼ�����PE_DOS_Header�ĵ�ַ
//����1��const void* PE_Begin_Address
//����1˵��������ֵ��PE��ʼ�ĵ�ַ
//����2��PE_DOS_HEADER** ppPE_DOS_Header
//����2˵��������ֵ��PE_DOS_Header�ĵ�ַ
//����ֵ�������ȡ�ɹ�������TRUE,���ʧ�ܣ�����FALSE
//***********************************
bool fnGet_PE_DOS_Header_Address(const void* PE_Begin_Address, PE_DOS_HEADER** ppPE_DOS_Header)
{
	if (PE_Begin_Address == NULL)
	{
		if (__DEBUG)
		{
			printf("PE_Begin_AddressΪ�ա�\r\n");
		}
		goto F;
	}
	
	//���PE_DOS_HEADERָ��
	*ppPE_DOS_Header = (PE_DOS_HEADER *)PE_Begin_Address;
	if (*ppPE_DOS_Header == NULL)
	{
		if (__DEBUG)
		{
			printf("��ȡPE_DOS_Headerʧ�ܡ�\r\n");
		}
		goto F;
	}
	return TRUE;
F:
	return FALSE;
}

//***********************************
//��������fnGet_PE_NT_Header_Address
//���ܣ���ȡPE�ļ���PE_NT_HEADER�ĵ�ַ
//����1��const PE_DOS_HEADER* pPE_DOS_Header
//����1˵��������ֵ������PE_DOS_Header�ĵ�ַ
//����2��PE_NT_HEADER** ppPE_NT_Header
//����2˵��������ֵ������PE_NT_Header�ĵ�ַ
//����ֵ�������ȡ�ɹ�������TRUE�������ȡʧ�ܣ�����FALSE
//***********************************
bool fnGet_PE_NT_Header_Address(const PE_DOS_HEADER* pPE_DOS_Header, PE_NT_HEADER** ppPE_NT_Header)
{
	if (pPE_DOS_Header == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_DOS_HeaderΪ�ա�\r\n");
		}
		goto F;
	}
	//�õ�PE_NT_HEADERָ��
	*ppPE_NT_Header = (PE_NT_HEADER *)((int)pPE_DOS_Header + pPE_DOS_Header->e_lfanew);
	return TRUE;
	
F:
	return FALSE;
	
}


//***********************************
//��������fnImageBuffer_Convert_FileBuffer
//���ܣ�ת��ImageBuffer��FileBuffer, ѹ������
//����1��void* pImageBuffer
//����1˵��������ֵ����ת����ImageBuffer�ĵ�ַ
//����2��void* pFileBuffer
//����2˵��������ֵ��ת�����FileBuffer�ĵ�ַ
//***********************************
bool fnImageBuffer_Convert_FileBuffer(void* pImageBuffer,
									  void* pFileBuffer)
{
	//PE_NT_HEADERָ��
	PE_NT_HEADER* pPE_NT_Header = NULL;
	//PE_DOS_HEADERָ��
	PE_DOS_HEADER* pPE_DOS_Header = NULL;
	//PE_Section_Headerָ��
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header = NULL;
	//����������
	unsigned int unNumberOfSections = 0;
	//ѭ������
	unsigned int unCount = 0;
	//״̬��
	bool blStatus = FALSE;
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pFileBufferΪ�ա�\r\n");
		}
		goto F;
	}
	if (pImageBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pImageBuffer��ֵΪNULL��\r\n");
		}
		goto F;
	}
	//��ȡPE_DOS_HEADER
	blStatus =  fnGet_PE_DOS_Header_Address(pImageBuffer, &pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡfnGetPE_DOS_HeaderAddressʧ�ܡ�\r\n");
		}
		goto F;
	}
	//�ж��Ƿ�Ϊ��Ч��WindowsPE�ļ�
	blStatus = fnBlIsVaildWindowsPEFile(pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("������Ч��PE�ļ���\r\n");
		}
		goto F;
	}
	//��ȡPE_NT_HEADER�ĵ�ַ
	blStatus = fnGet_PE_NT_Header_Address(pPE_DOS_Header, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡpPE_NT_Headerʧ�ܡ�\r\n");
		}
		goto F;
	}
	//�ж��Ƿ�Ϊ��Ч��NTͷ��ַ
	blStatus = fnBlIsVaildNTHeaderAddress(pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("������Ч��PE_NT_HEADER��ַ��\r\n");
		}
		goto F;
	}
	//��ȡ�ڱ�����
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &unNumberOfSections);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡpPE_Image_Section_Headerʧ�ܡ�\r\n");
		}
		goto F;
	}
	
	//����PE_DOS_HEADER, PE_NT_HEADER, PE_SECTION_HEADER��ImageBuffer
	memcpy(pFileBuffer, pImageBuffer, pPE_NT_Header->OptionalHeader.SizeOfHeaders * sizeof(char));
	
	
	
	//ѭ����ֵ����
	for (unCount = 0; unCount < unNumberOfSections; unCount++)
	{
		memcpy((void *)((unsigned int)pFileBuffer + pPE_Image_Section_Header[unCount].PointerToRawData), 
			(void *)((unsigned int)pImageBuffer + pPE_Image_Section_Header[unCount].VirtualAddress),
			pPE_Image_Section_Header[unCount].SizeOfRawData * sizeof(char));
	}
	
	return TRUE;
	
	
	
F:
	return FALSE;
}

//***********************************
//��������fnRVA_Convert_FOA
//���ܣ���RVAת����FOA
//����1��unsigned int unRAV
//����1˵��������ֵ����Ҫת���ĵ�ַ
//����2��unsigned* unFOA
//����2˵��������ֵ��ת����ĵ�ֵַ��ָ��
//����3��const void* pPE_Begin_Address
//����3˵��������ֵ��PE�ļ����ڴ��п�ʼ�ĵط�
//����ֵ�����ת�ɹ�������TRUE��ת��ʧ�ܣ�����FALSE
//***********************************
bool fnRVA_Convert_FOA(unsigned int unRAV, 
					   unsigned* unFOA, 
					   const void* pPE_Begin_Address)
{
	//PE_NT_HEADERָ��
	PE_NT_HEADER* pPE_NT_Header = NULL;
	//PE_DOS_HEADERָ��
	PE_DOS_HEADER* pPE_DOS_Header = NULL;
	//PE_Section_Headerָ��
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header = NULL;
	//����������
	unsigned int unNumberOfSections = 0;
	//��ת���ĵ�ַ���ڽڵı��
	unsigned int unNumberOfCurrentSection = 0;
	//�������ڽ��е�ƫ����
	unsigned int unDataOffsetInSection = 0;
	//״̬��
	bool blStatus = FALSE;
	
	if (unFOA == NULL)
	{
		if (__DEBUG)
		{
			printf("unFOAΪ0��\r\n");
		}
		goto F;
	}
	if (pPE_Begin_Address == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_Begin_AddressΪNULL.\r\n");
		}
		goto F;
	}
	//��ȡPE_DOS_HEADER
	blStatus =  fnGet_PE_DOS_Header_Address(pPE_Begin_Address, &pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡfnGetPE_DOS_HeaderAddressʧ�ܡ�\r\n");
		}
		goto F;
	}
	//�ж��Ƿ�Ϊ��Ч��WindowsPE�ļ�
	blStatus = fnBlIsVaildWindowsPEFile(pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("������Ч��PE�ļ���\r\n");
		}
		goto F;
	}
	//��ȡPE_NT_HEADER�ĵ�ַ
	blStatus = fnGet_PE_NT_Header_Address(pPE_DOS_Header, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡpPE_NT_Headerʧ�ܡ�\r\n");
		}
		goto F;
	}
	//�ж��Ƿ�Ϊ��Ч��NTͷ��ַ
	blStatus = fnBlIsVaildNTHeaderAddress(pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("������Ч��PE_NT_HEADER��ַ��\r\n");
		}
		goto F;
	}
	//��ȡ�ڱ�����
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &unNumberOfSections);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡpPE_Image_Section_Headerʧ�ܡ�\r\n");
		}
		goto F;
	}
	//������ͷ���ҳ���Ҫת���ĵ�ַ���ڵĽ�ͷ
	for (unNumberOfCurrentSection = 0; unNumberOfCurrentSection < unNumberOfSections; unNumberOfCurrentSection++)
	{
		//����ж�����������ʹ����������PEͷ�У����ں���Ľ����С�
		if ((unRAV - (unsigned int)pPE_Begin_Address) < pPE_NT_Header->OptionalHeader.SizeOfHeaders)
		{
			*unFOA = unRAV - (unsigned int)pPE_Begin_Address;
			break;
		}
		//�ж����ֵ�Ƿ�ȵ�ǰ�ڵ���ʼ��ַ��
		if (unRAV >= (pPE_Image_Section_Header[unNumberOfCurrentSection].VirtualAddress + (unsigned int)pPE_Begin_Address))
		{
			//�ж��Ƿ�Ϊ���һ����
			if (unNumberOfCurrentSection < unNumberOfSections - 1)
			{
				//�������һ���ڣ������ж��Ƿ����һ���ڵĿ�ʼ��ַС
				if (unRAV < (pPE_Image_Section_Header[unNumberOfCurrentSection + 1].VirtualAddress + (unsigned int)pPE_Begin_Address))
				{
					//�����ڽ��е�ƫ��
					unDataOffsetInSection = unRAV - (unsigned int)pPE_Begin_Address - pPE_Image_Section_Header[unNumberOfCurrentSection].VirtualAddress;
					//�ж��ڽ��е�ƫ���Ƿ񳬹���FileImage�ĽڵĴ�С
					if (unDataOffsetInSection > pPE_Image_Section_Header[unNumberOfCurrentSection].SizeOfRawData)
					{
						//������ھͱ�����Ϊһ���Ҳ�����Ӧ�ĵ�ַ���ڱ�����������ļ��е�δ��ʼ���������ڴ������б���ʼ����
						if (__DEBUG)
						{
							printf("�ļ�����ʱRVA�ڵڣ�%x���У����ǲ����ҵ���Ӧ��FOA����Ϊ�����ַ�������к󾭹����죬��FileImage��û�ж�Ӧ������.\r\n", unNumberOfCurrentSection + 1);
						}
						*unFOA = 0;
						goto F;
					}
					*unFOA = unDataOffsetInSection + pPE_Image_Section_Header[unNumberOfCurrentSection].PointerToRawData;
					break;
				}
			}
			else
			{
				//��������һ���ڣ����ж��Ƿ������һ������
				if (unRAV <= (unsigned int)pPE_Begin_Address + pPE_NT_Header->OptionalHeader.SizeOfImage)
				{
					unDataOffsetInSection = unRAV - (unsigned int)pPE_Begin_Address - pPE_Image_Section_Header[unNumberOfCurrentSection].VirtualAddress;
					//�ж��ڽ��е�ƫ���Ƿ񳬹���FileImage�ĽڵĴ�С
					if (unDataOffsetInSection > pPE_Image_Section_Header[unNumberOfCurrentSection].SizeOfRawData)
					{
						//������ھͱ�����Ϊһ���Ҳ�����Ӧ�ĵ�ַ���ڱ�����������ļ��е�δ��ʼ���������ڴ������б���ʼ����
						if (__DEBUG)
						{
							printf("�ļ�����ʱRVA�ڵڣ�%x���У����ǲ����ҵ���Ӧ��FOA����Ϊ�����ַ�������к󾭹����죬��FileImage��û�ж�Ӧ������.\r\n", unNumberOfCurrentSection + 1);
						}
						*unFOA = 0;
						goto F;
					}
					*unFOA = unDataOffsetInSection + pPE_Image_Section_Header[unNumberOfCurrentSection].PointerToRawData;
					break;
					
				}
				else
				{
					//����ͱ����������PE�ļ��С�
					if (__DEBUG)
					{
						printf("RVA���ڱ�PE�ļ��С�\r\n");
					}
					*unFOA = 0;
					goto F;
					
				}
			}
		}
		
	}
	
	
	
	
	return TRUE;
F:
	return FALSE;
	
}

//***********************************
//��������fnFOA_Convert_RVA
//���ܣ���FOAת����RVA
//����1��unsigned int unFOA, 
//����1˵��������ֵ����ת����FOAֵ
//����2��unsigned* punRVA
//����2˵��������ֵ��ת������RVAֵ��ָ��
//����3��const void* pPE_FileBuffer_Address
//����3˵��������ֵ��FileImage���׵�ַ
//����4:const void* pPE_ImageBuffer_Address
//����4˵��������ֵ��ImageBuffer���׵�ַ
//����ֵ�����ת�ɹ�������TRUE��ת��ʧ�ܣ�����FALSE
//***********************************
bool fnFOA_Convert_RVA(unsigned int unFOA, 
					   unsigned* punRVA, 
					   const void* pPE_FileBuffer_Address,
					   const void* pPE_ImageBuffer_Address)
{
	//PE_NT_HEADERָ��
	PE_NT_HEADER* pPE_NT_Header = NULL;
	//PE_DOS_HEADERָ��
	PE_DOS_HEADER* pPE_DOS_Header = NULL;
	//PE_Section_Headerָ��
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header = NULL;
	//����������
	unsigned int unNumberOfSections = 0;
	//��ת���ĵ�ַ���ڽڵı��
	unsigned int unNumberOfCurrentSection = 0;
	//�������ڽ��е�ƫ����
	unsigned int unDataOffsetInSection = 0;
	//״̬��
	bool blStatus = FALSE;
	
	if (unFOA == NULL)
	{
		if (__DEBUG)
		{
			printf("unFOAΪ0��\r\n");
		}
		goto F;
	}
	if (pPE_FileBuffer_Address == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_Begin_AddressΪNULL.\r\n");
		}
		goto F;
	}
	//��ȡPE_DOS_HEADER
	blStatus =  fnGet_PE_DOS_Header_Address(pPE_FileBuffer_Address, &pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡfnGetPE_DOS_HeaderAddressʧ�ܡ�\r\n");
		}
		goto F;
	}
	//�ж��Ƿ�Ϊ��Ч��WindowsPE�ļ�
	blStatus = fnBlIsVaildWindowsPEFile(pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("������Ч��PE�ļ���\r\n");
		}
		goto F;
	}
	//��ȡPE_NT_HEADER�ĵ�ַ
	blStatus = fnGet_PE_NT_Header_Address(pPE_DOS_Header, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡpPE_NT_Headerʧ�ܡ�\r\n");
		}
		goto F;
	}
	//�ж��Ƿ�Ϊ��Ч��NTͷ��ַ
	blStatus = fnBlIsVaildNTHeaderAddress(pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("������Ч��PE_NT_HEADER��ַ��\r\n");
		}
		goto F;
	}
	//��ȡ�ڱ�����
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &unNumberOfSections);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡpPE_Image_Section_Headerʧ�ܡ�\r\n");
		}
		goto F;
	}
	//ת����ַ
	//�ж�FOA���ĸ���
	for (unNumberOfCurrentSection = 0; unNumberOfCurrentSection < unNumberOfSections; unNumberOfCurrentSection++)
	{
		//�ж�FOA�Ƿ��ڵ�ǰ���С�
		if (unFOA 
			>= 
			(
			pPE_Image_Section_Header[unNumberOfCurrentSection].PointerToRawData 
			+ 
			(unsigned int)pPE_FileBuffer_Address
			) 
			&&
			unFOA 
			< 
			(
			pPE_Image_Section_Header[unNumberOfCurrentSection].PointerToRawData 
			+
			pPE_Image_Section_Header[unNumberOfCurrentSection].SizeOfRawData
			+
			(unsigned int)pPE_FileBuffer_Address)
			)
		{
			//����ڵ�ǰ����
			//����RVA
			*punRVA = 
				unFOA 
				- pPE_Image_Section_Header[unNumberOfCurrentSection].PointerToRawData
				- (unsigned int)pPE_FileBuffer_Address
				+ pPE_Image_Section_Header[unNumberOfCurrentSection].VirtualAddress
				+ (unsigned int)pPE_ImageBuffer_Address;
		}
	}
	
	return TRUE;
	
F:
	return FALSE;
	
}
//***********************************
//��������fnGet_PE_NT_Header_Address_By_FileBuffer
//���ܣ�ͨ��FileBufferֱ�ӻ�ȡPE_NT_Header�ĵ�ַ
//����1��const void* pFileBuffer
//����1˵��������ֵ��FileBuffer�ĵ�ַ
//����2��PE_NT_HEADER** ppPE_NT_Header
//����2˵��������ֵ������ȡPE_NT_Header��ָ���ָ��
//����ֵ�������ȡ�ɹ�������TRUE�������ȡʧ�ܣ�����FALSE
//***********************************
bool fnGet_PE_NT_Header_Address_By_FileBuffer(const void* pFileBuffer,
										   PE_NT_HEADER** ppPE_NT_Header)
{
	PE_DOS_HEADER* pPE_DOS_Header = NULL;
	//״̬��
	bool blStatus = FALSE;
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pFileBuffer��ֵΪ��\r\n");
		}
		goto F;
	}
	//��ȡPE_DOS_HEADER
	blStatus = fnGet_PE_DOS_Header_Address(pFileBuffer, &pPE_DOS_Header);
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_DOS_Header��ȡʧ��\r\n");
		}
		goto F;
	}
	//��ȡPE_NT_HEADER
	blStatus = fnGet_PE_NT_Header_Address(pPE_DOS_Header, ppPE_NT_Header);
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("ppPE_NT_Header��ȡʧ��\r\n");
		}
		goto F;
	}


	return TRUE;
F:
	return FALSE;
}


//***********************************
//fnFind_FileBuffer_Zero_Area_in_Section
//���ܣ���PE�Ľ����и��ݸ��������ԣ��ҵ���Ӧ�����Σ������ڽ����Ľ�β�հ������ҵ���Ӧ��С������
//����1��void* pFileBuffer
//����1˵��������ֵ��FileBuffer�ĵ�ַ
//����2��unsigned int unCharacteristic
//����2˵��������ֵ���ڵ�����
//����3��unsigned int unNeedSize
//����3˵��������ֵ����Ҫ�Ĵ�С
//����4��void** pAddress
//����4˵��������ֵ����������������׵�ַ��
//����ֵ������ɹ��ҵ�������TRUE�����û�ҵ�������FALSE
//***********************************
bool fnFind_FileBuffer_Zero_Area_in_Section(void* pFileBuffer, 
											unsigned int unCharacteristic,
											unsigned int unNeedSize,
											void** ppAddress)
{
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header = NULL;
	PE_NT_HEADER* pPE_NT_Header = NULL;
	//�ڵ�����
	unsigned int unNumberOfSection = 0;
	//״̬��
	bool blStatus = FALSE;
	//����ε��������
	unsigned int unIndexOfCodeSection = 0;
	//ѭ������
	unsigned int unCount = 0;
	//��ǰ�����ĵ�ַ
	char* pCurrentMemory = NULL;
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pFileBuffer ��ֵΪ��\r\n");
		}
		goto F;
	}

	//��ȡPE_NT_Header
	blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(pFileBuffer, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("pPE_NT_Header ��ȡʧ��\r\n");
		}
		goto F;
	}
	//��ȡPE_SECTION_HEADER
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &unNumberOfSection);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("pPE_Image_Section_Header ��ȡʧ��\r\n");
		}
		goto F;
	}
	if (unNumberOfSection == 0)
	{
		if (__DEBUG)
		{
			printf("unNumberOfSection ��ȡʧ��\r\n");
		}
		goto F;
	}
	//�ҿ�ִ������
	for (unIndexOfCodeSection = 0; unIndexOfCodeSection < unNumberOfSection; unIndexOfCodeSection ++)
	{
		if ( // Section is executable.(�ÿ��ִ��)]
			pPE_Image_Section_Header[unIndexOfCodeSection].Characteristics & unCharacteristic
			)
		{
			//�ҵ������
			//��ʼ��Ҫ����������ָ��
			pCurrentMemory =
				(char *)((unsigned int)pFileBuffer 
				+ pPE_Image_Section_Header[unIndexOfCodeSection].PointerToRawData
					+ (unsigned int)pPE_Image_Section_Header[unIndexOfCodeSection].Misc.VirtualSize);
			//�����ʵ�����ݺ���������0�������Ƿ񹻴��ShellCode
			for (unCount = 0; unCount < unNeedSize; unCount ++)
			{

				//�ж��Ƿ������һ����
				if (unIndexOfCodeSection < unNumberOfSection - 1)
				{
					//����������һ���ڣ������ж��Ƿ�Խ��
					if ((unsigned int)(pCurrentMemory + unCount) >= 
						(pPE_Image_Section_Header[unIndexOfCodeSection + 1].PointerToRawData + (unsigned int)pFileBuffer))
					{
						pCurrentMemory = NULL;
						//��������ѭ������������һ����
						
						break;
					}
					if (*(pCurrentMemory + unCount) != 0x0)
					{
						//����ҵ�һ����Ϊ������ݣ�����������������֮�⣬һ��Ҫ�ҵ�һ��������Ϊ0������
						pCurrentMemory = pCurrentMemory + unCount + 1;
						unCount = 0;
					}
				}
				else
				{
					//��������һ����
					//�ж����Ƿ�Խ���˵�ǰ�ڵĽ���
					if ((unsigned int)(pCurrentMemory + unCount) >= 
						(pPE_Image_Section_Header[unIndexOfCodeSection].PointerToRawData 
						+ (unsigned int)pFileBuffer 
						+ pPE_Image_Section_Header[unIndexOfCodeSection].SizeOfRawData))
					{
						//����������Լ��Ľ���
						if (__DEBUG)
						{
							printf("�ұ�����FileBuffer�Ĵ���Σ�û���������Ŀռ䡣\r\n");
						}
						goto F;				
					}
				}
			}

			//�ж��Ƿ��ҵ����������ĵ�ַ
			if (pCurrentMemory != NULL)
			{
				//�ҵ��˾�����ѭ��
				break;
			}
		}
	}
	*ppAddress = pCurrentMemory;

	return TRUE;
F:
	*ppAddress = NULL;
	return FALSE;
}


//***********************************
//��������fnCalculate_New_AddressOfEntryPoint
//���ܣ����ݸ�����FileImage��ַ�������µĳ�����ڵ�
//����1��const void* pFileBuffer
//����1˵��������ֵ��FIleBuffer��ָ��
//����2��unsigned int unNewEntryAddress
//����2˵��������ֵ����Ҫ���������ڵ��ַ
//����3��unsigned int* punNewAddressOfEntryPoint
//����3˵��������ֵ����������µ���ڵ��ַ��
//����ֵ���������ɹ����ͷ���TRUE�����ʧ�ܣ��ͷ���FALSE
//***********************************
bool fnCalculate_New_AddressOfEntryPoint(const void* pFileBuffer,
										 unsigned int unNewEntryAddress,
										 unsigned int* punNewAddressOfEntryPoint)
{
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header = NULL;
	PE_NT_HEADER* pPE_NT_Header = NULL;	
	//�ڵ�����
	unsigned int unNumberOfSection = 0;
	//״̬��
	bool blStatus = FALSE;
	//��ǰ����
	unsigned int unCurrentSectionIndex = 0;
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pFileBuffer ��ֵΪ��\r\n");
		}
		goto F;
	}
	//��ȡPE_NT_Header
	blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(pFileBuffer, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("pPE_NT_Header ��ȡʧ��\r\n");
		}
		goto F;
	}
	//��ȡPE_SECTION_HEADER
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &unNumberOfSection);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("pPE_Image_Section_Header ��ȡʧ��\r\n");
		}
		goto F;
	}
	if (unNumberOfSection == 0)
	{
		if (__DEBUG)
		{
			printf("unNumberOfSection ��ȡʧ��\r\n");
		}
		goto F;
	}
	//ѭ��������Ҫ�޸ĵĵ�ַ���ĸ�������
	for (unCurrentSectionIndex = 0; unCurrentSectionIndex < unNumberOfSection; unCurrentSectionIndex ++)
	{
		//�ж��Ƿ��ڵ�ǰ����
		if ((unNewEntryAddress 
			>= ((unsigned int)pFileBuffer + pPE_Image_Section_Header[unCurrentSectionIndex].PointerToRawData)) 
			&& 
			(unNewEntryAddress 
			< ((unsigned int)pFileBuffer + pPE_Image_Section_Header[unCurrentSectionIndex].PointerToRawData + pPE_Image_Section_Header[unCurrentSectionIndex].SizeOfRawData)) )
		{
			//���ڵ�ǰ����
			//�������ڴ��е���ڵ�
			*punNewAddressOfEntryPoint = 
				unNewEntryAddress 
				- (unsigned int)pFileBuffer 
				- pPE_Image_Section_Header[unCurrentSectionIndex].PointerToRawData
				+ pPE_Image_Section_Header[unCurrentSectionIndex].VirtualAddress;
			//����ѭ��
			break;
			
		}
		else
		{
			//���ٵ�ǰ����
			*punNewAddressOfEntryPoint = NULL;
		}
	}
	return TRUE;
	
F:
	return FALSE;
	
	
}

//***********************************
//��������fnCalculate_AddressOf_E8_E9
//���ܣ�����E8(CALL) E9(JMP)��ShellCode����д�ĵ�ַ
//����1��unsigned int unCurrentAddress
//����1˵��������ֵ��E8,E9��ǰ��PE�ļ������еĵ�ַ������֮�⣬��Ҫ�Ѿ���ImageBase�������
//����2��unsigned int unTargetAddress
//����2˵��������ֵ����PE�ļ���������Ҫ��ת�ĵ�ַ������֮�⣬��Ҫ�Ѿ���ImageBase�������
//����3��unsigned int* punCalculatedAddress
//����3˵��������ֵ��������ֵ�ĵ�ַ
//����ֵ���������ɹ����ͷ���TRUE���������ʧ�ܾͷ���FALSE
//***********************************

bool fnCalculate_AddressOf_E8_E9(unsigned int unCurrentAddress,
								 unsigned int unTargetAddress,
								 unsigned int* punCalculatedAddress)
{
	if (punCalculatedAddress == NULL)
	{
		if (__DEBUG)
		{
			printf("punCalculatedAddress ΪNULL \r\n");
		}
		goto F;

	}
	*punCalculatedAddress = unTargetAddress - unCurrentAddress - 5;
	
	return TRUE;
	
F:
	return FALSE;
}


//***********************************
//��������fnWrite_ShellCode_To_FileImage
//���ܣ���Ŀ���ַд��ShellCode
//����1��void* pTargetAddress
//����1˵���� ����ֵ��д��SHellCode�ĵ�ַ
//����2��char* pShellCode
//����2˵��������ֵ��ShellCode���׵�ַ
//����3��unsigned int unSizeOfShellCode
//����3˵��������ֵ��ShellCode�Ĵ�С
//����ֵ�����д��ɹ�������TRUE�����д��ʧ�ܣ�����FALSE
//***********************************

bool fnWrite_ShellCode_To_FileImage(void* pTargetAddress,
									char* pShellCode,
									unsigned int unSizeOfShellCode)
{
	if (pTargetAddress == NULL)
	{
		if (__DEBUG)
		{
			printf("pTargetAddress ΪNULL\r\n");
		}
		goto F;
	}
	if (pShellCode == NULL)
	{
		if (__DEBUG)
		{
			printf("pShellCode ΪNULL\r\n");
		}
		goto F;
	}
	if (unSizeOfShellCode == 0)
	{
		if (__DEBUG)
		{
			printf("unSizeOfShellCode Ϊ 0\r\n");
		}
		goto F;
	}
	memcpy(pTargetAddress, pShellCode, unSizeOfShellCode * sizeof(char));

	return TRUE;
F:
	return FALSE;

}
