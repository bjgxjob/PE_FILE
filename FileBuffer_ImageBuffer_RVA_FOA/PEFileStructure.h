// PEFileStructure.h: interface for the CPEFileStructure class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PEFILESTRUCTURE_H__EFDDA9D3_4BB8_49CE_A010_0A9B1C99D8F8__INCLUDED_)
#define AFX_PEFILESTRUCTURE_H__EFDDA9D3_4BB8_49CE_A010_0A9B1C99D8F8__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <WINDOWS.H>

class CPEFileStructure  
{
public:
	CPEFileStructure();
	virtual ~CPEFileStructure();

};

#pragma pack(1)
//PE�ļ�DOSͷ�ṹ��
struct PE_DOS_HEADER
{
	WORD   e_magic;                     
	WORD   e_cblp;                      
	WORD   e_cp;                        
	WORD   e_crlc;                      
	WORD   e_cparhdr;                   
	WORD   e_minalloc;                  
	WORD   e_maxalloc;                  
	WORD   e_ss;                        
	WORD   e_sp;                        
	WORD   e_csum;                      
	WORD   e_ip;                        
	WORD   e_cs;                        
	WORD   e_lfarlc;                    
	WORD   e_ovno;                      
	WORD   e_res[4];                   
	WORD   e_oemid;                     
	WORD   e_oeminfo;                   
	WORD   e_res2[10];                  
	DWORD  e_lfanew;  	
	
};

//PE�ļ���׼ͷ
struct PE_FILE_HEADER
{
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
	
};

//PE�ļ���ѡͷ
struct PE_OPTIONAL_HEADER
{
	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;
	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
};
//PE�ļ�NTͷ
struct PE_NT_HEADER
{
	DWORD Signature;
	PE_FILE_HEADER FileHeader;
	PE_OPTIONAL_HEADER OptionalHeader;
};

//PE�ļ�Sectionͷ
#define IMAGE_SIZEOF_SHORT_NAME  8
					
struct PE_IMAGE_SECTION_HEADER 
{
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
		DWORD   PhysicalAddress;
		DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
};
#pragma pack()

//�ж��Ƿ�����Ч��Windows��ִ���ļ�
bool fnBlIsVaildWindowsPEFile(PE_DOS_HEADER* pPE_DOS_HEADER);

//��ӡPE_DOS_HEADER��Ϣ
void fnPrintPE_DOS_HEADER_Info(PE_DOS_HEADER* pPE_DOS_HEADER);

//�ж��Ƿ�����Ч��NTͷ��ַ
bool fnBlIsVaildNTHeaderAddress(PE_NT_HEADER* pPE_NT_HEADER);

//��ӡPE_NT_HEADER��Ϣ
void fnPrintPE_NT_HEADER_Info(PE_NT_HEADER* pPE_NT_HEADER);

//��ӡPE_FILE_HEADER��Ϣ
void fnPrintPE_FILE_HEADER_Info(PE_FILE_HEADER* pPE_FILE_HEADER);

//��ӡPE_OPTIONAL_HEADER��Ϣ
void fnPrintfPE_OPTIONAL_HEADER_Info(PE_OPTIONAL_HEADER* pPE_OPTIONAL_HEADER);

//������ӡPE_SECTION_HEADER��Ϣ
void fnPrintPE_SECTION_HEADER_Info(PE_IMAGE_SECTION_HEADER* pPE_IMAGE_SECTION_HEADER, int nNumberOfSection);


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
												  unsigned int* pNumberOfSections);

//***********************************
//��������fnFileBuffer_Convert_ImageBuffer
//���ܣ�ת��FileBuffer��ImageBuffer, ���칦��
//����1��void* pFileBuffer
//����1˵��������ֵ����ת����FileBuffer�ĵ�ַ
//����2��unsigned int unFileBufferSize
//����2˵��������ֵ��FileBuffer�Ĵ�С
//����3��void* pImageBuffer
//����3˵��������ֵ��ת�����ImageBuffer�ĵ�ַ
//����4��unsigned int unImageBufferSzie
//����4˵��������ֵ��ImageBuffer�Ĵ�С
//����5��PE_NT_HEADER* pPE_NT_Header
//����5˵��������ֵ,pPE_NT_Header�ĵ�ַ
//����6��PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header
//����6˵��������ֵ����ͷ�ĵ�ַ
//����ֵ��bool����������ɹ�����TRUE�����ʧ�ܷ���FALSE
//***********************************
bool fnFileBuffer_Convert_ImageBuffer(void* pFileBuffer, 
									  unsigned int unFileBufferSize,
									  void* pImageBuffer, 
									  unsigned int unImageBufferSzie,
									  PE_NT_HEADER* pPE_NT_Header, 
									  PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header);
//***********************************
//��������fnGet_PE_DOS_Header_Address
//���ܣ���ImageBuffer����FileBuffer��ʼ�����PE_DOS_Header�ĵ�ַ
//����1��const void* PE_Begin_Address
//����1˵��������ֵ��PE��ʼ�ĵ�ַ
//����2��PE_DOS_HEADER** ppPE_DOS_Header
//����2˵��������ֵ��PE_DOS_Header�ĵ�ַ
//����ֵ�������ȡ�ɹ�������TRUE,���ʧ�ܣ�����FALSE
//***********************************
bool fnGet_PE_DOS_Header_Address(const void* PE_Begin_Address, PE_DOS_HEADER** ppPE_DOS_Header);

//***********************************
//��������fnFileBuffer_Convert_ImageBuffer
//���ܣ�ת��FileBuffer��ImageBuffer, ���칦��
//����1��void* pFileBuffer
//����1˵��������ֵ����ת����FileBuffer�ĵ�ַ
//����2��void* pImageBuffer
//����2˵��������ֵ��ת�����ImageBuffer�ĵ�ַ
//***********************************
bool fnFileBuffer_Convert_ImageBuffer(void* pFileBuffer, 
									  void* pImageBuffer);

//***********************************
//��������fnGet_PE_NT_Header_Address
//���ܣ���ȡPE�ļ���PE_NT_HEADER�ĵ�ַ
//����1��const PE_DOS_HEADER* pPE_DOS_Header
//����1˵��������ֵ������PE_DOS_Header�ĵ�ַ
//����2��PE_NT_HEADER** ppPE_NT_Header
//����2˵��������ֵ������PE_NT_Header�ĵ�ַ
//����ֵ�������ȡ�ɹ�������TRUE�������ȡʧ�ܣ�����FALSE
//***********************************
bool fnGet_PE_NT_Header_Address(const PE_DOS_HEADER* pPE_DOS_Header, PE_NT_HEADER** ppPE_NT_Header);

//***********************************
//��������fnImageBuffer_Convert_FileBuffer
//���ܣ�ת��ImageBuffer��FileBuffer, ѹ������
//����1��void* pImageBuffer
//����1˵��������ֵ����ת����ImageBuffer�ĵ�ַ
//����2��void* pFileBuffer
//����2˵��������ֵ��ת�����FileBuffer�ĵ�ַ
//***********************************
bool fnImageBuffer_Convert_FileBuffer(void* pImageBuffer,
									  void* pFileBuffer);
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
					   const void* pPE_Begin_Address);

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
					   const void* pPE_ImageBuffer_Address);


#endif // !defined(AFX_PEFILESTRUCTURE_H__EFDDA9D3_4BB8_49CE_A010_0A9B1C99D8F8__INCLUDED_)
