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
//PE文件DOS头结构体
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

//PE文件标准头
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

//PE文件可选头
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
//PE文件NT头
struct PE_NT_HEADER
{
	DWORD Signature;
	PE_FILE_HEADER FileHeader;
	PE_OPTIONAL_HEADER OptionalHeader;
};

//PE文件Section头
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

//判断是否是有效的Windows可执行文件
bool fnBlIsVaildWindowsPEFile(PE_DOS_HEADER* pPE_DOS_HEADER);

//打印PE_DOS_HEADER信息
void fnPrintPE_DOS_HEADER_Info(PE_DOS_HEADER* pPE_DOS_HEADER);

//判断是否是有效的NT头地址
bool fnBlIsVaildNTHeaderAddress(PE_NT_HEADER* pPE_NT_HEADER);

//打印PE_NT_HEADER信息
void fnPrintPE_NT_HEADER_Info(PE_NT_HEADER* pPE_NT_HEADER);

//打印PE_FILE_HEADER信息
void fnPrintPE_FILE_HEADER_Info(PE_FILE_HEADER* pPE_FILE_HEADER);

//打印PE_OPTIONAL_HEADER信息
void fnPrintfPE_OPTIONAL_HEADER_Info(PE_OPTIONAL_HEADER* pPE_OPTIONAL_HEADER);

//遍历打印PE_SECTION_HEADER信息
void fnPrintPE_SECTION_HEADER_Info(PE_IMAGE_SECTION_HEADER* pPE_IMAGE_SECTION_HEADER, int nNumberOfSection);


//***********************************
//函数名：fnGetPE_Image_Section_Header_Structure_Array
//功能：获取链表结构数组：
//参数1：PE_NT_HEADER* pPE_NT_Header
//参数1说明：传入数据，值不可以为NULL
//参数2：PE_IMAGE_SECTION_HEADER** pPE_Image_Section_Header 
//参数2说明：传出数据
//参数3：unsigned int* pNumberOfSections
//参数3说明：传出数据
//返回值：bool，如果函数成功返回TRUE，如果失败返回FALSE
//***********************************
bool fnGetPE_Image_Section_Header_Structure_Array(PE_NT_HEADER* pPE_NT_Header, 
												  PE_IMAGE_SECTION_HEADER** pPE_Image_Section_Header, 
												  unsigned int* pNumberOfSections);

//***********************************
//函数名：fnFileBuffer_Convert_ImageBuffer
//功能：转换FileBuffer到ImageBuffer, 拉伸功能
//参数1：void* pFileBuffer
//参数1说明：传入值，待转换的FileBuffer的地址
//参数2：unsigned int unFileBufferSize
//参数2说明：传入值，FileBuffer的大小
//参数3：void* pImageBuffer
//参数3说明：传出值，转换后的ImageBuffer的地址
//参数4：unsigned int unImageBufferSzie
//参数4说明：传入值，ImageBuffer的大小
//参数5：PE_NT_HEADER* pPE_NT_Header
//参数5说明：传入值,pPE_NT_Header的地址
//参数6：PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header
//参数6说明：传入值，节头的地址
//返回值：bool，如果函数成功返回TRUE，如果失败返回FALSE
//***********************************
bool fnFileBuffer_Convert_ImageBuffer(void* pFileBuffer, 
									  unsigned int unFileBufferSize,
									  void* pImageBuffer, 
									  unsigned int unImageBufferSzie,
									  PE_NT_HEADER* pPE_NT_Header, 
									  PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header);
//***********************************
//函数名：fnGet_PE_DOS_Header_Address
//功能：从ImageBuffer或者FileBuffer开始处获得PE_DOS_Header的地址
//参数1：const void* PE_Begin_Address
//参数1说明：传入值，PE开始的地址
//参数2：PE_DOS_HEADER** ppPE_DOS_Header
//参数2说明：传出值，PE_DOS_Header的地址
//返回值：如果获取成功，返回TRUE,如果失败，返回FALSE
//***********************************
bool fnGet_PE_DOS_Header_Address(const void* PE_Begin_Address, PE_DOS_HEADER** ppPE_DOS_Header);

//***********************************
//函数名：fnFileBuffer_Convert_ImageBuffer
//功能：转换FileBuffer到ImageBuffer, 拉伸功能
//参数1：void* pFileBuffer
//参数1说明：传入值，待转换的FileBuffer的地址
//参数2：void* pImageBuffer
//参数2说明：传出值，转换后的ImageBuffer的地址
//***********************************
bool fnFileBuffer_Convert_ImageBuffer(void* pFileBuffer, 
									  void* pImageBuffer);

//***********************************
//函数名：fnGet_PE_NT_Header_Address
//功能：获取PE文件的PE_NT_HEADER的地址
//参数1：const PE_DOS_HEADER* pPE_DOS_Header
//参数1说明：传入值，传入PE_DOS_Header的地址
//参数2：PE_NT_HEADER** ppPE_NT_Header
//参数2说明：传出值，传出PE_NT_Header的地址
//返回值：如果获取成功，返回TRUE，如果获取失败，返回FALSE
//***********************************
bool fnGet_PE_NT_Header_Address(const PE_DOS_HEADER* pPE_DOS_Header, PE_NT_HEADER** ppPE_NT_Header);

//***********************************
//函数名：fnImageBuffer_Convert_FileBuffer
//功能：转换ImageBuffer到FileBuffer, 压缩功能
//参数1：void* pImageBuffer
//参数1说明：传入值，待转换的ImageBuffer的地址
//参数2：void* pFileBuffer
//参数2说明：传出值，转换后的FileBuffer的地址
//***********************************
bool fnImageBuffer_Convert_FileBuffer(void* pImageBuffer,
									  void* pFileBuffer);
//***********************************
//函数名：fnRVA_Convert_FOA
//功能：把RVA转换成FOA
//参数1：unsigned int unRAV
//参数1说明：传入值，需要转换的地址
//参数2：unsigned* unFOA
//参数2说明：传出值，转换完的地址值的指针
//参数3：const void* pPE_Begin_Address
//参数3说明：传入值，PE文件在内存中开始的地方
//返回值：如果转成功，返回TRUE，转换失败，返回FALSE
//***********************************
bool fnRVA_Convert_FOA(unsigned int unRAV, 
					   unsigned* unFOA, 
					   const void* pPE_Begin_Address);

//***********************************
//函数名：fnFOA_Convert_RVA
//功能：把FOA转换成RVA
//参数1：unsigned int unFOA, 
//参数1说明：传入值，待转换的FOA值
//参数2：unsigned* punRVA
//参数2说明：传出值，转换过的RVA值的指针
//参数3：const void* pPE_FileBuffer_Address
//参数3说明：传入值，FileImage的首地址
//参数4:const void* pPE_ImageBuffer_Address
//参数4说明：传入值，ImageBuffer的首地址
//返回值：如果转成功，返回TRUE，转换失败，返回FALSE
//***********************************
bool fnFOA_Convert_RVA(unsigned int unFOA, 
					   unsigned* punRVA, 
					   const void* pPE_FileBuffer_Address,
					   const void* pPE_ImageBuffer_Address);


#endif // !defined(AFX_PEFILESTRUCTURE_H__EFDDA9D3_4BB8_49CE_A010_0A9B1C99D8F8__INCLUDED_)
