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

//节区属性
#define IMAGE_SCN_CNT_CODE 0x00000020              // Section contains code.(包含可执行代码) 
#define IMAGE_SCN_CNT_INITIALIZED_DATA  0x00000040  // Section contains initialized data.(该块包含已初始化的数据) 
#define  IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080  // Section contains uninitialized data.(该块包含未初始化的数据) 
#define  IMAGE_SCN_LNK_INFO   0x00000200             // Section contains comments or some other type of information. 
#define  IMAGE_SCN_LNK_REMOVE        0x00000800      // Section contents will not become part of image. 
#define  IMAGE_SCN_LNK_COMDAT     0x00001000         // Section contents comdat. 
#define  IMAGE_SCN_NO_DEFER_SPEC_EXC     0x00004000  // Reset speculative exceptions handling bits in the TLB entries for this section. 
#define  IMAGE_SCN_GPREL        0x00008000           // Section content can be accessed relative to GP. 
#define  IMAGE_SCN_ALIGN_16BYTES      0x00500000     // Default alignment if no others are specified. 
#define  IMAGE_SCN_LNK_NRELOC_OVFL   0x01000000      // Section contains extended relocations. 
#define  IMAGE_SCN_MEM_DISCARDABLE     0x02000000    // Section can be discarded. 
#define  IMAGE_SCN_MEM_NOT_CACHED     0x04000000     // Section is not cachable. 
#define  IMAGE_SCN_MEM_NOT_PAGED  0x08000000         // Section is not pageable. 
#define  IMAGE_SCN_MEM_SHARED         0x10000000     // Section is shareable(该块为共享块). 
#define  IMAGE_SCN_MEM_EXECUTE     0x20000000        // Section is executable.(该块可执行) 
#define  IMAGE_SCN_MEM_READ       0x40000000         // Section is readable.(该块可读) 
#define  IMAGE_SCN_MEM_WRITE    0x80000000           // Section is writeable.(该块可写) 

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

//***********************************
//fnFind_FileBuffer_Zero_Area_in_Section
//功能：从PE的节区中根据给定的属性，找到对应的区段，并且在节区的结尾空白区域找到相应大小的零区
//参数1：void* pFileBuffer
//参数1说明：传入值，FileBuffer的地址
//参数2：unsigned int unCharacteristic
//参数2说明：传入值，节的属性
//参数3：unsigned int unNeedSize
//参数3说明：传入值，需要的大小
//参数4：void** pAddress
//参数4说明：传出值，符合条件区域的首地址。
//返回值：如果成功找到，返回TRUE，如果没找到，返回FALSE
//***********************************
bool fnFind_FileBuffer_Zero_Area_in_Section(void* pFileBuffer, 
											unsigned int unCharacteristic,
											unsigned int unNeedSize,
											void** ppAddress);

//***********************************
//函数名：fnGet_PE_NT_Header_Address_By_FileBuffer
//功能：通过FileBuffer直接获取PE_NT_Header的地址
//参数1：const void* pFileBuffer
//参数1说明：传入值，FileBuffer的地址
//参数2：PE_NT_HEADER** ppPE_NT_Header
//参数2说明：传出值，待获取PE_NT_Header的指针的指针
//返回值：如果获取成功，返回TRUE，如果获取失败，返回FALSE
//***********************************
bool fnGet_PE_NT_Header_Address_By_FileBuffer(const void* pFileBuffer,
										   PE_NT_HEADER** ppPE_NT_Header);


//***********************************
//函数名：fnCalculate_New_AddressOfEntryPoint
//功能：根据给定的地址，计算新的程序入口点
//参数1：const void* pFileBuffer
//参数1说明：传入值，FIleBuffer的指针
//参数2：unsigned int unNewEntryAddress
//参数2说明：传入值，需要计算的新入口点地址
//参数3：unsigned int* punNewAddressOfEntryPoint
//参数3说明：传出值，计算完的新的入口点地址。
//返回值：如果计算成功，就返回TRUE，如果失败，就返回FALSE
//***********************************
bool fnCalculate_New_AddressOfEntryPoint(const void* pFileBuffer,
										 unsigned int unNewEntryAddress,
										 unsigned int* punNewAddressOfEntryPoint);
//***********************************
//函数名：fnCalculate_AddressOf_E8_E9
//功能：计算E8(CALL) E9(JMP)在ShellCode中填写的地址
//参数1：unsigned int unCurrentAddress
//参数1说明：传入值，E8,E9当前在ImageBuffer中的地址
//参数2：unsigned int unTargetAddress
//参数2说明：传入值，在内存中需要跳转的地址
//参数3：unsigned int* punCalculatedAddress
//参数3说明：传出值，计算后的值的地址
//返回值：如果计算成功，就返回TRUE，如果计算失败就返回FALSE
//***********************************

bool fnCalculate_AddressOf_E8_E9(unsigned int unCurrentAddress,
								 unsigned int unTargetAddress,
								 unsigned int* punCalculatedAddress);

//***********************************
//函数名：fnWrite_ShellCode_To_FileImage
//功能：向目标地址写入ShellCode
//参数1：void* pTargetAddress
//参数1说明： 传入值，写入SHellCode的地址
//参数2：char* pShellCode
//参数2说明：传入值，ShellCode的首地址
//参数3：unsigned int unSizeOfShellCode
//参数3说明：传入值，ShellCode的大小
//返回值：如果写入成功，返回TRUE，如果写入失败，返回FALSE
//***********************************

bool fnWrite_ShellCode_To_FileImage(void* pTargetAddress,
									char* pShellCode,
									unsigned int unSizeOfShellCode);





#endif // !defined(AFX_PEFILESTRUCTURE_H__EFDDA9D3_4BB8_49CE_A010_0A9B1C99D8F8__INCLUDED_)
