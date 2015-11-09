// PEFileStructure.h: interface for the CPEFileStructure class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PEFILESTRUCTURE_H__EFDDA9D3_4BB8_49CE_A010_0A9B1C99D8F8__INCLUDED_)
#define AFX_PEFILESTRUCTURE_H__EFDDA9D3_4BB8_49CE_A010_0A9B1C99D8F8__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <WINDOWS.H>
#include <STDLIB.H>

class CPEFileStructure  
{
public:
	CPEFileStructure();
	virtual ~CPEFileStructure();

};
//判断添加节区的状态
//节头存储区至少有2个节头大小的空间，空间中全是0
#define ADD_SECTION_HAVE_SPACE_ALL_ZERO	0x1
//节头存储区至少有2个节头的大小空间，但是存储区里不都是0
#define ADD_SECTION_HAVE_SPACE_NOT_ZERO 0x2
//节头存储区没有空间，但是可以上移NT头
#define ADD_SECTION_NO_SPACE_BUT_CAN_MOVE_UP 0x3
//节头存储区没有空间，NT头不能上移，只能扩大最后一节
#define ADD_SECTION_ONLY_AMPLIFY_LAST_SECTION 0x4

//添加节区的方法
//直接添加节区
#define ADD_SECTION_METHOD_DIRECTLY_ADD_SECTION 0x0
//现有头上移，在下面添加节头
#define ADD_SECTION_METHOD_MOVE_UP_SECTION_HEADER 0x1
//扩大最后一节
#define ADD_SECTION_METHOD_EXPANDING_LAST_SECTION 0x2


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

//Directory 索引项
// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

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
//参数4：const void* pImageBuffer_Address
//参数4说明：传入值，unFOA所在的FileBuffer的地址
//返回值：如果转成功，返回TRUE，转换失败，返回FALSE
//***********************************
bool fnRVA_Convert_FOA(unsigned int unRAV, 
					   unsigned* unFOA, 
					   const void* pImageBuffer_Address,
					   const void* pFileBuffer_Address);

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
//fnFind_ImageBuffer_ShellCode_Space_in_Section
//功能：从PE的节区中根据给定的属性，找到对应的区段，并且在节区的结尾空白区域找到相应大小的零区
//参数1：void* pFileBuffer
//参数1说明：传入值，ImageBuffer的地址
//参数2：unsigned int unCharacteristic
//参数2说明：传入值，需要添加的节区属性
//参数3：unsigned int unNeedSize
//参数3说明：传入值，需要的大小
//参数4:unsigned int unIndexOfSection
//参数说明：传入值，需要查找的节区编号
//参数5：void** pAddress
//参数5说明：传出值，符合条件区域的首地址。
//返回值：如果成功找到，返回TRUE，如果没找到，返回FALSE
//***********************************
bool fnFind_ImageBuffer_ShellCode_Space_in_Section(void* pImageBuffer, 
												unsigned int unCharacteristic,
												unsigned int unNeedSize,
												unsigned int unIndexOfSection,
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



//***********************************
//函数名：fnWrite_Data_To_Memory
//功能：向目标内存中写入数据
//参数1：void* pTargetAddress
//参数1说明：传入值，目标内存的地址
//参数2：void* pData
//参数2说明：传入值，待写入数据的地址
//参数3：unsigned int unSizeOfData
//参数3说明：传入值，需要写入数据的大小
//返回值：如果写入成功，返回TRUE，如果写入失败，返回FALSE
//***********************************
bool fnWrite_Data_To_Memory(void* pTargetAddress,
							void* pData,
							unsigned int unSizeOfData);
//***********************************
//函数名：fnAdd_Section
//功能：向ImageBuffer中添加节
//参数1：IN LPVOID lpFileBuffer
//参数1说明：FileBuffer的指针
//参数2：IN unsigned puSizeOfFileBuffer
//参数2说明:FIleBuffer的大小
//参数3：IN unsigned uSizeOfSection
//参数3说明：需要添加节的大小
//参数4：OUT LPVOID* plpNewFileBuffer
//参数4说明：添加区块后的FileBuffer
//参数5：OUT unsigned* puSizeOfNewFileBuffer
//参数5说明：NewFileBuffer的大小
//参数6：IN unsigned uCharacteristics
//参数6说明：新增节的属性
//参数7：IN char szName[8]
//参数7说明：新增节的名字
//返回值：如果添加成功返回TRUE，如果添加失败，返回FALSE
//***********************************

bool fnAdd_Section( 
				   IN LPVOID lpFileBuffer, 
				   IN unsigned uSizeOfFileBuffer,
				   IN unsigned uSizeOfSection,
				   OUT LPVOID* plpNewFileBuffer,
				   OUT unsigned* puSizeOfNewFileBuffer,
				   IN unsigned uCharacteristics,
				   IN char szName[8]
				   );
//***********************************
//函数名：fnMergeSection
//功能：合并节
//参数1：IN OUT LPVOID lpImageBuffer
//参数1说明：经过拉伸后，ImageBuffer，合并后的ImageBuffer也保存在这里。
//参数2：IN int nMergeSection1
//参数2说明:需要合并节的编号，要比nMergeSection2小,第1个为0，以此类推
//参数3：IN int nMergeSection2
//参数3说明：需要合并节的编号，要比nMergeSection1大，第1个为0，以此类推
//返回值：如果合并成功，返回TRUE，合并失败返回FALSE
//***********************************
bool fnMergeSection(IN OUT LPVOID lpImageBuffer, 
					IN int nMergeSection1, 
					IN int nMergeSection2
					);
//***********************************
//函数名：fnAlign
//功能：根据传入参数，计算对齐后的值
//参数1： IN unsigned unAlign
//参数1说明：对齐尺寸参数
//参数2：IN unsigned unNumber
//参数2说明:需要计算的数据
//返回值：计算后返回的值
//***********************************
unsigned fnAlign(
				 IN unsigned unAlign, 
				 IN unsigned unNumber);
//***********************************
//函数名：fnGetMaxNumber
//功能：获取最大值
//参数1：IN unsigned unNumber1
//参数1说明：数字1
//参数2：IN unsigned unNumber2
//参数2说明:数字2
//返回值：返回较大的值
//***********************************
unsigned fnGetMaxNumber(
						IN unsigned unNumber1, 
						IN unsigned unNumber2);

//***********************************
//函数名：fnGetMinNumber
//功能：获取最大值
//参数1：IN unsigned unNumber1
//参数1说明：数字1
//参数2：IN unsigned unNumber2
//参数2说明:数字2
//返回值：返回较小的值
//***********************************
unsigned fnGetMinNumber(
						IN unsigned unNumber1, 
						IN unsigned unNumber2);
//***********************************
//函数名：fnAllocate_ImageBuffer
//功能： 根据FileBuffer分配ImageBuffer的空间，并且初始化。
//参数1：IN void* pFileBuffer
//参数1说明： FileBuffer的地址
//返回值：如果成功，返回分配的地址，如果失败，返回 NULL
//***********************************
void* fnAllocate_ImageBuffer( IN void* pFileBuffer);

//***********************************
//函数名：fnGet_FileBuffer_Size_By_ImageBuffer
//功能：通过ImageBuffer获取FileBuffer的大小
//参数1：IN void* pImageBuffer
//参数1说明：ImageBuffer的地址
//返回值：如果获取成功，返回FileBuffer的大小，如果获取失败，返回0
//***********************************
unsigned fnGet_FileBuffer_Size_By_ImageBuffer(IN void* pImageBuffer);

//***********************************
//函数名：fnAdd_Section
//功能：向ImageBuffer中添加节
//参数1：IN LPVOID lpFileBuffer
//参数1说明：FileBuffer的指针
//参数2：IN unsigned puSizeOfFileBuffer
//参数2说明:FIleBuffer的大小
//参数3：IN unsigned uSizeOfSection
//参数3说明：需要添加节的大小
//参数4：OUT LPVOID* plpNewFileBuffer
//参数4说明：添加区块后的FileBuffer
//参数5：OUT unsigned* puSizeOfNewFileBuffer
//参数5说明：NewFileBuffer的大小
//参数6：IN unsigned uCharacteristics
//参数6说明：新增节的属性
//参数7：IN char szName[8]
//参数7说明：新增节的名字
//参数8： IN int nMethod
//参数8说明：选择方法,ADD_SECTION_METHOD_系列
//返回值：如果添加成功返回TRUE，如果添加失败，返回FALSE
//***********************************

bool fnAdd_Section_By_Method( 
				   IN LPVOID lpFileBuffer, 
				   IN unsigned uSizeOfFileBuffer,
				   IN unsigned uSizeOfSection,
				   OUT LPVOID* plpNewFileBuffer,
				   OUT unsigned* puSizeOfNewFileBuffer,
				   IN unsigned uCharacteristics,
				   IN char szName[8],
				   IN int nMethod
				   );



//***********************************
//函数名：fnGet_ExportTable_Address_By_FileBuffer
//功能：根据FileBuffer直接获取导出表的在的RVA
//参数1：IN LPVOID lpFileBuffer
//参数1说明：FileBuffer的地址
//参数2：IN OUT unsigned* puExportTable_Address
//参数2说明:传入保存导出表RVA地址的指针。
//返回值：如果成功，返回TRUE，如果失败，返回FALSE
//***********************************

bool fnGet_ExportTable_Address_By_FileBuffer(IN LPVOID lpFileBuffer, IN OUT unsigned* puExportTable_Address);

//***********************************
//函数名：fnPrint_ExportTable_Info
//功能：打印ExportTable的信息
//参数1：IN LPVOID lpFileBuffer
//参数1说明：FileBuffer的地址
//返回值：如果成功，返回TRUE，如果失败，返回FALSE
//***********************************
bool fnPrint_ExportTable_Info(IN LPVOID lpFileBuffer);


//***********************************
//函数名：fnRVA_Convert_FOA_By_FileBuffer
//功能：把给定的RVA转换成FOA
//参数1：IN unsigned uRVA
//参数1说明：给定的RVA值
//参数3：IN const LPVOID lpFileBuffer
//参数3说明：FileBuffer地址
//返回值：转换后FOA的值
//***********************************
unsigned fnRVA_Convert_FOA_By_FileBuffer(IN unsigned uRVA,  IN const LPVOID lpFileBuffer);

//***********************************
//函数名：fnGet_Function_RVA_Address_By_Name
//功能：根据名字从导出表中获取函数地址
//参数1：IN LPVOID lpFileBuffer
//参数1说明：FileBuffer的地址
//参数2：IN char* szFunctionName
//参数2说明:函数名的字符串
//返回值：如果成功，返回函数的RVA地址，如果失败，返回NULL。
//***********************************
void* fnGet_Function_RVA_Address_By_Name( IN LPVOID lpFileBuffer, IN char* szFunctionName);

//***********************************
//函数名：fnGet_Function_RVA_Address_By_Ordinals
//功能：根据序号获取导出表的函数地址
//参数1：IN LPVOID lpFileBuffer
//参数1说明：FileBuffer的地址
//参数2：IN unsigned uIndex
//参数2说明:函数的序号
//返回值：如果成功，返回函数的RVA,如果失败，返回NULL
//***********************************
void* fnGet_Function_RVA_Address_By_Ordinals(IN LPVOID lpFileBuffer, IN unsigned uIndex);

//***********************************
//函数名：fnGet_Directory_Address
//功能：根据给定的序号，从Buffer中获取对应的目录项结构体的地址
//参数1：IN LPVOID lpBuffer
//参数1说明：Buffer的地址
//参数2：IN int nIndex
//参数2说明:要获取的目录项的序号
//返回值：如果获取成功，返回目录项结构体的地址，如果获取失败，或者目录项不存在，返回NULL
//***********************************
PIMAGE_DATA_DIRECTORY fnGet_Directory_Address(IN LPVOID lpBuffer, IN int nIndex);
//***********************************
//函数名：fnPrint_Relocation_Table
//功能：遍历打印Buffer中的Relocation Table
//参数1：IN LPVOID lpBuffer
//参数1说明：Buffer的地址
//返回值：如果成功，返回TRUE，如果失败，返回FALSE
//***********************************
bool fnPrint_Relocation_Table( IN LPVOID lpBuffer);


//***********************************
//函数名：fnGet_Section_Header_by_RVA
//功能：根据所给定的RVA地址，得到所在节的节头
//参数1：IN DWORD RVA
//参数1说明：当前RVA地址
//参数2：IN LPVOID lpBuffer
//参数2说明: FileBuffer或者ImageBuffer的地址
//返回值：如果成功，返回IMAGE_SECTION_HEADER的地址，如果失败返回NULL
//***********************************
PIMAGE_SECTION_HEADER fnGet_Section_Header_by_RVA(IN DWORD RVA, IN LPVOID lpBuffer, OUT DWORD* pIndexOfSection);

#endif // !defined(AFX_PEFILESTRUCTURE_H__EFDDA9D3_4BB8_49CE_A010_0A9B1C99D8F8__INCLUDED_)
