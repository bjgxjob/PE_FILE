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
//�ж���ӽ�����״̬
//��ͷ�洢��������2����ͷ��С�Ŀռ䣬�ռ���ȫ��0
#define ADD_SECTION_HAVE_SPACE_ALL_ZERO	0x1
//��ͷ�洢��������2����ͷ�Ĵ�С�ռ䣬���Ǵ洢���ﲻ����0
#define ADD_SECTION_HAVE_SPACE_NOT_ZERO 0x2
//��ͷ�洢��û�пռ䣬���ǿ�������NTͷ
#define ADD_SECTION_NO_SPACE_BUT_CAN_MOVE_UP 0x3
//��ͷ�洢��û�пռ䣬NTͷ�������ƣ�ֻ���������һ��
#define ADD_SECTION_ONLY_AMPLIFY_LAST_SECTION 0x4

//��ӽ����ķ���
//ֱ����ӽ���
#define ADD_SECTION_METHOD_DIRECTLY_ADD_SECTION 0x0
//����ͷ���ƣ���������ӽ�ͷ
#define ADD_SECTION_METHOD_MOVE_UP_SECTION_HEADER 0x1
//�������һ��
#define ADD_SECTION_METHOD_EXPANDING_LAST_SECTION 0x2


//��������
#define IMAGE_SCN_CNT_CODE 0x00000020              // Section contains code.(������ִ�д���) 
#define IMAGE_SCN_CNT_INITIALIZED_DATA  0x00000040  // Section contains initialized data.(�ÿ�����ѳ�ʼ��������) 
#define  IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080  // Section contains uninitialized data.(�ÿ����δ��ʼ��������) 
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
#define  IMAGE_SCN_MEM_SHARED         0x10000000     // Section is shareable(�ÿ�Ϊ�����). 
#define  IMAGE_SCN_MEM_EXECUTE     0x20000000        // Section is executable.(�ÿ��ִ��) 
#define  IMAGE_SCN_MEM_READ       0x40000000         // Section is readable.(�ÿ�ɶ�) 
#define  IMAGE_SCN_MEM_WRITE    0x80000000           // Section is writeable.(�ÿ��д) 

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

//Directory ������
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
//����4��const void* pImageBuffer_Address
//����4˵��������ֵ��unFOA���ڵ�FileBuffer�ĵ�ַ
//����ֵ�����ת�ɹ�������TRUE��ת��ʧ�ܣ�����FALSE
//***********************************
bool fnRVA_Convert_FOA(unsigned int unRAV, 
					   unsigned* unFOA, 
					   const void* pImageBuffer_Address,
					   const void* pFileBuffer_Address);

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

//***********************************
//fnFind_ImageBuffer_ShellCode_Space_in_Section
//���ܣ���PE�Ľ����и��ݸ��������ԣ��ҵ���Ӧ�����Σ������ڽ����Ľ�β�հ������ҵ���Ӧ��С������
//����1��void* pFileBuffer
//����1˵��������ֵ��ImageBuffer�ĵ�ַ
//����2��unsigned int unCharacteristic
//����2˵��������ֵ����Ҫ��ӵĽ�������
//����3��unsigned int unNeedSize
//����3˵��������ֵ����Ҫ�Ĵ�С
//����4:unsigned int unIndexOfSection
//����˵��������ֵ����Ҫ���ҵĽ������
//����5��void** pAddress
//����5˵��������ֵ����������������׵�ַ��
//����ֵ������ɹ��ҵ�������TRUE�����û�ҵ�������FALSE
//***********************************
bool fnFind_ImageBuffer_ShellCode_Space_in_Section(void* pImageBuffer, 
												unsigned int unCharacteristic,
												unsigned int unNeedSize,
												unsigned int unIndexOfSection,
												void** ppAddress);

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
										   PE_NT_HEADER** ppPE_NT_Header);


//***********************************
//��������fnCalculate_New_AddressOfEntryPoint
//���ܣ����ݸ����ĵ�ַ�������µĳ�����ڵ�
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
										 unsigned int* punNewAddressOfEntryPoint);
//***********************************
//��������fnCalculate_AddressOf_E8_E9
//���ܣ�����E8(CALL) E9(JMP)��ShellCode����д�ĵ�ַ
//����1��unsigned int unCurrentAddress
//����1˵��������ֵ��E8,E9��ǰ��ImageBuffer�еĵ�ַ
//����2��unsigned int unTargetAddress
//����2˵��������ֵ�����ڴ�����Ҫ��ת�ĵ�ַ
//����3��unsigned int* punCalculatedAddress
//����3˵��������ֵ��������ֵ�ĵ�ַ
//����ֵ���������ɹ����ͷ���TRUE���������ʧ�ܾͷ���FALSE
//***********************************

bool fnCalculate_AddressOf_E8_E9(unsigned int unCurrentAddress,
								 unsigned int unTargetAddress,
								 unsigned int* punCalculatedAddress);

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
									unsigned int unSizeOfShellCode);



//***********************************
//��������fnWrite_Data_To_Memory
//���ܣ���Ŀ���ڴ���д������
//����1��void* pTargetAddress
//����1˵��������ֵ��Ŀ���ڴ�ĵ�ַ
//����2��void* pData
//����2˵��������ֵ����д�����ݵĵ�ַ
//����3��unsigned int unSizeOfData
//����3˵��������ֵ����Ҫд�����ݵĴ�С
//����ֵ�����д��ɹ�������TRUE�����д��ʧ�ܣ�����FALSE
//***********************************
bool fnWrite_Data_To_Memory(void* pTargetAddress,
							void* pData,
							unsigned int unSizeOfData);
//***********************************
//��������fnAdd_Section
//���ܣ���ImageBuffer����ӽ�
//����1��IN LPVOID lpFileBuffer
//����1˵����FileBuffer��ָ��
//����2��IN unsigned puSizeOfFileBuffer
//����2˵��:FIleBuffer�Ĵ�С
//����3��IN unsigned uSizeOfSection
//����3˵������Ҫ��ӽڵĴ�С
//����4��OUT LPVOID* plpNewFileBuffer
//����4˵�������������FileBuffer
//����5��OUT unsigned* puSizeOfNewFileBuffer
//����5˵����NewFileBuffer�Ĵ�С
//����6��IN unsigned uCharacteristics
//����6˵���������ڵ�����
//����7��IN char szName[8]
//����7˵���������ڵ�����
//����ֵ�������ӳɹ�����TRUE��������ʧ�ܣ�����FALSE
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
//��������fnMergeSection
//���ܣ��ϲ���
//����1��IN OUT LPVOID lpImageBuffer
//����1˵�������������ImageBuffer���ϲ����ImageBufferҲ���������
//����2��IN int nMergeSection1
//����2˵��:��Ҫ�ϲ��ڵı�ţ�Ҫ��nMergeSection2С,��1��Ϊ0���Դ�����
//����3��IN int nMergeSection2
//����3˵������Ҫ�ϲ��ڵı�ţ�Ҫ��nMergeSection1�󣬵�1��Ϊ0���Դ�����
//����ֵ������ϲ��ɹ�������TRUE���ϲ�ʧ�ܷ���FALSE
//***********************************
bool fnMergeSection(IN OUT LPVOID lpImageBuffer, 
					IN int nMergeSection1, 
					IN int nMergeSection2
					);
//***********************************
//��������fnAlign
//���ܣ����ݴ�����������������ֵ
//����1�� IN unsigned unAlign
//����1˵��������ߴ����
//����2��IN unsigned unNumber
//����2˵��:��Ҫ���������
//����ֵ������󷵻ص�ֵ
//***********************************
unsigned fnAlign(
				 IN unsigned unAlign, 
				 IN unsigned unNumber);
//***********************************
//��������fnGetMaxNumber
//���ܣ���ȡ���ֵ
//����1��IN unsigned unNumber1
//����1˵��������1
//����2��IN unsigned unNumber2
//����2˵��:����2
//����ֵ�����ؽϴ��ֵ
//***********************************
unsigned fnGetMaxNumber(
						IN unsigned unNumber1, 
						IN unsigned unNumber2);

//***********************************
//��������fnGetMinNumber
//���ܣ���ȡ���ֵ
//����1��IN unsigned unNumber1
//����1˵��������1
//����2��IN unsigned unNumber2
//����2˵��:����2
//����ֵ�����ؽ�С��ֵ
//***********************************
unsigned fnGetMinNumber(
						IN unsigned unNumber1, 
						IN unsigned unNumber2);
//***********************************
//��������fnAllocate_ImageBuffer
//���ܣ� ����FileBuffer����ImageBuffer�Ŀռ䣬���ҳ�ʼ����
//����1��IN void* pFileBuffer
//����1˵���� FileBuffer�ĵ�ַ
//����ֵ������ɹ������ط���ĵ�ַ�����ʧ�ܣ����� NULL
//***********************************
void* fnAllocate_ImageBuffer( IN void* pFileBuffer);

//***********************************
//��������fnGet_FileBuffer_Size_By_ImageBuffer
//���ܣ�ͨ��ImageBuffer��ȡFileBuffer�Ĵ�С
//����1��IN void* pImageBuffer
//����1˵����ImageBuffer�ĵ�ַ
//����ֵ�������ȡ�ɹ�������FileBuffer�Ĵ�С�������ȡʧ�ܣ�����0
//***********************************
unsigned fnGet_FileBuffer_Size_By_ImageBuffer(IN void* pImageBuffer);

//***********************************
//��������fnAdd_Section
//���ܣ���ImageBuffer����ӽ�
//����1��IN LPVOID lpFileBuffer
//����1˵����FileBuffer��ָ��
//����2��IN unsigned puSizeOfFileBuffer
//����2˵��:FIleBuffer�Ĵ�С
//����3��IN unsigned uSizeOfSection
//����3˵������Ҫ��ӽڵĴ�С
//����4��OUT LPVOID* plpNewFileBuffer
//����4˵�������������FileBuffer
//����5��OUT unsigned* puSizeOfNewFileBuffer
//����5˵����NewFileBuffer�Ĵ�С
//����6��IN unsigned uCharacteristics
//����6˵���������ڵ�����
//����7��IN char szName[8]
//����7˵���������ڵ�����
//����8�� IN int nMethod
//����8˵����ѡ�񷽷�,ADD_SECTION_METHOD_ϵ��
//����ֵ�������ӳɹ�����TRUE��������ʧ�ܣ�����FALSE
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
//��������fnGet_ExportTable_Address_By_FileBuffer
//���ܣ�����FileBufferֱ�ӻ�ȡ��������ڵ�RVA
//����1��IN LPVOID lpFileBuffer
//����1˵����FileBuffer�ĵ�ַ
//����2��IN OUT unsigned* puExportTable_Address
//����2˵��:���뱣�浼����RVA��ַ��ָ�롣
//����ֵ������ɹ�������TRUE�����ʧ�ܣ�����FALSE
//***********************************

bool fnGet_ExportTable_Address_By_FileBuffer(IN LPVOID lpFileBuffer, IN OUT unsigned* puExportTable_Address);

//***********************************
//��������fnPrint_ExportTable_Info
//���ܣ���ӡExportTable����Ϣ
//����1��IN LPVOID lpFileBuffer
//����1˵����FileBuffer�ĵ�ַ
//����ֵ������ɹ�������TRUE�����ʧ�ܣ�����FALSE
//***********************************
bool fnPrint_ExportTable_Info(IN LPVOID lpFileBuffer);


//***********************************
//��������fnRVA_Convert_FOA_By_FileBuffer
//���ܣ��Ѹ�����RVAת����FOA
//����1��IN unsigned uRVA
//����1˵����������RVAֵ
//����3��IN const LPVOID lpFileBuffer
//����3˵����FileBuffer��ַ
//����ֵ��ת����FOA��ֵ
//***********************************
unsigned fnRVA_Convert_FOA_By_FileBuffer(IN unsigned uRVA,  IN const LPVOID lpFileBuffer);

//***********************************
//��������fnGet_Function_RVA_Address_By_Name
//���ܣ��������ִӵ������л�ȡ������ַ
//����1��IN LPVOID lpFileBuffer
//����1˵����FileBuffer�ĵ�ַ
//����2��IN char* szFunctionName
//����2˵��:���������ַ���
//����ֵ������ɹ������غ�����RVA��ַ�����ʧ�ܣ�����NULL��
//***********************************
void* fnGet_Function_RVA_Address_By_Name( IN LPVOID lpFileBuffer, IN char* szFunctionName);

//***********************************
//��������fnGet_Function_RVA_Address_By_Ordinals
//���ܣ�������Ż�ȡ������ĺ�����ַ
//����1��IN LPVOID lpFileBuffer
//����1˵����FileBuffer�ĵ�ַ
//����2��IN unsigned uIndex
//����2˵��:���������
//����ֵ������ɹ������غ�����RVA,���ʧ�ܣ�����NULL
//***********************************
void* fnGet_Function_RVA_Address_By_Ordinals(IN LPVOID lpFileBuffer, IN unsigned uIndex);

//***********************************
//��������fnGet_Directory_Address
//���ܣ����ݸ�������ţ���Buffer�л�ȡ��Ӧ��Ŀ¼��ṹ��ĵ�ַ
//����1��IN LPVOID lpBuffer
//����1˵����Buffer�ĵ�ַ
//����2��IN int nIndex
//����2˵��:Ҫ��ȡ��Ŀ¼������
//����ֵ�������ȡ�ɹ�������Ŀ¼��ṹ��ĵ�ַ�������ȡʧ�ܣ�����Ŀ¼����ڣ�����NULL
//***********************************
PIMAGE_DATA_DIRECTORY fnGet_Directory_Address(IN LPVOID lpBuffer, IN int nIndex);
//***********************************
//��������fnPrint_Relocation_Table
//���ܣ�������ӡBuffer�е�Relocation Table
//����1��IN LPVOID lpBuffer
//����1˵����Buffer�ĵ�ַ
//����ֵ������ɹ�������TRUE�����ʧ�ܣ�����FALSE
//***********************************
bool fnPrint_Relocation_Table( IN LPVOID lpBuffer);


//***********************************
//��������fnGet_Section_Header_by_RVA
//���ܣ�������������RVA��ַ���õ����ڽڵĽ�ͷ
//����1��IN DWORD RVA
//����1˵������ǰRVA��ַ
//����2��IN LPVOID lpBuffer
//����2˵��: FileBuffer����ImageBuffer�ĵ�ַ
//����ֵ������ɹ�������IMAGE_SECTION_HEADER�ĵ�ַ�����ʧ�ܷ���NULL
//***********************************
PIMAGE_SECTION_HEADER fnGet_Section_Header_by_RVA(IN DWORD RVA, IN LPVOID lpBuffer, OUT DWORD* pIndexOfSection);

#endif // !defined(AFX_PEFILESTRUCTURE_H__EFDDA9D3_4BB8_49CE_A010_0A9B1C99D8F8__INCLUDED_)
