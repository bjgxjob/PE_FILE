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

//判断是否是有效的Windows可执行文件
bool fnBlIsVaildWindowsPEFile(PE_DOS_HEADER* pPE_DOS_HEADER)
{
	//判断传入的指针是否为空
	if (pPE_DOS_HEADER == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_DOS_HEADER 为空.\r\n");
		}
		goto F;
	}
	
	//如果要用字符来判断的话，要写'ZM'，因为在内存中是小端存储。
	if (pPE_DOS_HEADER->e_magic != 0x5a4d)
	{
		if (__DEBUG)
		{
			printf("不是有效的Windows Executive 文件。\r\n");
		}
		
		goto F;
	}
	else
	{
		if (__DEBUG)
		{
			printf("是有效的Windows Executive 文件。\r\n");
		}
		goto T;
		
	}
T:
	return TRUE;
F:
	return FALSE;
};

//打印PE_DOS_HEADER信息
void fnPrintPE_DOS_HEADER_Info(PE_DOS_HEADER* pPE_DOS_HEADER)
{
	int nCount = 0;
	if (pPE_DOS_HEADER == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_DOS_HEADER 为空.\r\n");
		}
		goto RET;
		
	}
	printf("开始打印PE DOS Header:\r\n");
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
	
	//打印完成
	printf("PE_DOS_HEADER打印完成.\r\n");
	
RET:
	return;
	
}

//判断是否是有效的NT头地址
bool fnBlIsVaildNTHeaderAddress(PE_NT_HEADER* pPE_NT_HEADER)
{
	//判断传入的指针是否为空
	if (pPE_NT_HEADER == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_NT_HEADER 为空.\r\n");
		}
		goto F;
	}
	//这次用字符转化的数字来判断
	if (pPE_NT_HEADER->Signature != 'EP')
	{
		if (__DEBUG)
		{
			printf("不是有效的NT头地址，或者不是有效的PE文件。\r\n");
		}
		goto F;
	}
	else
	{
		if (__DEBUG)
		{
			printf("是有效的NT头地址。\r\n");
		}
		goto T;
	}
F:
	return FALSE;
T:
	return TRUE;
}

//打印PE_NT_HEADER信息
void fnPrintPE_NT_HEADER_Info(PE_NT_HEADER* pPE_NT_HEADER)
{
	//判断传入的指针是否为空
	if (pPE_NT_HEADER == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_NT_HEADER为空.\r\n");
		}
		goto RET;
		
	}
	//开始打印PE_NT_Header
	printf("开始打印PE_NT_Header\r\n");
	//Signature
	printf("Signature:%x\r\n", pPE_NT_HEADER->Signature);
	//PE_FILE_HEADER的信息和PE_OPTIONAL_HEADER的信息在其他函数中打印。
	printf("PE_FILE_HEADER的信息和PE_OPTIONAL_HEADER的信息在其他函数中打印。\r\n");
	//打印结束
	printf("PE_NT_Header打印结束。\r\n");
RET:
	return;
}

//打印PE_FILE_HEADER信息
void fnPrintPE_FILE_HEADER_Info(PE_FILE_HEADER* pPE_FILE_HEADER)
{
	//判断传入的指针是否为空
	if (pPE_FILE_HEADER == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_FILE_HEADER为空.\r\n");
		}
		goto RET;
	}
	//开始打印PE_FILE_HEADER的信息
	printf("开始打印PE_FILE_HEADER的信息。\r\n");
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
	//打印完成
	printf("PE_FILE_HEADER信息打印完成。\r\n");
	
	
RET:
	return;
}

//打印PE_OPTIONAL_HEADER信息
void fnPrintfPE_OPTIONAL_HEADER_Info(PE_OPTIONAL_HEADER* pPE_OPTIONAL_HEADER)
{
	if (pPE_OPTIONAL_HEADER == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_OPTIONAL_HEADER为空\r\n");
		}
		goto RET;
	}
	
	printf("开始打印PE_OPTIONAL_HEADER的信息。\r\n");
	//Magic
	printf("Magic:%x\r\n", pPE_OPTIONAL_HEADER->Magic);
	if (pPE_OPTIONAL_HEADER->Magic == 0x10B)
	{
		printf("该文件是32Bit PE文件.\r\n");
	}
	if (pPE_OPTIONAL_HEADER->Magic == 0x20B)
	{
		printf("该文件是64Bit PE文件.\r\n");
	}
	if ((pPE_OPTIONAL_HEADER->Magic != 0x10B) && (pPE_OPTIONAL_HEADER->Magic != 0x20B))
	{
		printf("该文件既不是32Bit PE文件也不是64Bit PE文件\r\n");
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

//遍历打印PE_SECTION_HEADER信息
void fnPrintPE_SECTION_HEADER_Info(PE_IMAGE_SECTION_HEADER* pPE_IMAGE_SECTION_HEADER, int nNumberOfSection)
{
	char szSectionName[9] = {0};
	int i = 0;
	int nTest = sizeof(PE_IMAGE_SECTION_HEADER);
	if (pPE_IMAGE_SECTION_HEADER == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_IMAGE_SECTION_HEADER为NULL.\r\n");
		}
		goto RET;
	}
	printf("**************************开始打印PE_IMAGE_SECTION_HEADER******************\r\n");
	
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
	printf("**********************PE_IMAGE_SECTION_HEADER打印结束***************************\r\n");
	
RET:
	return;
}

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
												  unsigned int* pNumberOfSections
												  )
{
	if (pPE_NT_Header == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_NT_Header为空。\r\n");
		}
		goto F;
	}
	if (pNumberOfSections == NULL)
	{
		if (__DEBUG)
		{
			printf("pNumberOfSections为空。\r\n");
		}
		goto F;
	}
	//从PE_NT_Header中获取NumberOfSections
	(*pNumberOfSections) = pPE_NT_Header->FileHeader.NumberOfSections;
	if (*pNumberOfSections == 0)
	{
		if (__DEBUG)
		{
			printf("*pNumberOfSections的值为0，可能是NT头指针错误或者不是有效的PE文件。\r\n");
		}
		goto F;
	}
	//获取PE_IMAGE_SECTION_HEADER地址
	*pPE_Image_Section_Header = (PE_IMAGE_SECTION_HEADER *)((unsigned int)&pPE_NT_Header->OptionalHeader + pPE_NT_Header->FileHeader.SizeOfOptionalHeader);
	if (pPE_Image_Section_Header == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_Image_Section_Header获取失败。\r\n");
		}
		goto F;
	}
	
	return TRUE;
F:
	return FALSE;
}

//***********************************
//函数名：fnFileBuffer_Convert_ImageBuffer
//功能：转换FileBuffer到ImageBuffer, 拉伸功能
//参数1：void* pFileBuffer
//参数1说明：传入值，待转换的FileBuffer的地址
//参数2：void* pImageBuffer
//参数2说明：传出值，转换后的ImageBuffer的地址
//***********************************
bool fnFileBuffer_Convert_ImageBuffer(void* pFileBuffer, 
									  void* pImageBuffer)
{
	//PE_NT_HEADER指针
	PE_NT_HEADER* pPE_NT_Header = NULL;
	//PE_DOS_HEADER指针
	PE_DOS_HEADER* pPE_DOS_Header = NULL;
	//PE_Section_Header指针
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header = NULL;
	//节区的数量
	unsigned int unNumberOfSections = 0;
	//循环计数
	unsigned int unCount = 0;
	//状态量
	bool blStatus = FALSE;
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pFileBuffer为空。\r\n");
		}
		goto F;
	}
	if (pImageBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pImageBuffer的值为NULL。\r\n");
		}
		goto F;
	}
	//获取PE_DOS_HEADER
	blStatus =  fnGet_PE_DOS_Header_Address(pFileBuffer, &pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取fnGetPE_DOS_HeaderAddress失败。\r\n");
		}
		goto F;
	}
	//判断是否为有效的WindowsPE文件
	blStatus = fnBlIsVaildWindowsPEFile(pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("不是有效的PE文件。\r\n");
		}
		goto F;
	}
	//获取PE_NT_HEADER的地址
	blStatus = fnGet_PE_NT_Header_Address(pPE_DOS_Header, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取pPE_NT_Header失败。\r\n");
		}
		goto F;
	}
	//判断是否为有效的NT头地址
	blStatus = fnBlIsVaildNTHeaderAddress(pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("不是有效的PE_NT_HEADER地址。\r\n");
		}
		goto F;
	}
	//获取节表数组
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &unNumberOfSections);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取pPE_Image_Section_Header失败。\r\n");
		}
		goto F;
	}
	
	//复制PE_DOS_HEADER, PE_NT_HEADER, PE_SECTION_HEADER到ImageBuffer
	memcpy(pImageBuffer, pFileBuffer, pPE_NT_Header->OptionalHeader.SizeOfHeaders * sizeof(char));
	
	
	
	//循环赋值节区
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
//函数名：fnGetPE_DOS_HeaderAddress
//功能：从ImageBuffer或者FileBuffer开始处获得PE_DOS_Header的地址
//参数1：const void* PE_Begin_Address
//参数1说明：传入值，PE开始的地址
//参数2：PE_DOS_HEADER** ppPE_DOS_Header
//参数2说明：传出值，PE_DOS_Header的地址
//返回值：如果获取成功，返回TRUE,如果失败，返回FALSE
//***********************************
bool fnGet_PE_DOS_Header_Address(const void* PE_Begin_Address, PE_DOS_HEADER** ppPE_DOS_Header)
{
	if (PE_Begin_Address == NULL)
	{
		if (__DEBUG)
		{
			printf("PE_Begin_Address为空。\r\n");
		}
		goto F;
	}
	
	//获得PE_DOS_HEADER指针
	*ppPE_DOS_Header = (PE_DOS_HEADER *)PE_Begin_Address;
	if (*ppPE_DOS_Header == NULL)
	{
		if (__DEBUG)
		{
			printf("获取PE_DOS_Header失败。\r\n");
		}
		goto F;
	}
	return TRUE;
F:
	return FALSE;
}

//***********************************
//函数名：fnGet_PE_NT_Header_Address
//功能：获取PE文件的PE_NT_HEADER的地址
//参数1：const PE_DOS_HEADER* pPE_DOS_Header
//参数1说明：传入值，传入PE_DOS_Header的地址
//参数2：PE_NT_HEADER** ppPE_NT_Header
//参数2说明：传出值，传出PE_NT_Header的地址
//返回值：如果获取成功，返回TRUE，如果获取失败，返回FALSE
//***********************************
bool fnGet_PE_NT_Header_Address(const PE_DOS_HEADER* pPE_DOS_Header, PE_NT_HEADER** ppPE_NT_Header)
{
	if (pPE_DOS_Header == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_DOS_Header为空。\r\n");
		}
		goto F;
	}
	//得到PE_NT_HEADER指针
	*ppPE_NT_Header = (PE_NT_HEADER *)((int)pPE_DOS_Header + pPE_DOS_Header->e_lfanew);
	return TRUE;
	
F:
	return FALSE;
	
}


//***********************************
//函数名：fnImageBuffer_Convert_FileBuffer
//功能：转换ImageBuffer到FileBuffer, 压缩功能
//参数1：void* pImageBuffer
//参数1说明：传入值，待转换的ImageBuffer的地址
//参数2：void* pFileBuffer
//参数2说明：传出值，转换后的FileBuffer的地址
//***********************************
bool fnImageBuffer_Convert_FileBuffer(void* pImageBuffer,
									  void* pFileBuffer)
{
	//PE_NT_HEADER指针
	PE_NT_HEADER* pPE_NT_Header = NULL;
	//PE_DOS_HEADER指针
	PE_DOS_HEADER* pPE_DOS_Header = NULL;
	//PE_Section_Header指针
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header = NULL;
	//节区的数量
	unsigned int unNumberOfSections = 0;
	//循环计数
	unsigned int unCount = 0;
	//状态量
	bool blStatus = FALSE;
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pFileBuffer为空。\r\n");
		}
		goto F;
	}
	if (pImageBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pImageBuffer的值为NULL。\r\n");
		}
		goto F;
	}
	//获取PE_DOS_HEADER
	blStatus =  fnGet_PE_DOS_Header_Address(pFileBuffer, &pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取fnGetPE_DOS_HeaderAddress失败。\r\n");
		}
		goto F;
	}
	//判断是否为有效的WindowsPE文件
	blStatus = fnBlIsVaildWindowsPEFile(pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("不是有效的PE文件。\r\n");
		}
		goto F;
	}
	//获取PE_NT_HEADER的地址
	blStatus = fnGet_PE_NT_Header_Address(pPE_DOS_Header, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取pPE_NT_Header失败。\r\n");
		}
		goto F;
	}
	//判断是否为有效的NT头地址
	blStatus = fnBlIsVaildNTHeaderAddress(pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("不是有效的PE_NT_HEADER地址。\r\n");
		}
		goto F;
	}
	//获取节表数组
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &unNumberOfSections);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取pPE_Image_Section_Header失败。\r\n");
		}
		goto F;
	}
	
	//复制PE_DOS_HEADER, PE_NT_HEADER, PE_SECTION_HEADER到ImageBuffer
	memcpy(pImageBuffer, pFileBuffer, pPE_NT_Header->OptionalHeader.SizeOfHeaders * sizeof(char));
	
	
	
	//循环赋值节区
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
					   const void* pPE_Begin_Address)
{
	//PE_NT_HEADER指针
	PE_NT_HEADER* pPE_NT_Header = NULL;
	//PE_DOS_HEADER指针
	PE_DOS_HEADER* pPE_DOS_Header = NULL;
	//PE_Section_Header指针
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header = NULL;
	//节区的数量
	unsigned int unNumberOfSections = 0;
	//待转换的地址所在节的编号
	unsigned int unNumberOfCurrentSection = 0;
	//在数据在节中的偏移量
	unsigned int unDataOffsetInSection = 0;
	//状态量
	bool blStatus = FALSE;
	
	if (unFOA == NULL)
	{
		if (__DEBUG)
		{
			printf("unFOA为0。\r\n");
		}
		goto F;
	}
	if (pPE_Begin_Address == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_Begin_Address为NULL.\r\n");
		}
		goto F;
	}
	//获取PE_DOS_HEADER
	blStatus =  fnGet_PE_DOS_Header_Address(pPE_Begin_Address, &pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取fnGetPE_DOS_HeaderAddress失败。\r\n");
		}
		goto F;
	}
	//判断是否为有效的WindowsPE文件
	blStatus = fnBlIsVaildWindowsPEFile(pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("不是有效的PE文件。\r\n");
		}
		goto F;
	}
	//获取PE_NT_HEADER的地址
	blStatus = fnGet_PE_NT_Header_Address(pPE_DOS_Header, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取pPE_NT_Header失败。\r\n");
		}
		goto F;
	}
	//判断是否为有效的NT头地址
	blStatus = fnBlIsVaildNTHeaderAddress(pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("不是有效的PE_NT_HEADER地址。\r\n");
		}
		goto F;
	}
	//获取节表数组
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &unNumberOfSections);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取pPE_Image_Section_Header失败。\r\n");
		}
		goto F;
	}
	//遍历节头，找出需要转换的地址所在的节头
	for (unNumberOfCurrentSection = 0; unNumberOfCurrentSection < unNumberOfSections; unNumberOfCurrentSection++)
	{
		//这个判断如果成立，就代表这个数据PE头中，不在后面的节区中。
		if ((unRAV - (unsigned int)pPE_Begin_Address) < pPE_NT_Header->OptionalHeader.SizeOfHeaders)
		{
			*unFOA = unRAV - (unsigned int)pPE_Begin_Address;
			break;
		}
		//判断这个值是否比当前节的起始地址大
		if (unRAV >= (pPE_Image_Section_Header[unNumberOfCurrentSection].VirtualAddress + (unsigned int)pPE_Begin_Address))
		{
			//判断是否为最后一个节
			if (unNumberOfCurrentSection < unNumberOfSections - 1)
			{
				//不是最后一个节，继续判断是否比下一个节的开始地址小
				if (unRAV < (pPE_Image_Section_Header[unNumberOfCurrentSection + 1].VirtualAddress + (unsigned int)pPE_Begin_Address))
				{
					//计算在节中的偏移
					unDataOffsetInSection = unRAV - (unsigned int)pPE_Begin_Address - pPE_Image_Section_Header[unNumberOfCurrentSection].VirtualAddress;
					//判断在节中的偏移是否超过了FileImage的节的大小
					if (unDataOffsetInSection > pPE_Image_Section_Header[unNumberOfCurrentSection].SizeOfRawData)
					{
						//如果大于就报错，因为一定找不到对应的地址，节被拉伸过，在文件中的未初始化数据在内存运行中被初始化了
						if (__DEBUG)
						{
							printf("文件运行时RVA在第：%x节中，但是不能找到对应的FOA，因为这个地址是在运行后经过拉伸，在FileImage中没有对应的数据.\r\n", unNumberOfCurrentSection + 1);
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
				//如果是最后一个节，就判断是否在最后一个节中
				if (unRAV <= (unsigned int)pPE_Begin_Address + pPE_NT_Header->OptionalHeader.SizeOfImage)
				{
					unDataOffsetInSection = unRAV - (unsigned int)pPE_Begin_Address - pPE_Image_Section_Header[unNumberOfCurrentSection].VirtualAddress;
					//判断在节中的偏移是否超过了FileImage的节的大小
					if (unDataOffsetInSection > pPE_Image_Section_Header[unNumberOfCurrentSection].SizeOfRawData)
					{
						//如果大于就报错，因为一定找不到对应的地址，节被拉伸过，在文件中的未初始化数据在内存运行中被初始化了
						if (__DEBUG)
						{
							printf("文件运行时RVA在第：%x节中，但是不能找到对应的FOA，因为这个地址是在运行后经过拉伸，在FileImage中没有对应的数据.\r\n", unNumberOfCurrentSection + 1);
						}
						*unFOA = 0;
						goto F;
					}
					*unFOA = unDataOffsetInSection + pPE_Image_Section_Header[unNumberOfCurrentSection].PointerToRawData;
					break;
					
				}
				else
				{
					//否则就报错，不再这个PE文件中。
					if (__DEBUG)
					{
						printf("RVA不在本PE文件中。\r\n");
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
					   const void* pPE_ImageBuffer_Address)
{
	//PE_NT_HEADER指针
	PE_NT_HEADER* pPE_NT_Header = NULL;
	//PE_DOS_HEADER指针
	PE_DOS_HEADER* pPE_DOS_Header = NULL;
	//PE_Section_Header指针
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header = NULL;
	//节区的数量
	unsigned int unNumberOfSections = 0;
	//待转换的地址所在节的编号
	unsigned int unNumberOfCurrentSection = 0;
	//在数据在节中的偏移量
	unsigned int unDataOffsetInSection = 0;
	//状态量
	bool blStatus = FALSE;
	
	if (unFOA == NULL)
	{
		if (__DEBUG)
		{
			printf("unFOA为0。\r\n");
		}
		goto F;
	}
	if (pPE_FileBuffer_Address == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_Begin_Address为NULL.\r\n");
		}
		goto F;
	}
	//获取PE_DOS_HEADER
	blStatus =  fnGet_PE_DOS_Header_Address(pPE_FileBuffer_Address, &pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取fnGetPE_DOS_HeaderAddress失败。\r\n");
		}
		goto F;
	}
	//判断是否为有效的WindowsPE文件
	blStatus = fnBlIsVaildWindowsPEFile(pPE_DOS_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("不是有效的PE文件。\r\n");
		}
		goto F;
	}
	//获取PE_NT_HEADER的地址
	blStatus = fnGet_PE_NT_Header_Address(pPE_DOS_Header, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取pPE_NT_Header失败。\r\n");
		}
		goto F;
	}
	//判断是否为有效的NT头地址
	blStatus = fnBlIsVaildNTHeaderAddress(pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("不是有效的PE_NT_HEADER地址。\r\n");
		}
		goto F;
	}
	//获取节表数组
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &unNumberOfSections);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("获取pPE_Image_Section_Header失败。\r\n");
		}
		goto F;
	}
	for (unNumberOfCurrentSection = 0; unNumberOfCurrentSection < unNumberOfSections; unNumberOfCurrentSection ++)
	{
		//这个判断如果成立，就代表这个数据PE头中，不在后面的节区中。
		if ((unFOA - (unsigned int)pPE_FileBuffer_Address) < pPE_NT_Header->OptionalHeader.SizeOfHeaders)
		{
			*punRVA = unFOA - (unsigned int)pPE_FileBuffer_Address;
			break;
		}
		//判断FOA是否比当前节区的SizeOfRawData大
		if (unFOA >= (pPE_Image_Section_Header[unNumberOfCurrentSection].SizeOfRawData + (unsigned int)pPE_FileBuffer_Address))
		{
			//判断当前节区是否为最后一个节区
			if (unNumberOfCurrentSection < unNumberOfSections - 1)
			{
				//不是最后一个节区
				//判断是否比下一个节区的PointerToRawData小
				if (unFOA < (pPE_Image_Section_Header[unNumberOfCurrentSection + 1].SizeOfRawData + (unsigned int)pPE_FileBuffer_Address))
				{
					//比当前节区大，比下一个节区小，说明就在这个节区里面。
					//计算偏移地址
					unDataOffsetInSection = unFOA - pPE_Image_Section_Header[unNumberOfCurrentSection].PointerToRawData - (unsigned int)pPE_FileBuffer_Address;
					//计算RVA
					*punRVA = unDataOffsetInSection + pPE_Image_Section_Header[unNumberOfCurrentSection].VirtualAddress + (unsigned int)pPE_ImageBuffer_Address;
					break;
				}			

			}
			else
			{
				//是最后一个节区
				//判断是否超出了这个FileImage
				if (unFOA >= (pPE_Image_Section_Header[unNumberOfCurrentSection].PointerToRawData + pPE_Image_Section_Header[unNumberOfCurrentSection].SizeOfRawData + (unsigned int)pPE_FileBuffer_Address))
				{
					if (__DEBUG)
					{
						printf("FOA超出了FileImage的界限。\r\n");
					}
					*punRVA = 0;
					goto F;
				}
				else
				{
					//没有超出界限
					//计算偏移
					unDataOffsetInSection = unFOA - pPE_Image_Section_Header[unNumberOfCurrentSection].PointerToRawData - (unsigned int)pPE_FileBuffer_Address;
					//计算RVA
					*punRVA = unDataOffsetInSection + pPE_Image_Section_Header[unNumberOfCurrentSection].VirtualAddress + (unsigned int)pPE_ImageBuffer_Address;
					break;

				}
			}
		}
	}
	
	return TRUE;
	
F:
	return FALSE;
	
}


