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
	blStatus =  fnGet_PE_DOS_Header_Address(pImageBuffer, &pPE_DOS_Header);
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
	memcpy(pFileBuffer, pImageBuffer, pPE_NT_Header->OptionalHeader.SizeOfHeaders * sizeof(char));
	
	
	
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
	//转换地址
	//判断FOA在哪个段
	for (unNumberOfCurrentSection = 0; unNumberOfCurrentSection < unNumberOfSections; unNumberOfCurrentSection++)
	{
		//判断FOA是否在当前段中。
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
			//如果在当前区段
			//计算RVA
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
//函数名：fnGet_PE_NT_Header_Address_By_FileBuffer
//功能：通过FileBuffer直接获取PE_NT_Header的地址
//参数1：const void* pFileBuffer
//参数1说明：传入值，FileBuffer的地址
//参数2：PE_NT_HEADER** ppPE_NT_Header
//参数2说明：传出值，待获取PE_NT_Header的指针的指针
//返回值：如果获取成功，返回TRUE，如果获取失败，返回FALSE
//***********************************
bool fnGet_PE_NT_Header_Address_By_FileBuffer(const void* pFileBuffer,
										   PE_NT_HEADER** ppPE_NT_Header)
{
	PE_DOS_HEADER* pPE_DOS_Header = NULL;
	//状态量
	bool blStatus = FALSE;
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pFileBuffer的值为空\r\n");
		}
		goto F;
	}
	//获取PE_DOS_HEADER
	blStatus = fnGet_PE_DOS_Header_Address(pFileBuffer, &pPE_DOS_Header);
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_DOS_Header获取失败\r\n");
		}
		goto F;
	}
	//获取PE_NT_HEADER
	blStatus = fnGet_PE_NT_Header_Address(pPE_DOS_Header, ppPE_NT_Header);
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("ppPE_NT_Header获取失败\r\n");
		}
		goto F;
	}


	return TRUE;
F:
	return FALSE;
}


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
											void** ppAddress)
{
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header = NULL;
	PE_NT_HEADER* pPE_NT_Header = NULL;
	//节的数量
	unsigned int unNumberOfSection = 0;
	//状态量
	bool blStatus = FALSE;
	//代码段的索引编号
	unsigned int unIndexOfCodeSection = 0;
	//循环计数
	unsigned int unCount = 0;
	//当前搜索的地址
	char* pCurrentMemory = NULL;
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pFileBuffer 的值为空\r\n");
		}
		goto F;
	}

	//获取PE_NT_Header
	blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(pFileBuffer, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("pPE_NT_Header 获取失败\r\n");
		}
		goto F;
	}
	//获取PE_SECTION_HEADER
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &unNumberOfSection);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("pPE_Image_Section_Header 获取失败\r\n");
		}
		goto F;
	}
	if (unNumberOfSection == 0)
	{
		if (__DEBUG)
		{
			printf("unNumberOfSection 获取失败\r\n");
		}
		goto F;
	}
	//找可执行区段
	for (unIndexOfCodeSection = 0; unIndexOfCodeSection < unNumberOfSection; unIndexOfCodeSection ++)
	{
		if ( // Section is executable.(该块可执行)]
			pPE_Image_Section_Header[unIndexOfCodeSection].Characteristics & unCharacteristic
			)
		{
			//找到代码段
			//初始化要搜索的区域指针
			pCurrentMemory =
				(char *)((unsigned int)pFileBuffer 
				+ pPE_Image_Section_Header[unIndexOfCodeSection].PointerToRawData
					+ (unsigned int)pPE_Image_Section_Header[unIndexOfCodeSection].Misc.VirtualSize);
			//代码段实际数据后搜索空余0区，看是否够存放ShellCode
			for (unCount = 0; unCount < unNeedSize; unCount ++)
			{

				//判断是否是最后一个节
				if (unIndexOfCodeSection < unNumberOfSection - 1)
				{
					//如果不是最后一个节，继续判断是否越界
					if ((unsigned int)(pCurrentMemory + unCount) >= 
						(pPE_Image_Section_Header[unIndexOfCodeSection + 1].PointerToRawData + (unsigned int)pFileBuffer))
					{
						pCurrentMemory = NULL;
						//跳出本次循环继续搜索下一个节
						
						break;
					}
					if (*(pCurrentMemory + unCount) != 0x0)
					{
						//如果找到一个不为零的数据，继续向搜索，言外之意，一定要找到一个连续不为0的区域
						pCurrentMemory = pCurrentMemory + unCount + 1;
						unCount = 0;
					}
				}
				else
				{
					//如果是最后一个节
					//判断他是否越过了当前节的界限
					if ((unsigned int)(pCurrentMemory + unCount) >= 
						(pPE_Image_Section_Header[unIndexOfCodeSection].PointerToRawData 
						+ (unsigned int)pFileBuffer 
						+ pPE_Image_Section_Header[unIndexOfCodeSection].SizeOfRawData))
					{
						//如果超过了自己的界限
						if (__DEBUG)
						{
							printf("找遍整个FileBuffer的代码段，没发现这样的空间。\r\n");
						}
						goto F;				
					}
				}
			}

			//判断是否找到符合条件的地址
			if (pCurrentMemory != NULL)
			{
				//找到了就跳出循环
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
//函数名：fnCalculate_New_AddressOfEntryPoint
//功能：根据给定的FileImage地址，计算新的程序入口点
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
										 unsigned int* punNewAddressOfEntryPoint)
{
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header = NULL;
	PE_NT_HEADER* pPE_NT_Header = NULL;	
	//节的数量
	unsigned int unNumberOfSection = 0;
	//状态量
	bool blStatus = FALSE;
	//当前节区
	unsigned int unCurrentSectionIndex = 0;
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pFileBuffer 的值为空\r\n");
		}
		goto F;
	}
	//获取PE_NT_Header
	blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(pFileBuffer, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("pPE_NT_Header 获取失败\r\n");
		}
		goto F;
	}
	//获取PE_SECTION_HEADER
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &unNumberOfSection);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("pPE_Image_Section_Header 获取失败\r\n");
		}
		goto F;
	}
	if (unNumberOfSection == 0)
	{
		if (__DEBUG)
		{
			printf("unNumberOfSection 获取失败\r\n");
		}
		goto F;
	}
	//循环搜索需要修改的地址在哪个节区中
	for (unCurrentSectionIndex = 0; unCurrentSectionIndex < unNumberOfSection; unCurrentSectionIndex ++)
	{
		//判断是否在当前节中
		if ((unNewEntryAddress 
			>= ((unsigned int)pFileBuffer + pPE_Image_Section_Header[unCurrentSectionIndex].PointerToRawData)) 
			&& 
			(unNewEntryAddress 
			< ((unsigned int)pFileBuffer + pPE_Image_Section_Header[unCurrentSectionIndex].PointerToRawData + pPE_Image_Section_Header[unCurrentSectionIndex].SizeOfRawData)) )
		{
			//是在当前节中
			//计算在内存中的入口点
			*punNewAddressOfEntryPoint = 
				unNewEntryAddress 
				- (unsigned int)pFileBuffer 
				- pPE_Image_Section_Header[unCurrentSectionIndex].PointerToRawData
				+ pPE_Image_Section_Header[unCurrentSectionIndex].VirtualAddress;
			//跳出循环
			break;
			
		}
		else
		{
			//不再当前节区
			*punNewAddressOfEntryPoint = NULL;
		}
	}
	return TRUE;
	
F:
	return FALSE;
	
	
}

//***********************************
//函数名：fnCalculate_AddressOf_E8_E9
//功能：计算E8(CALL) E9(JMP)在ShellCode中填写的地址
//参数1：unsigned int unCurrentAddress
//参数1说明：传入值，E8,E9当前在PE文件运行中的地址，言外之意，需要已经和ImageBase运算过。
//参数2：unsigned int unTargetAddress
//参数2说明：传入值，在PE文件运行中需要跳转的地址，言外之意，需要已经和ImageBase运算过。
//参数3：unsigned int* punCalculatedAddress
//参数3说明：传出值，计算后的值的地址
//返回值：如果计算成功，就返回TRUE，如果计算失败就返回FALSE
//***********************************

bool fnCalculate_AddressOf_E8_E9(unsigned int unCurrentAddress,
								 unsigned int unTargetAddress,
								 unsigned int* punCalculatedAddress)
{
	if (punCalculatedAddress == NULL)
	{
		if (__DEBUG)
		{
			printf("punCalculatedAddress 为NULL \r\n");
		}
		goto F;

	}
	*punCalculatedAddress = unTargetAddress - unCurrentAddress - 5;
	
	return TRUE;
	
F:
	return FALSE;
}


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
									unsigned int unSizeOfShellCode)
{
	if (pTargetAddress == NULL)
	{
		if (__DEBUG)
		{
			printf("pTargetAddress 为NULL\r\n");
		}
		goto F;
	}
	if (pShellCode == NULL)
	{
		if (__DEBUG)
		{
			printf("pShellCode 为NULL\r\n");
		}
		goto F;
	}
	if (unSizeOfShellCode == 0)
	{
		if (__DEBUG)
		{
			printf("unSizeOfShellCode 为 0\r\n");
		}
		goto F;
	}
	memcpy(pTargetAddress, pShellCode, unSizeOfShellCode * sizeof(char));

	return TRUE;
F:
	return FALSE;

}
