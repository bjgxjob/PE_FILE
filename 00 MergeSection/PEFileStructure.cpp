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
										  //参数4：const void* pImageBuffer_Address
										  //参数4说明：传入值，unFOA所在的FileBuffer的地址
										  //返回值：如果转成功，返回TRUE，转换失败，返回FALSE
										  //***********************************
										  bool fnRVA_Convert_FOA(unsigned int unRAV, 
											  unsigned* unFOA, 
											  const void* pImageBuffer_Address,
											  const void* pFileBuffer_Address)
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
											  if (pImageBuffer_Address == NULL)
											  {
												  if (__DEBUG)
												  {
													  printf("pImageBuffer_Address为NULL.\r\n");
												  }
												  goto F;
											  }
											  if (pFileBuffer_Address == NULL)
											  {
												  if (__DEBUG)
												  {
													  printf("pFileBuffer_Address 为NULL.\r\n");
												  }
												  goto F;
											  }
											  //获取PE_DOS_HEADER
											  blStatus =  fnGet_PE_DOS_Header_Address(pImageBuffer_Address, &pPE_DOS_Header);
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
												  if ((unRAV - (unsigned int)pImageBuffer_Address) < pPE_NT_Header->OptionalHeader.SizeOfHeaders)
												  {
													  *unFOA = unRAV - (unsigned int)pImageBuffer_Address;
													  break;
												  }
												  //判断这个值是否比当前节的起始地址大
												  if (unRAV >= (pPE_Image_Section_Header[unNumberOfCurrentSection].VirtualAddress + (unsigned int)pImageBuffer_Address))
												  {
													  //判断是否为最后一个节
													  if (unNumberOfCurrentSection < unNumberOfSections - 1)
													  {
														  //不是最后一个节，继续判断是否比下一个节的开始地址小
														  if (unRAV < (pPE_Image_Section_Header[unNumberOfCurrentSection + 1].VirtualAddress + (unsigned int)pImageBuffer_Address))
														  {
															  //计算在节中的偏移
															  unDataOffsetInSection = unRAV - (unsigned int)pImageBuffer_Address - pPE_Image_Section_Header[unNumberOfCurrentSection].VirtualAddress;
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
															  *unFOA = unDataOffsetInSection + pPE_Image_Section_Header[unNumberOfCurrentSection].PointerToRawData + (unsigned)pFileBuffer_Address;
															  break;
														  }
													  }
													  else
													  {
														  //如果是最后一个节，就判断是否在最后一个节中
														  if (unRAV <= (unsigned int)pImageBuffer_Address + pPE_NT_Header->OptionalHeader.SizeOfImage)
														  {
															  unDataOffsetInSection = unRAV - (unsigned int)pImageBuffer_Address - pPE_Image_Section_Header[unNumberOfCurrentSection].VirtualAddress;
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
															  *unFOA = unDataOffsetInSection + pPE_Image_Section_Header[unNumberOfCurrentSection].PointerToRawData + (unsigned)pFileBuffer_Address;
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
												   void** ppAddress)
{
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header = NULL;
	PE_NT_HEADER* pPE_NT_Header = NULL;
	//节的数量
	unsigned int unNumberOfSection = 0;
	//状态量
	bool blStatus = FALSE;
	//当前搜索的地址
	if (pImageBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("pFileBuffer 的值为空\r\n");
		}
		goto F;
	}
	
	//获取PE_NT_Header
	blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(pImageBuffer, &pPE_NT_Header);
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
	//判断是否有这个节
	if (unIndexOfSection > unNumberOfSection)
	{
		if (__DEBUG)
		{
			printf("要求寻找的节不存在。\r\n");
		}
		goto F;
	}
	
	//判断是否有空间存放数据
	if ((int)(pPE_Image_Section_Header[unIndexOfSection].SizeOfRawData - pPE_Image_Section_Header[unIndexOfSection].Misc.VirtualSize) < (int)unNeedSize)
	{
		if (__DEBUG)
		{
			printf("当前节区没有足够的大小存储数据\r\n");
		}
		goto F;
	}
	//得到空间地址
	*ppAddress = (void*)(pPE_Image_Section_Header[unIndexOfSection].VirtualAddress 
		+ 
		pPE_Image_Section_Header[unIndexOfSection].Misc.VirtualSize
		+
		(unsigned int)pImageBuffer);
	//修改节区属性
	pPE_Image_Section_Header[unIndexOfSection].Characteristics =
		pPE_Image_Section_Header[unIndexOfSection].Characteristics
		| unCharacteristic;
	
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
	if (punNewAddressOfEntryPoint == NULL)
	{
		if (__DEBUG)
		{
			printf("计算OEP失败.\r\n");
		}
		goto F;
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
							unsigned int unSizeOfData)
{
	if (pTargetAddress == NULL)
	{
		if (__DEBUG)
		{
			printf("pTargetAddress 为空\r\n");
		}
		goto F;
	}
	if (pData == NULL)
	{
		if (__DEBUG)
		{
			printf("pData 为空\r\n");
		}
		goto F;
	}
	if (unSizeOfData == 0)
	{
		if (__DEBUG)
		{
			printf("unSizeOfData 为空\r\n");
		}
		goto F;
	}
	memcpy(pTargetAddress, pData, unSizeOfData);
	return TRUE;
F:
	return FALSE;
}


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
				   )
{
	//PE_DOS_HEADER
	PE_DOS_HEADER* pPE_DOS_Header = NULL;
	//PE_NT_HEADER
	PE_NT_HEADER* pPE_NT_Header = NULL;
	//PE_IMAGE_SECTION_HEADER
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header = NULL;
	//Number Of Sections
	unsigned uNumberOfSections = 0;
	//PE_DOS_HEADER_New
	PE_DOS_HEADER* pPE_DOS_Header_New = NULL;
	//PE_NT_HEADER_New
	PE_NT_HEADER* pPE_NT_Header_New = NULL;
	//PE_IMAGE_SECTION_HEADER_New
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header_New = NULL;
	//Number Of Sections_New
	unsigned uNumberOfSections_New = 0;
	//EmptySpace
	unsigned uEmptySpace = 0;
	//Status
	bool blStatus = FALSE;
	//Circulate Variable
	unsigned uCount = 0;
	//Switch Branch
	unsigned uBranch = 0xFF;
	
	
	if (lpFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: lpImageBuffer \r\n");
		}
		goto F;
	}
	if (uSizeOfSection == 0)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: uSizeOfSection \r\n");
		}
		goto F;
	}
	if (plpNewFileBuffer == 0)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: plpNewFileBuffer \r\n");
		}
		goto F;
	}
	if (uSizeOfFileBuffer == 0)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: puSizeOfFileBuffer \r\n");
		}
		goto F;
	}
	if (puSizeOfNewFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: puSizeOfNewFileBuffer \r\n");
		}
		goto F;
	}
	
	
	
	//Get PE_DOS_Header Address
	pPE_DOS_Header = (PE_DOS_HEADER*)lpFileBuffer;
	
	//Get PE_NT_Header Address
	blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(lpFileBuffer, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: fnGet_PE_NT_Header_Address_By_FileBuffer \r\n");
		}
		goto F;
	}
	
	//Get PE_Image_Section_Header_Arry
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &uNumberOfSections);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: fnGetPE_Image_Section_Header_Structure_Array \r\n");
		}
		goto F;
	}
	//verified uSizeOfFileBuffer
	if (uSizeOfFileBuffer % pPE_NT_Header->OptionalHeader.FileAlignment != 0)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: uSizeOfFileBuffer illegal. PE_NT_Header->OptionalHeader.FileAlignment:%x \r\n", 
				pPE_NT_Header->OptionalHeader.FileAlignment);
		}
		goto F;
	}
	//Get empty space
	uEmptySpace = 
		pPE_NT_Header->OptionalHeader.SizeOfHeaders 
		- 
		((unsigned)&pPE_Image_Section_Header[uNumberOfSections] - (unsigned)lpFileBuffer);
	//Verify whether it is have enough space to save new section header
	if (uEmptySpace >= sizeof(PE_IMAGE_SECTION_HEADER) * 2)
	{
		for (uCount = 0; uCount < sizeof(PE_IMAGE_SECTION_HEADER) * 2; uCount++)
		{
			//Verify each of byte is zero.
			if ( *((char*)&pPE_Image_Section_Header[uNumberOfSections] + uCount) != 0)
			{
				//If not, Break out.
				if (pPE_DOS_Header->e_lfanew - sizeof(PE_DOS_HEADER) >= sizeof(PE_IMAGE_SECTION_HEADER))
				{
					uBranch = ADD_SECTION_NO_SPACE_BUT_CAN_MOVE_UP;
				}
				else
				{
					uBranch = ADD_SECTION_ONLY_AMPLIFY_LAST_SECTION;
				}
				break;
			}
			else
			{
				uBranch = ADD_SECTION_HAVE_SPACE_ALL_ZERO;
			}
		}
	}
	else
	{
		
	}
	
	switch(uBranch)
	{
	case ADD_SECTION_HAVE_SPACE_ALL_ZERO:
		{
			//malloc plpNewBuffer
			*plpNewFileBuffer = malloc(uSizeOfFileBuffer + uSizeOfSection);
			if (*plpNewFileBuffer != NULL)
			{
				memset(*plpNewFileBuffer, 0x0, uSizeOfFileBuffer + uSizeOfSection);
			}
			else
			{
				if (__DEBUG)
				{
					printf("fnAdd_Section: plpNewFileBuffer \r\n");
				}
				goto F;
			}
			
			
			//Initialized puSizeOfNewFileBuffer
			*puSizeOfNewFileBuffer = uSizeOfFileBuffer + uSizeOfSection;
			//Initialized NewBuffer
			memcpy(*plpNewFileBuffer, lpFileBuffer, uSizeOfFileBuffer);
			//Get New PE Headers	
			//Get NEW_PE_DOS_Header Address
			pPE_DOS_Header_New = (PE_DOS_HEADER*)*plpNewFileBuffer;
			
			//Get NEW PE_NT_Header Address
			blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(*plpNewFileBuffer, &pPE_NT_Header_New);
			if (blStatus != TRUE)
			{
				if (__DEBUG)
				{
					printf("fnAdd_Section: fnGet_PE_NT_Header_Address_By_FileBuffer \r\n");
				}
				goto F;
			}
			
			//Get NEW_PE_Image_Section_Header_Arry
			blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header_New, &pPE_Image_Section_Header_New, &uNumberOfSections_New);
			if (blStatus != TRUE)
			{
				if (__DEBUG)
				{
					printf("fnAdd_Section: fnGetPE_Image_Section_Header_Structure_Array \r\n");
				}
				goto F;
			}
			
			//Modify New Section Headers
			//Characteristics
			pPE_Image_Section_Header_New[uNumberOfSections_New].Characteristics = uCharacteristics;
			//Misc
			pPE_Image_Section_Header_New[uNumberOfSections_New].Misc.PhysicalAddress = uSizeOfSection;
			//Name
			memcpy(pPE_Image_Section_Header_New[uNumberOfSections_New].Name, szName, 8);
			//uNumberOfSections_New
			pPE_Image_Section_Header_New[uNumberOfSections_New].NumberOfLinenumbers
				=
				pPE_Image_Section_Header_New[uNumberOfSections_New - 1].NumberOfLinenumbers;
			//NumberOfRelocations
			pPE_Image_Section_Header_New[uNumberOfSections_New].NumberOfRelocations
				=
				pPE_Image_Section_Header_New[uNumberOfSections_New - 1].NumberOfRelocations;
			//PointerToLinenumbers
			pPE_Image_Section_Header_New[uNumberOfSections_New].PointerToLinenumbers
				=
				pPE_Image_Section_Header_New[uNumberOfSections_New - 1].PointerToLinenumbers;
			//PointerToRawData
			pPE_Image_Section_Header_New[uNumberOfSections_New].PointerToRawData
				=
				pPE_Image_Section_Header_New[uNumberOfSections_New - 1].PointerToRawData 
				+
				pPE_Image_Section_Header_New[uNumberOfSections_New - 1].SizeOfRawData;
			//PointerToLinenumbers
			pPE_Image_Section_Header_New[uNumberOfSections_New].PointerToRelocations
				=
				pPE_Image_Section_Header_New[uNumberOfSections_New - 1].PointerToRelocations;
			//SizeOfRawData
			if (uSizeOfSection % pPE_NT_Header_New->OptionalHeader.FileAlignment != 0)
			{
				pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData 
					=
					pPE_NT_Header_New->OptionalHeader.FileAlignment * (uSizeOfSection / pPE_NT_Header_New->OptionalHeader.FileAlignment + 1);
			}
			else
			{
				pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData = uSizeOfSection;
			}
			//VirtualAddress
			pPE_Image_Section_Header_New[uNumberOfSections_New].VirtualAddress = 
				pPE_NT_Header->OptionalHeader.SizeOfImage;
			
			//Modify NT Headers
			//NumberOfSections
			pPE_NT_Header_New->FileHeader.NumberOfSections ++;
			//SizeOfImage
			pPE_NT_Header_New->OptionalHeader.SizeOfImage = 
				pPE_Image_Section_Header_New[uNumberOfSections_New].VirtualAddress 
				+ 
				((
				pPE_Image_Section_Header_New[uNumberOfSections_New].Misc.VirtualSize 
				>
				pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData
				)
				?
				pPE_Image_Section_Header_New[uNumberOfSections_New].Misc.VirtualSize
				:
			pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData);
			if (pPE_NT_Header_New->OptionalHeader.SizeOfImage % pPE_NT_Header->OptionalHeader.SectionAlignment != 0)
			{
				pPE_NT_Header_New->OptionalHeader.SizeOfImage = 
					(pPE_NT_Header_New->OptionalHeader.SizeOfImage / pPE_NT_Header->OptionalHeader.SectionAlignment + 1)
					*
					pPE_NT_Header->OptionalHeader.SectionAlignment;
			}
			
			break;
			}
		case ADD_SECTION_NO_SPACE_BUT_CAN_MOVE_UP:
			{
				//初始化新PE文件的大小
				*puSizeOfNewFileBuffer = uSizeOfFileBuffer + uSizeOfSection;
				//申请新PE文件的FileImage
				*plpNewFileBuffer = malloc(*puSizeOfNewFileBuffer);
				//判断申请是否成功
				if (*plpNewFileBuffer == NULL)
				{
					if (__DEBUG)
					{
						printf("plpNewFileBuffer 为空.\r\n");
						goto F;
					}
				}
				else //否则初始化
				{
					memset(*plpNewFileBuffer, 0x0,*puSizeOfNewFileBuffer);
					
				}
				//上移一个Section_Head的大小
				//COPY PE_DOS_HEADER
				memcpy(*plpNewFileBuffer, lpFileBuffer, sizeof(PE_DOS_HEADER));
				//获取新PE结构的DOS头
				pPE_DOS_Header_New = (PE_DOS_HEADER*)*plpNewFileBuffer;
				//修改e_lfanew数据的值
				pPE_DOS_Header_New->e_lfanew = pPE_DOS_Header_New->e_lfanew - sizeof(PE_IMAGE_SECTION_HEADER);
				//COPY PE_NT_HEADER
				memcpy(
					(void*)((int)(*plpNewFileBuffer) + pPE_DOS_Header_New->e_lfanew), 
					pPE_NT_Header, 
					sizeof(pPE_NT_Header->Signature) + sizeof(pPE_NT_Header->FileHeader) + pPE_NT_Header->FileHeader.SizeOfOptionalHeader
					);
				//获取新PE的NT_Header
				blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(*plpNewFileBuffer, &pPE_NT_Header_New);
				if (blStatus != TRUE)
				{
					if (__DEBUG)
					{
						printf("fnAddSection:获取新PE的NT_Header失败.\r\n");
					}
					goto F;
				}
				//获取带添加的Section Header的索引
				uNumberOfSections_New = pPE_NT_Header_New->FileHeader.NumberOfSections;
				//从原来的PE文件复制各个Section_Header到新的PE文件
				memcpy(
					(void*)((int)pPE_NT_Header_New + sizeof(pPE_NT_Header_New->Signature) + sizeof(PE_FILE_HEADER) + pPE_NT_Header_New->FileHeader.SizeOfOptionalHeader),
					pPE_Image_Section_Header,
					sizeof(PE_IMAGE_SECTION_HEADER) * pPE_NT_Header->FileHeader.NumberOfSections
					);
				//获取新PE的Section_Header
				pPE_Image_Section_Header_New = 
					(PE_IMAGE_SECTION_HEADER*)((int)pPE_NT_Header_New + sizeof(pPE_NT_Header_New->Signature) + sizeof(PE_FILE_HEADER) + pPE_NT_Header_New->FileHeader.SizeOfOptionalHeader);
				//添加新的Section_Header
				//Name
				memcpy(pPE_Image_Section_Header_New[uNumberOfSections_New].Name, szName, sizeof(char) * 8);
				//Misc
				//Misc中的值是未对齐前的值
				pPE_Image_Section_Header_New[uNumberOfSections_New].Misc.PhysicalAddress = uSizeOfSection;
				
				//VirtualAddress
				pPE_Image_Section_Header_New[uNumberOfSections_New].VirtualAddress = pPE_NT_Header_New->OptionalHeader.SizeOfImage;
				//SizeOfRawData
				if (uSizeOfSection % pPE_NT_Header_New->OptionalHeader.FileAlignment != 0)
				{
					pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData 
						=
						pPE_NT_Header_New->OptionalHeader.FileAlignment * (uSizeOfSection / pPE_NT_Header_New->OptionalHeader.FileAlignment + 1);
				}
				else
				{
					pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData = uSizeOfSection;
				}
				//PointerToRawData
				pPE_Image_Section_Header_New[uNumberOfSections_New].PointerToRawData 
					= 
					pPE_Image_Section_Header_New[uNumberOfSections_New - 1].PointerToRawData + pPE_Image_Section_Header_New[uNumberOfSections_New - 1].SizeOfRawData;
				//PointerToRelocations
				pPE_Image_Section_Header_New[uNumberOfSections_New].PointerToRelocations = pPE_Image_Section_Header_New[uNumberOfSections_New - 1].PointerToRelocations;
				//PointerToLineNumbers
				pPE_Image_Section_Header_New[uNumberOfSections_New].PointerToLinenumbers = pPE_Image_Section_Header_New[uNumberOfSections_New - 1].PointerToLinenumbers;
				//NumberOfRelocations
				pPE_Image_Section_Header_New[uNumberOfSections_New].NumberOfRelocations = pPE_Image_Section_Header_New[uNumberOfSections_New - 1].NumberOfRelocations;
				//NumberOfLinenumbers
				pPE_Image_Section_Header_New[uNumberOfSections_New].NumberOfLinenumbers = pPE_Image_Section_Header_New[uNumberOfSections_New - 1].NumberOfLinenumbers;
				//Characteristic
				pPE_Image_Section_Header_New[uNumberOfSections_New].Characteristics = uCharacteristics;
				
				//修改新PE的NT头中的信息
				//NumberOfSection
				pPE_NT_Header_New->FileHeader.NumberOfSections ++;
				//SizeOfImage
				//先计算出SizeOfImage的大小
				pPE_NT_Header_New->OptionalHeader.SizeOfImage = 
					pPE_Image_Section_Header_New[uNumberOfSections_New].VirtualAddress 
					+ 
					((pPE_Image_Section_Header_New[uNumberOfSections_New].Misc.PhysicalAddress > pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData) 
					?
					pPE_Image_Section_Header_New[uNumberOfSections_New].Misc.PhysicalAddress
					:
				pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData);
				//判断是否内存对齐
				if (pPE_NT_Header_New->OptionalHeader.SizeOfImage % pPE_NT_Header_New->OptionalHeader.SectionAlignment != 0)
				{
					pPE_NT_Header_New->OptionalHeader.SizeOfImage = 
						(pPE_NT_Header_New->OptionalHeader.SizeOfImage % pPE_NT_Header_New->OptionalHeader.SectionAlignment + 1)
						*
						pPE_NT_Header_New->OptionalHeader.SectionAlignment;
				}
				//复制剩余的数据进新PE
				memcpy(
					&pPE_Image_Section_Header_New[uNumberOfSections_New + 1], 
					&pPE_Image_Section_Header[uNumberOfSections_New], 
					uSizeOfFileBuffer - ((int)&pPE_Image_Section_Header[uNumberOfSections_New] - (int)lpFileBuffer));
				break;
			}
			case ADD_SECTION_ONLY_AMPLIFY_LAST_SECTION:
				{
					//扩大最后一个节区
					*puSizeOfNewFileBuffer = uSizeOfFileBuffer + uSizeOfSection;
					//申请新FILEBUFFER的内存空间
					*plpNewFileBuffer = malloc(*puSizeOfNewFileBuffer);
					//验证是否分配成功
					if (*plpNewFileBuffer == NULL)
					{
						if (__DEBUG)
						{
							printf("fnAddSection: plpNewFileBuffer 为空.\r\n");
						}
						goto F;
					}
					//初始化内存空间
					memset(*plpNewFileBuffer, 0x0, *puSizeOfNewFileBuffer);
					//拷贝旧PE到新PE
					memcpy(*plpNewFileBuffer, lpFileBuffer, uSizeOfFileBuffer);
					//得到新PE的各种头信息
					pPE_DOS_Header_New = (PE_DOS_HEADER *)*plpNewFileBuffer;
					blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(*plpNewFileBuffer, &pPE_NT_Header_New);
					if (blStatus != TRUE)
					{
						if (__DEBUG)
						{
							printf("fnAddSection: fnGet_PE_NT_Header_Address_By_FileBuffer失败。\r\n");
						}
						goto F;
					}
					blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header_New, &pPE_Image_Section_Header_New, &uNumberOfSections_New);
					if (blStatus != TRUE)
					{
						if (__DEBUG)
						{
							printf("fnAddSection: fnGetPE_Image_Section_Header_Structure_Array 失败.\r\n");
						}
						goto F;
					}
					//找到最后一节
					//修改实际大小
					pPE_Image_Section_Header_New[uNumberOfSections_New - 1].Misc.PhysicalAddress += uSizeOfSection;
					//修改在文件中的大小
					if (uSizeOfSection % pPE_NT_Header_New->OptionalHeader.FileAlignment != 0)
					{
						pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData 
							=
							pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData
							+
							pPE_NT_Header_New->OptionalHeader.FileAlignment * (uSizeOfSection / pPE_NT_Header_New->OptionalHeader.FileAlignment + 1);
					}
					else
					{
						pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData += uSizeOfSection;
					}
					//修改属性
					pPE_Image_Section_Header_New[uNumberOfSections_New - 1].Characteristics = pPE_Image_Section_Header_New[uNumberOfSections_New - 1].Characteristics | uCharacteristics;
					//修改PE_NT_HEADER的信息
					//先计算出SizeOfImage的值
					pPE_NT_Header_New->OptionalHeader.SizeOfImage += uSizeOfSection;
					//判断是否符合内存对齐
					if (pPE_NT_Header_New->OptionalHeader.SizeOfImage % pPE_NT_Header_New->OptionalHeader.SectionAlignment != 0)
					{
						pPE_NT_Header_New->OptionalHeader.SizeOfImage = 
							(pPE_NT_Header_New->OptionalHeader.SizeOfImage / pPE_NT_Header_New->OptionalHeader.SectionAlignment + 1)
							*
							(pPE_NT_Header_New->OptionalHeader.SectionAlignment);

					}
					break;
						
				}
			default:
				break;
				
				
				
				
		}
		
		return TRUE;
		
		
		
		
		
		
F:
		if (*plpNewFileBuffer != NULL)
		{
			free(*plpNewFileBuffer);
			*plpNewFileBuffer = NULL;
		}
		return FALSE;
}

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
					)
{
	int nNumberOfSection = -1;
	bool blStatus = FALSE;
	PE_DOS_HEADER* pPE_DOS_HEADER = NULL;
	PE_NT_HEADER* pPE_NT_HEADER = NULL;
	PE_IMAGE_SECTION_HEADER* pPE_IMAGE_SECTION_HEADER = NULL;
	int i = 0;
	if (lpImageBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("fnMergeSection: lpImageBuffer 为空。\r\n");
		}
		goto F;
	}
	

	//获取PE头
	pPE_DOS_HEADER = (PE_DOS_HEADER *)lpImageBuffer;
	blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(lpImageBuffer, &pPE_NT_HEADER);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnMergeSection: fnGet_PE_NT_Header_Address_By_FileBuffer 出错。\r\n");
		}
		goto F;
	}
	//获取节信息
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_HEADER, &pPE_IMAGE_SECTION_HEADER, (unsigned *)&nNumberOfSection);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnMergeSection: fnGetPE_Image_Section_Header_Structure_Array 出错。\r\n");
		}
	}
	//判断传入的节信息是否正确
	if (!(0 <= nMergeSection1 && nMergeSection1 < nNumberOfSection && nMergeSection1 < nMergeSection2))
	{
		if (__DEBUG)
		{
			printf("fnMergeSection: nMergeSection1 出错。\r\n");
		}
		goto F;
	}
	if (!(0 <= nMergeSection2 && nMergeSection2 < nNumberOfSection && nMergeSection1 < nMergeSection2))
	{
		if (__DEBUG)
		{
			printf("fnMergeSection: nMergeSection2 出错。\r\n");
		}
		goto F;
	}
	//合并节开始
	//修改Section_Header的信息
	pPE_IMAGE_SECTION_HEADER[nMergeSection1].Misc.PhysicalAddress 
		=
	pPE_IMAGE_SECTION_HEADER[nMergeSection1].SizeOfRawData 
		=
		pPE_IMAGE_SECTION_HEADER[nMergeSection2].VirtualAddress 
		-
		pPE_IMAGE_SECTION_HEADER[nMergeSection1].VirtualAddress
		+
		fnGetMaxNumber(pPE_IMAGE_SECTION_HEADER[nMergeSection2].Misc.PhysicalAddress, pPE_IMAGE_SECTION_HEADER[nMergeSection2].SizeOfRawData);
	//对齐参数
	if (pPE_IMAGE_SECTION_HEADER[nMergeSection1].SizeOfRawData % pPE_NT_HEADER->OptionalHeader.FileAlignment != 0)
	{
		pPE_IMAGE_SECTION_HEADER[nMergeSection1].SizeOfRawData 
			= 
			pPE_IMAGE_SECTION_HEADER[nMergeSection1].Misc.PhysicalAddress 
			= 
			fnAlign(pPE_NT_HEADER->OptionalHeader.FileAlignment, pPE_IMAGE_SECTION_HEADER[nMergeSection1].SizeOfRawData);
	}
	//修改节的属性
	pPE_IMAGE_SECTION_HEADER[nMergeSection1].Characteristics = pPE_IMAGE_SECTION_HEADER[nMergeSection1].Characteristics | pPE_IMAGE_SECTION_HEADER[nMergeSection2].Characteristics;
	//移动Section Header
	//判断是否是最后一个节合并
	if (!((nMergeSection2 + 1) == nNumberOfSection))
	{
		
		//如果不是最后一个节合并，其余的节头依次上移并且清零
		for (i = nMergeSection2; i < nNumberOfSection - 1; i++)
		{
			pPE_IMAGE_SECTION_HEADER[i + 1].PointerToRawData = pPE_IMAGE_SECTION_HEADER[i - 1].SizeOfRawData + pPE_IMAGE_SECTION_HEADER[i - 1].PointerToRawData;
			memcpy(&pPE_IMAGE_SECTION_HEADER[i], &pPE_IMAGE_SECTION_HEADER[i + 1], sizeof(PE_IMAGE_SECTION_HEADER));
			memset(&pPE_IMAGE_SECTION_HEADER[i + 1], 0x0, sizeof(PE_IMAGE_SECTION_HEADER));
		}
	}
	else
	{
		//如果是最后一节，直接把节头清零
		memset(&pPE_IMAGE_SECTION_HEADER[nMergeSection2], 0x0, sizeof(PE_IMAGE_SECTION_HEADER));
	}
	//修改NT_HEADER中的值
	pPE_NT_HEADER->FileHeader.NumberOfSections --;


	return TRUE;
F:
	return FALSE;
}
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
				 IN unsigned unNumber)
{
	unsigned unRet = 0;;
	if (unNumber % unAlign != 0)
	{
		unRet = (unNumber / unAlign + 1) * unAlign;
	}
	else
	{
		unRet = unNumber;
	}
	return unRet;
}
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
						IN unsigned unNumber2)
{
	unsigned unRet = 0;
	if (unNumber1 >= unNumber2)
	{
		unRet = unNumber1;
	}
	else
	{
		unRet = unNumber2;
	}
	return unRet;
}

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
						IN unsigned unNumber2)
{
	unsigned unRet = 0;
	if (unNumber1 <= unNumber2)
	{
		unRet = unNumber1;
	}
	else
	{
		unRet = unNumber2;
	}
	return unRet;
}
//***********************************
//函数名：fnAllocate_ImageBuffer
//功能： 根据FileBuffer分配ImageBuffer的空间，并且初始化。
//参数1：IN void* pFileBuffer
//参数1说明： FileBuffer的地址
//返回值：如果成功，返回分配的地址，如果失败，返回 NULL
//***********************************

void* fnAllocate_ImageBuffer( IN void* pFileBuffer)
{
	void* pImageBuffer = NULL;
	bool blStatus = FALSE;
	PE_NT_HEADER* pPE_NT_HEADER = NULL;
	if (pFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf(" fnAllocate_ImageBuffer: pFileBuffer 为空.\r\n");
		}
		goto F;
	}
	blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(pFileBuffer, &pPE_NT_HEADER);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf(" fnAllocate_ImageBuffer: fnGet_PE_NT_Header_Address_By_FileBuffer 失败.\r\n");
		}
		goto F;
	}
	pImageBuffer = malloc(pPE_NT_HEADER->OptionalHeader.SizeOfImage);
	if (pImageBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf(" fnAllocate_ImageBuffer: pImageBuffer 分配内存失败.\r\n");
		}
		goto F;
	}
	memset(pImageBuffer, 0x0, pPE_NT_HEADER->OptionalHeader.SizeOfImage);
	return pImageBuffer;



F:
	if (pImageBuffer != NULL)
	{
		free(pImageBuffer);
		pImageBuffer = NULL;
	}
	return NULL;
}

//***********************************
//函数名：fnGet_FileBuffer_Size_By_ImageBuffer
//功能：通过ImageBuffer获取FileBuffer的大小
//参数1：IN void* pImageBuffer
//参数1说明：ImageBuffer的地址
//返回值：如果获取成功，返回FileBuffer的大小，如果获取失败，返回0
//***********************************
unsigned fnGet_FileBuffer_Size_By_ImageBuffer(IN void* pImageBuffer)
{
	unsigned unFileBufferSize = 0;
	PE_NT_HEADER* pPE_NT_HEADER = NULL;
	PE_IMAGE_SECTION_HEADER* pPE_IMAGE_SECTION_HEADER = NULL;
	unsigned unNumberOfSection = 0;
	bool blStatus = FALSE;

	if (pImageBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("fnGet_FileBuffer_Size_By_ImageBuffer: pImageBuffer 为空.\r\n");
		}
		unFileBufferSize = 0;
		goto F;
	}
	blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(pImageBuffer, &pPE_NT_HEADER);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnGet_FileBuffer_Size_By_ImageBuffer: fnGet_PE_NT_Header_Address_By_FileBuffer 失败.\r\n");
		}
		unFileBufferSize = 0;
		goto F;
	}
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_HEADER, &pPE_IMAGE_SECTION_HEADER, &unNumberOfSection);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnGet_FileBuffer_Size_By_ImageBuffer: fnGetPE_Image_Section_Header_Structure_Array 失败.\r\n");
		}
		unFileBufferSize = 0;
		goto F;
	}
	//获取大小
	unFileBufferSize = pPE_IMAGE_SECTION_HEADER[unNumberOfSection - 1].PointerToRawData + pPE_IMAGE_SECTION_HEADER[unNumberOfSection - 1].SizeOfRawData;


F:
	return unFileBufferSize;


}

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
				   )
{
	//PE_DOS_HEADER
	PE_DOS_HEADER* pPE_DOS_Header = NULL;
	//PE_NT_HEADER
	PE_NT_HEADER* pPE_NT_Header = NULL;
	//PE_IMAGE_SECTION_HEADER
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header = NULL;
	//Number Of Sections
	unsigned uNumberOfSections = 0;
	//PE_DOS_HEADER_New
	PE_DOS_HEADER* pPE_DOS_Header_New = NULL;
	//PE_NT_HEADER_New
	PE_NT_HEADER* pPE_NT_Header_New = NULL;
	//PE_IMAGE_SECTION_HEADER_New
	PE_IMAGE_SECTION_HEADER* pPE_Image_Section_Header_New = NULL;
	//Number Of Sections_New
	unsigned uNumberOfSections_New = 0;
	//EmptySpace
	unsigned uEmptySpace = 0;
	//Status
	bool blStatus = FALSE;
	//Circulate Variable
	unsigned uCount = 0;
	//Switch Branch
	unsigned uBranch = 0xFF;
	
	
	if (lpFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: lpImageBuffer \r\n");
		}
		goto F;
	}
	if (uSizeOfSection == 0)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: uSizeOfSection \r\n");
		}
		goto F;
	}
	if (plpNewFileBuffer == 0)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: plpNewFileBuffer \r\n");
		}
		goto F;
	}
	if (uSizeOfFileBuffer == 0)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: puSizeOfFileBuffer \r\n");
		}
		goto F;
	}
	if (puSizeOfNewFileBuffer == NULL)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: puSizeOfNewFileBuffer \r\n");
		}
		goto F;
	}
	
	
	
	//Get PE_DOS_Header Address
	pPE_DOS_Header = (PE_DOS_HEADER*)lpFileBuffer;
	
	//Get PE_NT_Header Address
	blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(lpFileBuffer, &pPE_NT_Header);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: fnGet_PE_NT_Header_Address_By_FileBuffer \r\n");
		}
		goto F;
	}
	
	//Get PE_Image_Section_Header_Arry
	blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header, &pPE_Image_Section_Header, &uNumberOfSections);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: fnGetPE_Image_Section_Header_Structure_Array \r\n");
		}
		goto F;
	}
	//verified uSizeOfFileBuffer
	if (uSizeOfFileBuffer % pPE_NT_Header->OptionalHeader.FileAlignment != 0)
	{
		if (__DEBUG)
		{
			printf("fnAdd_Section: uSizeOfFileBuffer illegal. PE_NT_Header->OptionalHeader.FileAlignment:%x \r\n", 
				pPE_NT_Header->OptionalHeader.FileAlignment);
		}
		goto F;
	}
	
	switch(nMethod)
	{
	case ADD_SECTION_METHOD_DIRECTLY_ADD_SECTION:
		{
			//malloc plpNewBuffer
			*plpNewFileBuffer = malloc(uSizeOfFileBuffer + uSizeOfSection);
			if (*plpNewFileBuffer != NULL)
			{
				memset(*plpNewFileBuffer, 0x0, uSizeOfFileBuffer + uSizeOfSection);
			}
			else
			{
				if (__DEBUG)
				{
					printf("fnAdd_Section: plpNewFileBuffer \r\n");
				}
				goto F;
			}
			
			
			//Initialized puSizeOfNewFileBuffer
			*puSizeOfNewFileBuffer = uSizeOfFileBuffer + uSizeOfSection;
			//Initialized NewBuffer
			memcpy(*plpNewFileBuffer, lpFileBuffer, uSizeOfFileBuffer);
			//Get New PE Headers	
			//Get NEW_PE_DOS_Header Address
			pPE_DOS_Header_New = (PE_DOS_HEADER*)*plpNewFileBuffer;
			
			//Get NEW PE_NT_Header Address
			blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(*plpNewFileBuffer, &pPE_NT_Header_New);
			if (blStatus != TRUE)
			{
				if (__DEBUG)
				{
					printf("fnAdd_Section: fnGet_PE_NT_Header_Address_By_FileBuffer \r\n");
				}
				goto F;
			}
			
			//Get NEW_PE_Image_Section_Header_Arry
			blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header_New, &pPE_Image_Section_Header_New, &uNumberOfSections_New);
			if (blStatus != TRUE)
			{
				if (__DEBUG)
				{
					printf("fnAdd_Section: fnGetPE_Image_Section_Header_Structure_Array \r\n");
				}
				goto F;
			}
			
			//Modify New Section Headers
			//Characteristics
			pPE_Image_Section_Header_New[uNumberOfSections_New].Characteristics = uCharacteristics;
			//Misc
			pPE_Image_Section_Header_New[uNumberOfSections_New].Misc.PhysicalAddress = uSizeOfSection;
			//Name
			memcpy(pPE_Image_Section_Header_New[uNumberOfSections_New].Name, szName, 8);
			//uNumberOfSections_New
			pPE_Image_Section_Header_New[uNumberOfSections_New].NumberOfLinenumbers
				=
				pPE_Image_Section_Header_New[uNumberOfSections_New - 1].NumberOfLinenumbers;
			//NumberOfRelocations
			pPE_Image_Section_Header_New[uNumberOfSections_New].NumberOfRelocations
				=
				pPE_Image_Section_Header_New[uNumberOfSections_New - 1].NumberOfRelocations;
			//PointerToLinenumbers
			pPE_Image_Section_Header_New[uNumberOfSections_New].PointerToLinenumbers
				=
				pPE_Image_Section_Header_New[uNumberOfSections_New - 1].PointerToLinenumbers;
			//PointerToRawData
			pPE_Image_Section_Header_New[uNumberOfSections_New].PointerToRawData
				=
				pPE_Image_Section_Header_New[uNumberOfSections_New - 1].PointerToRawData 
				+
				pPE_Image_Section_Header_New[uNumberOfSections_New - 1].SizeOfRawData;
			//PointerToLinenumbers
			pPE_Image_Section_Header_New[uNumberOfSections_New].PointerToRelocations
				=
				pPE_Image_Section_Header_New[uNumberOfSections_New - 1].PointerToRelocations;
			//SizeOfRawData
			if (uSizeOfSection % pPE_NT_Header_New->OptionalHeader.FileAlignment != 0)
			{
				pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData 
					=
					pPE_NT_Header_New->OptionalHeader.FileAlignment * (uSizeOfSection / pPE_NT_Header_New->OptionalHeader.FileAlignment + 1);
			}
			else
			{
				pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData = uSizeOfSection;
			}
			//VirtualAddress
			pPE_Image_Section_Header_New[uNumberOfSections_New].VirtualAddress = 
				pPE_NT_Header->OptionalHeader.SizeOfImage;
			
			//Modify NT Headers
			//NumberOfSections
			pPE_NT_Header_New->FileHeader.NumberOfSections ++;
			//SizeOfImage
			pPE_NT_Header_New->OptionalHeader.SizeOfImage = 
				pPE_Image_Section_Header_New[uNumberOfSections_New].VirtualAddress 
				+ 
				((
				pPE_Image_Section_Header_New[uNumberOfSections_New].Misc.VirtualSize 
				>
				pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData
				)
				?
				pPE_Image_Section_Header_New[uNumberOfSections_New].Misc.VirtualSize
				:
			pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData);
			if (pPE_NT_Header_New->OptionalHeader.SizeOfImage % pPE_NT_Header->OptionalHeader.SectionAlignment != 0)
			{
				pPE_NT_Header_New->OptionalHeader.SizeOfImage = 
					(pPE_NT_Header_New->OptionalHeader.SizeOfImage / pPE_NT_Header->OptionalHeader.SectionAlignment + 1)
					*
					pPE_NT_Header->OptionalHeader.SectionAlignment;
			}
			
			break;
			}
		case ADD_SECTION_METHOD_MOVE_UP_SECTION_HEADER:
			{
				//初始化新PE文件的大小
				*puSizeOfNewFileBuffer = uSizeOfFileBuffer + uSizeOfSection;
				//申请新PE文件的FileImage
				*plpNewFileBuffer = malloc(*puSizeOfNewFileBuffer);
				//判断申请是否成功
				if (*plpNewFileBuffer == NULL)
				{
					if (__DEBUG)
					{
						printf("plpNewFileBuffer 为空.\r\n");
						goto F;
					}
				}
				else //否则初始化
				{
					memset(*plpNewFileBuffer, 0x0,*puSizeOfNewFileBuffer);
					
				}
				//上移一个Section_Head的大小
				//COPY PE_DOS_HEADER
				memcpy(*plpNewFileBuffer, lpFileBuffer, sizeof(PE_DOS_HEADER));
				//获取新PE结构的DOS头
				pPE_DOS_Header_New = (PE_DOS_HEADER*)*plpNewFileBuffer;
				//修改e_lfanew数据的值
				pPE_DOS_Header_New->e_lfanew = pPE_DOS_Header_New->e_lfanew - sizeof(PE_IMAGE_SECTION_HEADER);
				//COPY PE_NT_HEADER
				memcpy(
					(void*)((int)(*plpNewFileBuffer) + pPE_DOS_Header_New->e_lfanew), 
					pPE_NT_Header, 
					sizeof(pPE_NT_Header->Signature) + sizeof(pPE_NT_Header->FileHeader) + pPE_NT_Header->FileHeader.SizeOfOptionalHeader
					);
				//获取新PE的NT_Header
				blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(*plpNewFileBuffer, &pPE_NT_Header_New);
				if (blStatus != TRUE)
				{
					if (__DEBUG)
					{
						printf("fnAddSection:获取新PE的NT_Header失败.\r\n");
					}
					goto F;
				}
				//获取带添加的Section Header的索引
				uNumberOfSections_New = pPE_NT_Header_New->FileHeader.NumberOfSections;
				//从原来的PE文件复制各个Section_Header到新的PE文件
				memcpy(
					(void*)((int)pPE_NT_Header_New + sizeof(pPE_NT_Header_New->Signature) + sizeof(PE_FILE_HEADER) + pPE_NT_Header_New->FileHeader.SizeOfOptionalHeader),
					pPE_Image_Section_Header,
					sizeof(PE_IMAGE_SECTION_HEADER) * pPE_NT_Header->FileHeader.NumberOfSections
					);
				//获取新PE的Section_Header
				pPE_Image_Section_Header_New = 
					(PE_IMAGE_SECTION_HEADER*)((int)pPE_NT_Header_New + sizeof(pPE_NT_Header_New->Signature) + sizeof(PE_FILE_HEADER) + pPE_NT_Header_New->FileHeader.SizeOfOptionalHeader);
				//添加新的Section_Header
				//Name
				memcpy(pPE_Image_Section_Header_New[uNumberOfSections_New].Name, szName, sizeof(char) * 8);
				//Misc
				//Misc中的值是未对齐前的值
				pPE_Image_Section_Header_New[uNumberOfSections_New].Misc.PhysicalAddress = uSizeOfSection;
				
				//VirtualAddress
				pPE_Image_Section_Header_New[uNumberOfSections_New].VirtualAddress = pPE_NT_Header_New->OptionalHeader.SizeOfImage;
				//SizeOfRawData
				if (uSizeOfSection % pPE_NT_Header_New->OptionalHeader.FileAlignment != 0)
				{
					pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData 
						=
						pPE_NT_Header_New->OptionalHeader.FileAlignment * (uSizeOfSection / pPE_NT_Header_New->OptionalHeader.FileAlignment + 1);
				}
				else
				{
					pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData = uSizeOfSection;
				}
				//PointerToRawData
				pPE_Image_Section_Header_New[uNumberOfSections_New].PointerToRawData 
					= 
					pPE_Image_Section_Header_New[uNumberOfSections_New - 1].PointerToRawData + pPE_Image_Section_Header_New[uNumberOfSections_New - 1].SizeOfRawData;
				//PointerToRelocations
				pPE_Image_Section_Header_New[uNumberOfSections_New].PointerToRelocations = pPE_Image_Section_Header_New[uNumberOfSections_New - 1].PointerToRelocations;
				//PointerToLineNumbers
				pPE_Image_Section_Header_New[uNumberOfSections_New].PointerToLinenumbers = pPE_Image_Section_Header_New[uNumberOfSections_New - 1].PointerToLinenumbers;
				//NumberOfRelocations
				pPE_Image_Section_Header_New[uNumberOfSections_New].NumberOfRelocations = pPE_Image_Section_Header_New[uNumberOfSections_New - 1].NumberOfRelocations;
				//NumberOfLinenumbers
				pPE_Image_Section_Header_New[uNumberOfSections_New].NumberOfLinenumbers = pPE_Image_Section_Header_New[uNumberOfSections_New - 1].NumberOfLinenumbers;
				//Characteristic
				pPE_Image_Section_Header_New[uNumberOfSections_New].Characteristics = uCharacteristics;
				
				//修改新PE的NT头中的信息
				//NumberOfSection
				pPE_NT_Header_New->FileHeader.NumberOfSections ++;
				//SizeOfImage
				//先计算出SizeOfImage的大小
				pPE_NT_Header_New->OptionalHeader.SizeOfImage = 
					pPE_Image_Section_Header_New[uNumberOfSections_New].VirtualAddress 
					+ 
					((pPE_Image_Section_Header_New[uNumberOfSections_New].Misc.PhysicalAddress > pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData) 
					?
					pPE_Image_Section_Header_New[uNumberOfSections_New].Misc.PhysicalAddress
					:
				pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData);
				//判断是否内存对齐
				if (pPE_NT_Header_New->OptionalHeader.SizeOfImage % pPE_NT_Header_New->OptionalHeader.SectionAlignment != 0)
				{
					pPE_NT_Header_New->OptionalHeader.SizeOfImage = 
						(pPE_NT_Header_New->OptionalHeader.SizeOfImage % pPE_NT_Header_New->OptionalHeader.SectionAlignment + 1)
						*
						pPE_NT_Header_New->OptionalHeader.SectionAlignment;
				}
				//复制剩余的数据进新PE
				memcpy(
					&pPE_Image_Section_Header_New[uNumberOfSections_New + 1], 
					&pPE_Image_Section_Header[uNumberOfSections_New], 
					uSizeOfFileBuffer - ((int)&pPE_Image_Section_Header[uNumberOfSections_New] - (int)lpFileBuffer));
				break;
			}
			case ADD_SECTION_METHOD_EXPANDING_LAST_SECTION:
				{
					//扩大最后一个节区
					*puSizeOfNewFileBuffer = uSizeOfFileBuffer + uSizeOfSection;
					//申请新FILEBUFFER的内存空间
					*plpNewFileBuffer = malloc(*puSizeOfNewFileBuffer);
					//验证是否分配成功
					if (*plpNewFileBuffer == NULL)
					{
						if (__DEBUG)
						{
							printf("fnAddSection: plpNewFileBuffer 为空.\r\n");
						}
						goto F;
					}
					//初始化内存空间
					memset(*plpNewFileBuffer, 0x0, *puSizeOfNewFileBuffer);
					//拷贝旧PE到新PE
					memcpy(*plpNewFileBuffer, lpFileBuffer, uSizeOfFileBuffer);
					//得到新PE的各种头信息
					pPE_DOS_Header_New = (PE_DOS_HEADER *)*plpNewFileBuffer;
					blStatus = fnGet_PE_NT_Header_Address_By_FileBuffer(*plpNewFileBuffer, &pPE_NT_Header_New);
					if (blStatus != TRUE)
					{
						if (__DEBUG)
						{
							printf("fnAddSection: fnGet_PE_NT_Header_Address_By_FileBuffer失败。\r\n");
						}
						goto F;
					}
					blStatus = fnGetPE_Image_Section_Header_Structure_Array(pPE_NT_Header_New, &pPE_Image_Section_Header_New, &uNumberOfSections_New);
					if (blStatus != TRUE)
					{
						if (__DEBUG)
						{
							printf("fnAddSection: fnGetPE_Image_Section_Header_Structure_Array 失败.\r\n");
						}
						goto F;
					}
					//找到最后一节
					//修改实际大小
					pPE_Image_Section_Header_New[uNumberOfSections_New - 1].Misc.PhysicalAddress += uSizeOfSection;
					//修改在文件中的大小
					if (uSizeOfSection % pPE_NT_Header_New->OptionalHeader.FileAlignment != 0)
					{
						pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData 
							=
							pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData
							+
							pPE_NT_Header_New->OptionalHeader.FileAlignment * (uSizeOfSection / pPE_NT_Header_New->OptionalHeader.FileAlignment + 1);
					}
					else
					{
						pPE_Image_Section_Header_New[uNumberOfSections_New].SizeOfRawData += uSizeOfSection;
					}
					//修改属性
					pPE_Image_Section_Header_New[uNumberOfSections_New - 1].Characteristics = pPE_Image_Section_Header_New[uNumberOfSections_New - 1].Characteristics | uCharacteristics;
					//修改PE_NT_HEADER的信息
					//先计算出SizeOfImage的值
					pPE_NT_Header_New->OptionalHeader.SizeOfImage += uSizeOfSection;
					//判断是否符合内存对齐
					if (pPE_NT_Header_New->OptionalHeader.SizeOfImage % pPE_NT_Header_New->OptionalHeader.SectionAlignment != 0)
					{
						pPE_NT_Header_New->OptionalHeader.SizeOfImage = 
							(pPE_NT_Header_New->OptionalHeader.SizeOfImage / pPE_NT_Header_New->OptionalHeader.SectionAlignment + 1)
							*
							(pPE_NT_Header_New->OptionalHeader.SectionAlignment);

					}
					break;
						
				}
			default:
				break;
		}
		
		return TRUE;
		
F:
		if (*plpNewFileBuffer != NULL)
		{
			free(*plpNewFileBuffer);
			*plpNewFileBuffer = NULL;
		}
		return FALSE;
}
