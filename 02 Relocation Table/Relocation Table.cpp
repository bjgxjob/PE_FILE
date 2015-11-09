// Relocation Table.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "FileOperation.h"
#include "PEFileStructure.h"


#define PATH "E:\\MyDllHindFunctionName.dll"

int main(int argc, char* argv[])
{
	LPVOID lpFileBuffer = NULL;
	DWORD dwFileBufferSize = 0;
	bool bStatus = FALSE;

	PIMAGE_DATA_DIRECTORY pImage_Relocation_Directory = NULL;

	bStatus = fnReadFile(PATH, &lpFileBuffer, (unsigned int *)&dwFileBufferSize);
	if (bStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("main(): fnReadFile Ê§°Ü\r\n");
		}
		goto RET;
	}

	bStatus = fnPrint_Relocation_Table(lpFileBuffer);

	


RET:
	if (lpFileBuffer != NULL)
	{
		free(lpFileBuffer);
		lpFileBuffer = NULL;
	}
	return 0;

}

