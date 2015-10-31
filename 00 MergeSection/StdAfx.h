// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//

#if !defined(AFX_STDAFX_H__E99AA074_83CD_4D80_A056_BF035FF5C6AF__INCLUDED_)
#define AFX_STDAFX_H__E99AA074_83CD_4D80_A056_BF035FF5C6AF__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

#include <stdio.h>

// TODO: reference additional headers your program requires here
#include "FileOperation.h"
#include "PEFileStructure.h"

#define __DEBUG 1

#define PATH_READ "e:\\Notepad.exe"

#define PATH_WRITE "e:\\AddSection.exe"

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__E99AA074_83CD_4D80_A056_BF035FF5C6AF__INCLUDED_)
