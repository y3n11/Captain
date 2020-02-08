#ifndef _HOOKS_
#define _HOOKS_

#include <string>
#include <sstream> 
#include <iostream>
#include <fstream>
#include <locale>
#include <codecvt>
#include <map>

#include "CaptainHook.hpp"
#include "Reporting.hpp"
#include "Utils.hpp"

typedef BOOL(WINAPI *pfnCreateProcessW)(LPCWSTR lpApplicationName,
										LPTSTR lpCommandLine,
										LPSECURITY_ATTRIBUTES lpProcessAttributes,
										LPSECURITY_ATTRIBUTES lpThreadAttributes,
										BOOL bInheritHandles,
										DWORD dwCreationFlags,
										LPVOID lpEnvironment,
										LPCTSTR lpCurrentDirectory,
										LPSTARTUPINFOW lpStartupInfo,
										LPPROCESS_INFORMATION lpProcessInformation);


typedef HANDLE(WINAPI *pfnCreateFileW)(	LPCWSTR               lpFileName,
										DWORD                 dwDesiredAccess,
										DWORD                 dwShareMode,
										LPSECURITY_ATTRIBUTES lpSecurityAttributes,
										DWORD                 dwCreationDisposition,
										DWORD                 dwFlagsAndAttributes,
										HANDLE                hTemplateFile);

typedef BOOL(WINAPI *pfnDeleteFileW)(LPCWSTR path);
typedef HMODULE(WINAPI *pfnLoadLibraryW)(LPCWSTR lpLibFileName);
typedef HMODULE(WINAPI *pfnLoadLibraryA)(LPCSTR lpLibFileName);

typedef LONG(WINAPI *pfnRegOpenKeyExW)( HKEY    hKey,
										LPCWSTR lpSubKey,
										DWORD   ulOptions,
										REGSAM  samDesired,
										PHKEY   phkResult );


typedef HMODULE(*pfnLoadLibraryExW)( LPCWSTR lpLibFileName,
							         HANDLE hFile,
							         DWORD  dwFlags);

typedef HANDLE(WINAPI *pfnCreateRemoteThread)( HANDLE                 hProcess,
								               LPSECURITY_ATTRIBUTES  lpThreadAttributes,
								               SIZE_T                 dwStackSize,
								               LPTHREAD_START_ROUTINE lpStartAddress,
								               LPVOID                 lpParameter,
								               DWORD                  dwCreationFlags,
								               LPDWORD                lpThreadId );


typedef LPVOID (WINAPI * pfnVirtualAllocEx)(  HANDLE hProcess,
								              LPVOID lpAddress,
								              SIZE_T dwSize,
								              DWORD  flAllocationType,
								              DWORD  flProtect );


typedef BOOL (WINAPI * pfnWriteProcessMemory)( HANDLE  hProcess,
										       LPVOID  lpBaseAddress,
										       LPCVOID lpBuffer,
										       SIZE_T  nSize,
										       SIZE_T  *lpNumberOfBytesWritten);


typedef BOOL (WINAPI * pfnReadProcessMemory)( HANDLE  hProcess,
										      LPCVOID lpBaseAddress,
										      LPVOID  lpBuffer,
										      SIZE_T  nSize,
										      SIZE_T  *lpNumberOfBytesRead );

typedef HANDLE (WINAPI * pfnOpenProcess)( DWORD dwDesiredAccess,
										  BOOL  bInheritHandle,
      									  DWORD dwProcessId );

pfnCreateProcessW 		fpCreateProcessW;
pfnCreateFileW 			fpCreateFileW;
pfnDeleteFileW 			fpDeleteFileW;
pfnLoadLibraryW			fpLoadLibraryW;
pfnRegOpenKeyExW		fpRegOpenKeyExW;
pfnLoadLibraryA			fpLoadLibraryA;
pfnLoadLibraryExW		fpLoadLibraryExW;
pfnCreateRemoteThread	fpCreateRemoteThread;
pfnVirtualAllocEx		fpVirtualAllocEx;
pfnWriteProcessMemory	fpWriteProcessMemory;
pfnReadProcessMemory	fpReadProcessMemory;
pfnOpenProcess			fpOpenProcess;



std::map<std::string, LPBYTE> g_saved_bytes;

BOOL WINAPI HookedCreateProcessW (LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {

	BYTE bSavedByte;
	std::map<std::string, std::string> _args;
	
	_args.insert(std::pair<std::string, std::string>("lpApplicationName", Utils::WideStringToAscii(lpApplicationName)));
    _args.insert(std::pair<std::string, std::string>("lpCommandLine", Utils::WideStringToAscii(lpCommandLine)));

    Reporting::Log("CreateProcessW", _args);

    CaptainHook::UnHookFunction((DWORD64)fpCreateProcessW, g_saved_bytes.find("CreateProcessW")->second);
    BOOL b = CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    g_saved_bytes.find("CreateProcessW")->second = CaptainHook::HookFunction((DWORD64)fpCreateProcessW, (DWORD64)HookedCreateProcessW);

    return b;
}


BOOL WINAPI HookedDeleteFileW(LPCWSTR lpFileName){

	BYTE bSavedByte;
	std::map<std::string, std::string> _args;
	_args.insert(std::pair<std::string, std::string>("lpFileName", Utils::WideStringToAscii(lpFileName)));
	Reporting::Log("DeleteFileW", _args);

	CaptainHook::UnHookFunction((DWORD64)fpDeleteFileW, g_saved_bytes.find("DeleteFileW")->second);
	BOOL b = DeleteFileW(lpFileName);
	g_saved_bytes.find("DeleteFileW")->second = CaptainHook::HookFunction((DWORD64)fpDeleteFileW, (DWORD64)HookedDeleteFileW);

	return b;
}


/*HANDLE WINAPI HookedCreateFileW( LPCWSTR               lpFileName,
							  DWORD                 dwDesiredAccess,
							  DWORD                 dwShareMode,
							  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
							  DWORD                 dwCreationDisposition,
							  DWORD                 dwFlagsAndAttributes,
							  HANDLE                hTemplateFile){

	BYTE bSavedByte;
	CaptainHook::UnHookFunction((DWORD64)fpCreateFileW, g_saved_bytes.find("CreateFileW")->second);
	
	std::map<std::string, std::string> _args;
	_args.insert(std::pair<std::string, std::string>("lpFileName", Utils::WideStringToAscii(lpFileName)));
	Reporting::Log("CreateFileW", _args);

	HANDLE hFile = CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	g_saved_bytes.find("CreateFileW")->second = CaptainHook::HookFunction((DWORD64)fpCreateFileW, (DWORD64)HookedCreateFileW);

	return hFile;

}*/

HMODULE WINAPI HookedLoadLibraryW(LPCWSTR lpLibFileName)
{
	BYTE bSavedByte;
	


	std::map<std::string, std::string> _args;
	_args.insert(std::pair<std::string, std::string>("lpLibFileName", Utils::WideStringToAscii(lpLibFileName)));
	Reporting::Log("LoadLibraryW", _args);

	CaptainHook::UnHookFunction((DWORD64)fpLoadLibraryW, g_saved_bytes.find("LoadLibraryW")->second);
	HMODULE hModule = LoadLibraryW(lpLibFileName);

	g_saved_bytes.find("LoadLibraryW")->second = CaptainHook::HookFunction((DWORD64)fpLoadLibraryW, (DWORD64)HookedLoadLibraryW);

	return hModule;

}

HMODULE HookedLoadLibraryExW( LPCWSTR lpLibFileName,
            					HANDLE hFile,
            					DWORD  dwFlag)
{
	BYTE bSavedByte;


	std::map<std::string, std::string> _args;
	_args.insert(std::pair<std::string, std::string>("lpLibFileName", Utils::WideStringToAscii(lpLibFileName)));
	Reporting::Log("LoadLibraryExW", _args);

	CaptainHook::UnHookFunction((DWORD64)fpLoadLibraryExW, g_saved_bytes.find("LoadLibraryExW")->second);
	HMODULE hModule = LoadLibraryExW(lpLibFileName, hFile, dwFlag);

	g_saved_bytes.find("LoadLibraryExW")->second = CaptainHook::HookFunction((DWORD64)fpLoadLibraryExW, (DWORD64)HookedLoadLibraryExW);

	return hModule;

}

HMODULE WINAPI HookedLoadLibraryA(LPCSTR lpLibFileName)
{
	BYTE bSavedByte;


	std::map<std::string, std::string> _args;
	_args.insert(std::pair<std::string, std::string>("lpLibFileName", std::string(lpLibFileName)));
	Reporting::Log("LoadLibraryA", _args);

	CaptainHook::UnHookFunction((DWORD64)fpLoadLibraryA, g_saved_bytes.find("LoadLibraryA")->second);
	HMODULE hModule = LoadLibraryA(lpLibFileName);

	g_saved_bytes.find("LoadLibraryA")->second = CaptainHook::HookFunction((DWORD64)fpLoadLibraryA, (DWORD64)HookedLoadLibraryA);

	return hModule;

}

HANDLE WINAPI HookedCreateRemoteThread(
                HANDLE                 hProcess,
              LPSECURITY_ATTRIBUTES  lpThreadAttributes,
              SIZE_T                 dwStackSize,
              LPTHREAD_START_ROUTINE lpStartAddress,
              LPVOID                 lpParameter,
              DWORD                  dwCreationFlags,
              LPDWORD                lpThreadId )
{
	BYTE bSavedByte;

    std::map<std::string, std::string> _args;
    Reporting::Log("CreateRemoteThread", _args);

    CaptainHook::UnHookFunction((DWORD64)fpCreateRemoteThread, g_saved_bytes.find("CreateRemoteThread")->second);
    HANDLE hThread = CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

	g_saved_bytes.find("CreateRemoteThread")->second = CaptainHook::HookFunction((DWORD64)fpCreateRemoteThread, (DWORD64)HookedCreateRemoteThread);

	return hThread;
}

LPVOID HookedVirtualAllocEx(
      HANDLE hProcess,
      LPVOID lpAddress,
      SIZE_T dwSize,
      DWORD  flAllocationType,
      DWORD  flProtect)
{
    std::map<std::string, std::string> _args;
    Reporting::Log("VirtualAllocEx", _args);

	CaptainHook::UnHookFunction((DWORD64)fpVirtualAllocEx, g_saved_bytes.find("VirtualAllocEx")->second);
    LPVOID lpMem = VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    g_saved_bytes.find("VirtualAllocEx")->second = CaptainHook::HookFunction((DWORD64)fpVirtualAllocEx, (DWORD64)HookedVirtualAllocEx);

    return lpMem;
}


BOOL HookedWriteProcessMemory(
      HANDLE  hProcess,
      LPVOID  lpBaseAddress,
      LPCVOID lpBuffer,
      SIZE_T  nSize,
      SIZE_T  *lpNumberOfBytesWritten)
{
    std::map<std::string, std::string> _args;
    Reporting::Log("WriteProcessMemory", _args);

    CaptainHook::UnHookFunction((DWORD64)fpWriteProcessMemory, g_saved_bytes.find("WriteProcessMemory")->second);
   	BOOL b = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    g_saved_bytes.find("WriteProcessMemory")->second = CaptainHook::HookFunction((DWORD64)fpWriteProcessMemory, (DWORD64)HookedWriteProcessMemory);

   	return b;
}



BOOL HookedReadProcessMemory(
      HANDLE  hProcess,
      LPCVOID lpBaseAddress,
      LPVOID  lpBuffer,
      SIZE_T  nSize,
      SIZE_T  *lpNumberOfBytesRead)
{
    std::map<std::string, std::string> _args;
    Reporting::Log("ReadProcessMemory", _args);

    CaptainHook::UnHookFunction((DWORD64)fpReadProcessMemory, g_saved_bytes.find("ReadProcessMemory")->second);
    BOOL b = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    g_saved_bytes.find("ReadProcessMemory")->second = CaptainHook::HookFunction((DWORD64)fpReadProcessMemory, (DWORD64)HookedReadProcessMemory);

    return b;

}


HANDLE HookedOpenProcess(
      DWORD dwDesiredAccess,
      BOOL  bInheritHandle,
      DWORD dwProcessId)
{
    std::map<std::string, std::string> _args;
    Reporting::Log("OpenProcess", _args);

    CaptainHook::UnHookFunction((DWORD64)fpOpenProcess, g_saved_bytes.find("OpenProcess")->second);
    HANDLE h = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
   	g_saved_bytes.find("OpenProcess")->second = CaptainHook::HookFunction((DWORD64)fpOpenProcess, (DWORD64)HookedOpenProcess);

    return h;
}


/*

LONG WINAPI HookedRegOpenKeyExW( HKEY    hKey,
								 LPCWSTR lpSubKey,
								 DWORD   ulOptions,
								 REGSAM  samDesired,
								PHKEY   phkResult)
{
	BYTE bSavedByte;
	CaptainHook::UnHookFunction((DWORD64)fpCreateFileW, g_saved_bytes.find("CreateFileW")->second);

	std::map<std::string, std::string> _args;
	_args.insert(std::pair<std::string, std::string>("lpSubKey", Utils::WideStringToAscii(lpSubKey)));
	Reporting::Log("RegOpenKeyExW", _args);

	CaptainHook::UnHookFunction((DWORD64)fpRegOpenKeyExW, g_saved_bytes.find("RegOpenKeyExW")->second);
	LONG ret = fpRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);

	g_saved_bytes.find("CreateFileW")->second = CaptainHook::HookFunction((DWORD64)fpCreateFileW, (DWORD64)HookedCreateFileW);
	g_saved_bytes.find("RegOpenKeyExW")->second = CaptainHook::HookFunction((DWORD64)fpRegOpenKeyExW, (DWORD64)HookedRegOpenKeyExW);

	return ret;
}

*/

#endif
