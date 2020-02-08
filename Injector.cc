#include <Windows.h>
#include <stdio.h>

VOID InjectDll(HANDLE hProcess, LPCSTR lpszDllPath)
{
	DWORD dwDllPathLen = strlen(lpszDllPath);
	LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, dwDllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(hProcess, lpBaseAddress, lpszDllPath, dwDllPathLen, NULL);

	HMODULE hModule = GetModuleHandle("kernel32.dll");

	LPVOID lpStartAddress = GetProcAddress(hModule, "LoadLibraryA");

	CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpBaseAddress, 0, NULL);
}

int main(int argc, char* argv[])
{
	if (argc != 2)
		return -1;

	DWORD pid = atoi(argv[1]);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if(hProc == NULL)
		return -2;
	InjectDll(hProc, "C:\\ProgramData\\Captain\\Captain.dll");

	return 0;
}