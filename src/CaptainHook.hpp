#ifndef _CAPTAINHOOK_
#define _CAPTAINHOOK_

#include <Windows.h>
#include <stdio.h>

namespace CaptainHook{

	template<typename T>
	static T ReadMemory(LPVOID lpAddress) {
		return *((T *)lpAddress);
	}

	template<typename T>
	static void WriteMemory(LPVOID lpAddress, T value) {
		*((T *)lpAddress) = value;
	}

	template<typename T>
	T* PointMemory(DWORD address) {
		return ((T*)address);
	}

	template<typename T>
	static DWORD ProtectMemory(LPVOID lpAddress, SIZE_T size, DWORD flProtect) {
		DWORD flOldProtect = 0;
		::VirtualProtect(lpAddress, size, flProtect, &flOldProtect);

		return flOldProtect;
	}

	static LPBYTE HookFunction(DWORD64 dwFuncAddress, DWORD64 dwNewAddress){

		LPBYTE origBytes = new BYTE[16]; //10

		for(INT i = 0; i < 16; i++){
			origBytes[i] = ReadMemory<BYTE>((LPVOID)(dwFuncAddress + i));
		}

		DWORD flOldProtect = ProtectMemory<DWORD64>((LPVOID)dwFuncAddress, 16, PAGE_EXECUTE_READWRITE);

		WriteMemory<BYTE>((LPVOID)dwFuncAddress, 0x50);
		WriteMemory<BYTE>((LPVOID)(dwFuncAddress + 1), 0x48);
		WriteMemory<BYTE>((LPVOID)(dwFuncAddress + 2), 0xb8);
		WriteMemory<DWORD64>((LPVOID)(dwFuncAddress + 3), dwNewAddress);
		WriteMemory<BYTE>((LPVOID)(dwFuncAddress + 11), 0x48);
		WriteMemory<BYTE>((LPVOID)(dwFuncAddress + 12), 0x87);
		WriteMemory<BYTE>((LPVOID)(dwFuncAddress + 13), 0x04);
		WriteMemory<BYTE>((LPVOID)(dwFuncAddress + 14), 0x24);
		WriteMemory<BYTE>((LPVOID)(dwFuncAddress + 15), 0xC3);


		ProtectMemory<DWORD>((LPVOID)dwFuncAddress, 16, flOldProtect);

		return origBytes;
	}

	static VOID UnHookFunction(DWORD64 dwFuncAddress, LPBYTE origBytes){

		DWORD flOldProtect = ProtectMemory<DWORD64>((LPVOID)dwFuncAddress, 16, PAGE_EXECUTE_READWRITE);

		for(INT i = 0; i < 16; i++)
			WriteMemory<BYTE>((LPVOID)(dwFuncAddress + i), origBytes[i]);

		ProtectMemory<DWORD64>((LPVOID)dwFuncAddress, 16, flOldProtect);
	}

}



#endif
