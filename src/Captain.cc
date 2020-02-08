#include <Windows.h>
#include "Hooks.hpp"
#include "CaptainHook.hpp"


VOID EnableHooks()
{
	LPBYTE bytes = nullptr;

    std::string psName = Utils::GetCurrentProcessName();


	fpCreateProcessW = (pfnCreateProcessW)GetProcAddress(LoadLibraryW(L"kernel32"), "CreateProcessW");
    if (fpCreateProcessW == NULL)
        return;

    bytes = CaptainHook::HookFunction((DWORD64)fpCreateProcessW, (DWORD64)HookedCreateProcessW);
    g_saved_bytes.insert({"CreateProcessW", bytes});


    fpLoadLibraryW = (pfnLoadLibraryW)GetProcAddress(LoadLibraryW(L"kernel32"), "LoadLibraryW");
    if(fpLoadLibraryW == NULL)
    	return;

    bytes = CaptainHook::HookFunction((DWORD64)fpLoadLibraryW, (DWORD64)HookedLoadLibraryW);
    g_saved_bytes.insert({"LoadLibraryW", bytes});

   fpLoadLibraryA = (pfnLoadLibraryA)GetProcAddress(LoadLibraryW(L"kernel32"), "LoadLibraryA");
    if(fpLoadLibraryW == NULL)
    	return;

    bytes = CaptainHook::HookFunction((DWORD64)fpLoadLibraryA, (DWORD64)HookedLoadLibraryA);
    g_saved_bytes.insert({"LoadLibraryA", bytes});

    fpLoadLibraryExW = (pfnLoadLibraryExW)GetProcAddress(LoadLibraryW(L"kernel32"), "LoadLibraryExW");
    if(fpLoadLibraryExW == NULL)
        return;

    bytes = CaptainHook::HookFunction((DWORD64)fpLoadLibraryExW, (DWORD64)HookedLoadLibraryExW);
    g_saved_bytes.insert({"LoadLibraryExW", bytes});

    fpCreateRemoteThread = (pfnCreateRemoteThread)GetProcAddress(LoadLibraryW(L"kernel32"), "CreateRemoteThread");
    if(fpCreateRemoteThread == NULL)
        return;

    bytes = CaptainHook::HookFunction((DWORD64)fpCreateRemoteThread, (DWORD64)HookedCreateRemoteThread);
    g_saved_bytes.insert({"CreateRemoteThread", bytes});


    fpVirtualAllocEx = (pfnVirtualAllocEx)GetProcAddress(LoadLibraryW(L"kernel32"), "VirtualAllocEx");
    if(fpVirtualAllocEx == NULL)
        return;

    bytes = CaptainHook::HookFunction((DWORD64)fpVirtualAllocEx, (DWORD64)HookedVirtualAllocEx);
    g_saved_bytes.insert({"VirtualAllocEx", bytes});


    fpWriteProcessMemory = (pfnWriteProcessMemory)GetProcAddress(LoadLibraryW(L"kernel32"), "WriteProcessMemory");
    if(fpWriteProcessMemory == NULL)
        return;

    bytes = CaptainHook::HookFunction((DWORD64)fpWriteProcessMemory, (DWORD64)HookedWriteProcessMemory);
    g_saved_bytes.insert({"WriteProcessMemory", bytes});


    fpReadProcessMemory = (pfnReadProcessMemory)GetProcAddress(LoadLibraryW(L"kernel32"), "ReadProcessMemory");
    if(fpReadProcessMemory == NULL)
        return;

    bytes = CaptainHook::HookFunction((DWORD64)fpReadProcessMemory, (DWORD64)HookedReadProcessMemory);
    g_saved_bytes.insert({"ReadProcessMemory", bytes});

    if (psName == "C:\\Windows\\Explorer.EXE" ||
        psName == "C:\\Windows\\explorer.exe")
        return;

    fpOpenProcess = (pfnOpenProcess)GetProcAddress(LoadLibraryW(L"kernel32"), "OpenProcess");
    if(fpOpenProcess == NULL)
        return;

    bytes = CaptainHook::HookFunction((DWORD64)fpOpenProcess, (DWORD64)HookedOpenProcess);
    g_saved_bytes.insert({"OpenProcess", bytes});

}

VOID DisableHooks()
{
    std::string psName = Utils::GetCurrentProcessName();

	CaptainHook::UnHookFunction((DWORD64)fpCreateProcessW, g_saved_bytes.find("CreateProcessW")->second);
	CaptainHook::UnHookFunction((DWORD64)fpLoadLibraryW, g_saved_bytes.find("LoadLibraryW")->second);
	CaptainHook::UnHookFunction((DWORD64)fpLoadLibraryA, g_saved_bytes.find("LoadLibraryA")->second);
    CaptainHook::UnHookFunction((DWORD64)fpLoadLibraryExW, g_saved_bytes.find("LoadLibraryExW")->second);
    CaptainHook::UnHookFunction((DWORD64)fpCreateRemoteThread, g_saved_bytes.find("CreateRemoteThread")->second);
    CaptainHook::UnHookFunction((DWORD64)fpVirtualAllocEx, g_saved_bytes.find("VirtualAllocEx")->second);
    CaptainHook::UnHookFunction((DWORD64)fpWriteProcessMemory, g_saved_bytes.find("WriteProcessMemory")->second);
    CaptainHook::UnHookFunction((DWORD64)fpReadProcessMemory, g_saved_bytes.find("ReadProcessMemory")->second);

    if (psName == "C:\\Windows\\Explorer.EXE" ||
        psName == "C:\\Windows\\explorer.exe")
        return;


    CaptainHook::UnHookFunction((DWORD64)fpOpenProcess, g_saved_bytes.find("OpenProcess")->second);

}


BOOL APIENTRY DllMain(HANDLE hInstance, DWORD fdwReason, LPVOID lpReserved) {

    switch (fdwReason) {

        case DLL_PROCESS_ATTACH:

        	Reporting::Init();
            EnableHooks();

            break;

        case DLL_PROCESS_DETACH:

        	DisableHooks();

        	break;
    }

    return TRUE;
}
