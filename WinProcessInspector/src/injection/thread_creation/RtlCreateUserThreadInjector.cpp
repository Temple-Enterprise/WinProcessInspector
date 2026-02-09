#include "../InjectionEngine.h"

namespace WinProcessInspector {
namespace Injection {

bool InjectViaRtlCreateUserThread(HANDLE hProcess, LPCSTR DllPath) {
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32) {
		return false;
	}
	LPVOID LoadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryA");

	if (!LoadLibraryAddr) {
		return false;
	}

	LPVOID pDllPath = VirtualAllocEx(hProcess, 0, strlen(DllPath), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pDllPath) {
		return false;
	}

	BOOL written = WriteProcessMemory(hProcess, pDllPath, (LPVOID)DllPath, strlen(DllPath), NULL);

	if (!written) {
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		return false;
	}

	HMODULE modNtDll = GetModuleHandleA("ntdll.dll");

	if (!modNtDll) {
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		return false;
	}

	pRtlCreatUserThread pfunc_RtlCreateUserThread = (pRtlCreatUserThread)GetProcAddress(modNtDll, "RtlCreateUserThread");

	if (!pfunc_RtlCreateUserThread) {
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		return false;
	}

	HANDLE hThread = NULL;

	pfunc_RtlCreateUserThread(
		hProcess,
		NULL,
		0,
		0,
		0,
		0,
		LoadLibraryAddr,
		pDllPath,
		&hThread,
		NULL
	);

	if (!hThread) {
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
	CloseHandle(hThread);

	return true;
}

}
}
