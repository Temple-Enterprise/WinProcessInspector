#include "../InjectionEngine.h"

namespace WinProcessInspector {
namespace Injection {

bool InjectViaCreateRemoteThread(LPCSTR DllPath, HANDLE hProcess) {
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32) {
		return false;
	}
	LPVOID LoadLibAddr = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");

	if (!LoadLibAddr) {
		return false;
	}

	LPVOID pDllPath = VirtualAllocEx(hProcess, 0, strlen(DllPath), MEM_COMMIT, PAGE_READWRITE);

	if (!pDllPath) {
		return false;
	}

	BOOL Written = WriteProcessMemory(hProcess, pDllPath, (LPVOID)DllPath, strlen(DllPath), NULL);

	if (!Written) {
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, pDllPath, 0, NULL);

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
