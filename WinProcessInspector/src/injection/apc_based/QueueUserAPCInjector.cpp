#include "../InjectionEngine.h"

namespace WinProcessInspector {
namespace Injection {

bool InjectViaQueueUserAPC(LPCSTR DllPath, HANDLE hProcess, DWORD processId) {
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32) {
		return false;
	}
	LPVOID LoadLibAddr = GetProcAddress(hKernel32, "LoadLibraryA");

	if (!LoadLibAddr) {
		return false;
	}

	LPVOID pDllPath = VirtualAllocEx(hProcess, 0, strlen(DllPath), MEM_COMMIT, PAGE_READWRITE);

	if (!pDllPath) {
		return false;
	}

	BOOL Written = WriteProcessMemory(hProcess, pDllPath, LPVOID(DllPath), strlen(DllPath), NULL);

	if (!Written) {
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		return false;
	}

	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hThreadSnap == INVALID_HANDLE_VALUE) {
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		return false;
	}

	te32.dwSize = sizeof(THREADENTRY32);
	DWORD threadId = 0;

	if (!Thread32First(hThreadSnap, &te32)) {
		CloseHandle(hThreadSnap);
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		return false;
	}

	do {
		if (te32.th32OwnerProcessID == processId) {
			threadId = te32.th32ThreadID;
			HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);

			if (hThread) {
				DWORD dwResult = QueueUserAPC((PAPCFUNC)LoadLibAddr, hThread, (ULONG_PTR)pDllPath);
				CloseHandle(hThread);

				if (dwResult) {
					CloseHandle(hThreadSnap);
					return true;
				}
			}
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);

	return false;
}

}
}
