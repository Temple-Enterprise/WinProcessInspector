#include "../InjectionEngine.h"

namespace WinProcessInspector {
namespace Injection {

bool InjectViaSetWindowsHookEx(DWORD processId, LPCSTR dllPath) {
	HMODULE hModDll = LoadLibraryA(dllPath);

	if (!hModDll) {
		return false;
	}

	HOOKPROC procAddress = (HOOKPROC)GetProcAddress(hModDll, "HookProcedure");

	if (!procAddress) {
		return false;
	}

	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hThreadSnap == INVALID_HANDLE_VALUE) {
		return false;
	}

	te32.dwSize = sizeof(THREADENTRY32);
	DWORD threadId = 0;

	if (!Thread32First(hThreadSnap, &te32)) {
		CloseHandle(hThreadSnap);
		return false;
	}

	do {
		if (te32.th32OwnerProcessID == processId) {
			threadId = te32.th32ThreadID;
			HANDLE hThread = OpenThread(READ_CONTROL, FALSE, te32.th32ThreadID);

			if (hThread) {
				HHOOK hookHandle = SetWindowsHookExA(WH_KEYBOARD, procAddress, hModDll, (DWORD)threadId);
				CloseHandle(hThread);

				if (hookHandle) {
					UnhookWindowsHookEx(hookHandle);
					CloseHandle(hThreadSnap);
					return true;
				}
			}
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return false;
}

}
}
