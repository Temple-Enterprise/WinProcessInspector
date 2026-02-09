#include "WinProcessModule.h"

namespace WinProcessInspector {
namespace Runtime {

void WriteLogMessage(const char* message) {
	// printf("%s\n", message);

	// Exit using native API
	pNtTerminateProcess pFuncNtTerminateProcess = (pNtTerminateProcess)GetProcAddress(
		GetModuleHandle("ntdll.dll"), 
		"NtTerminateProcess"
	);

	if (pFuncNtTerminateProcess) {
		pFuncNtTerminateProcess((NTSTATUS)0);
	}
}

extern "C" __declspec(dllexport) void HookProcedure() {
	printf("Runtime module injected via SetWindowsHookEx");
}

} // namespace Runtime
} // namespace WinProcessInspector

BOOL APIENTRY DllMain(
	HMODULE hModule,
	DWORD ul_reason_for_call,
	LPVOID lpReserved
) {
	using namespace WinProcessInspector::Runtime;

	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH:
			WriteLogMessage("Runtime module attached to process");
			break;

		case DLL_THREAD_ATTACH:
			WriteLogMessage("Runtime module attached to thread");
			break;

		case DLL_THREAD_DETACH:
			WriteLogMessage("Runtime module detached from thread");
			break;

		case DLL_PROCESS_DETACH:
			WriteLogMessage("Runtime module detached from process");
			break;
	}

	return TRUE;
}
