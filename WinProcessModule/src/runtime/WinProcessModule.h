#pragma once

#include <stdio.h>
#include <Windows.h>

namespace WinProcessInspector {
namespace Runtime {

	// Logging functionality
	void WriteLogMessage(const char* message);

	// Hook procedure for SetWindowsHookEx injection
	extern "C" __declspec(dllexport) void HookProcedure();

} // namespace Runtime
} // namespace WinProcessInspector

// Native API function pointer definitions
typedef NTSTATUS (WINAPI* pNtTerminateProcess)(
	IN	NTSTATUS	ExitStatus
);
