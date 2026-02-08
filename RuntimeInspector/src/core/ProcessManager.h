#pragma once

#include <Windows.h>
#include <tlHelp32.h>
#include <vector>
#include <string>

namespace RuntimeInspector {
namespace Core {

	struct ProcessInfo {
		DWORD ProcessId;
		DWORD ParentProcessId;
		std::string ProcessName;
		std::string Architecture;
	};

	std::vector<ProcessInfo> EnumerateAllProcesses();
	DWORD SelectProcessFromList();
	DWORD FindProcessByName(const char* processName);
	HANDLE OpenTargetProcess(DWORD processId);

}
}
