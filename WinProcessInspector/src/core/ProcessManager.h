#pragma once

#include <Windows.h>
#include <tlHelp32.h>
#include <vector>
#include <string>
#include <memory>
#include "HandleWrapper.h"
#include "../security/SecurityManager.h"

namespace WinProcessInspector {
namespace Core {

	struct ProcessInfo {
		DWORD ProcessId = 0;
		DWORD ParentProcessId = 0;
		std::string ProcessName;
		std::string Architecture;
		DWORD SessionId = 0;
		Security::IntegrityLevel IntegrityLevel = Security::IntegrityLevel::Unknown;
		std::wstring UserSid;
		std::wstring UserName;
		std::wstring UserDomain;
	};

	struct ThreadInfo {
		DWORD ThreadId = 0;
		DWORD ProcessId = 0;
		ULONG_PTR StartAddress = 0;
		DWORD State = 0; 
		int Priority = 0; 
		DWORD WaitReason = 0; 
	};

	class ProcessManager {
	public:
		ProcessManager() = default;
		~ProcessManager() = default;

		ProcessManager(const ProcessManager&) = delete;
		ProcessManager& operator=(const ProcessManager&) = delete;
		ProcessManager(ProcessManager&&) = default;
		ProcessManager& operator=(ProcessManager&&) = default;

		std::vector<ProcessInfo> EnumerateAllProcesses() const;
		ProcessInfo GetProcessDetails(DWORD processId) const;
		DWORD FindProcessByName(const char* processName) const;
		std::vector<ThreadInfo> EnumerateThreads(DWORD processId) const;
		HandleWrapper OpenProcess(DWORD processId, DWORD desiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) const;
		std::string GetProcessArchitecture(DWORD processId) const;
		DWORD GetProcessSessionId(DWORD processId) const;
		bool GetProcessUser(DWORD processId, std::wstring& userSid, std::wstring& userName, std::wstring& userDomain) const;

	private:

		std::string GetArchitectureFromHandle(HANDLE hProcess) const;
		ULONG_PTR GetThreadStartAddress(HANDLE hThread) const;
		bool GetThreadState(HANDLE hThread, DWORD& state, DWORD& waitReason) const;
	};

}
}
