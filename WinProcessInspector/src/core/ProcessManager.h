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
		std::wstring CommandLine;
		FILETIME CreationTime = {};
		DWORD ThreadCount = 0;
		DWORD HandleCount = 0;
		DWORD GdiObjectCount = 0;
		DWORD UserObjectCount = 0;
		SIZE_T PeakWorkingSetSize = 0;
		ULONGLONG ReadOperationCount = 0;
		ULONGLONG WriteOperationCount = 0;
		ULONGLONG ReadTransferCount = 0;
		ULONGLONG WriteTransferCount = 0;
		DWORD PageFaultCount = 0;
		bool DEPEnabled = false;
		bool ASLREnabled = false;
		bool CFGEnabled = false;
		bool IsVirtualized = false;
		bool IsAppContainer = false;
		bool IsInJob = false;
		DWORD PriorityClass = 0;
		DWORD_PTR AffinityMask = 0;
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
		
		std::wstring GetProcessCommandLine(DWORD processId) const;
		bool GetProcessTimes(DWORD processId, FILETIME& creationTime, FILETIME& exitTime, FILETIME& kernelTime, FILETIME& userTime) const;
		bool GetProcessCounts(DWORD processId, DWORD& threadCount, DWORD& handleCount) const;
		bool GetProcessGdiUserCounts(DWORD processId, DWORD& gdiCount, DWORD& userCount) const;
		bool GetProcessIoCounters(DWORD processId, ULONGLONG& readOps, ULONGLONG& writeOps, ULONGLONG& readBytes, ULONGLONG& writeBytes) const;
		bool GetProcessMitigations(DWORD processId, bool& depEnabled, bool& aslrEnabled, bool& cfgEnabled) const;
		bool IsProcessVirtualized(DWORD processId) const;
		bool IsProcessAppContainer(DWORD processId) const;
		bool IsProcessInJob(DWORD processId) const;
		
		bool GetProcessPriorityClass(DWORD processId, DWORD& priorityClass) const;
		bool SetProcessPriorityClass(DWORD processId, DWORD priorityClass) const;
		bool GetProcessAffinityMask(DWORD processId, DWORD_PTR& processAffinityMask, DWORD_PTR& systemAffinityMask) const;
		bool SetProcessAffinityMask(DWORD processId, DWORD_PTR affinityMask) const;
		std::wstring GetPriorityClassString(DWORD priorityClass) const;

	private:
		std::string GetArchitectureFromHandle(HANDLE hProcess) const;

		ULONG_PTR GetThreadStartAddress(HANDLE hThread) const;

		bool GetThreadState(HANDLE hThread, DWORD& state, DWORD& waitReason) const;
	};

} // namespace Core
} // namespace WinProcessInspector
