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

	/**
	 * Process information structure
	 */
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

	/**
	 * Thread information structure
	 */
	struct ThreadInfo {
		DWORD ThreadId = 0;
		DWORD ProcessId = 0;
		ULONG_PTR StartAddress = 0;
		DWORD State = 0; // THREAD_STATE_* constants
		int Priority = 0; // Thread priority
		DWORD WaitReason = 0; // Wait reason code
	};

	/**
	 * Process manager for enumerating and querying processes
	 * Uses RAII for safe resource management
	 */
	class ProcessManager {
	public:
		ProcessManager() = default;
		~ProcessManager() = default;

		// Non-copyable, movable
		ProcessManager(const ProcessManager&) = delete;
		ProcessManager& operator=(const ProcessManager&) = delete;
		ProcessManager(ProcessManager&&) = default;
		ProcessManager& operator=(ProcessManager&&) = default;

		/**
		 * Enumerate all running processes
		 * @return Vector of process information
		 */
		std::vector<ProcessInfo> EnumerateAllProcesses() const;

		/**
		 * Get detailed information for a specific process
		 * @param processId Process ID
		 * @return ProcessInfo with full details (empty ProcessId if failed)
		 */
		ProcessInfo GetProcessDetails(DWORD processId) const;

		/**
		 * Find a process by name (first match)
		 * @param processName Process executable name (UTF-8)
		 * @return Process ID if found, 0 otherwise
		 */
		DWORD FindProcessByName(const char* processName) const;

		/**
		 * Enumerate threads for a specific process
		 * @param processId Process ID
		 * @return Vector of thread information
		 */
		std::vector<ThreadInfo> EnumerateThreads(DWORD processId) const;

		/**
		 * Open a process handle with specified access rights
		 * @param processId Process ID
		 * @param desiredAccess Desired access rights
		 * @return HandleWrapper with process handle (invalid if failed)
		 */
		HandleWrapper OpenProcess(DWORD processId, DWORD desiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) const;

		/**
		 * Get process architecture (x86/x64)
		 * @param processId Process ID
		 * @return Architecture string ("x86", "x64", or "?")
		 */
		std::string GetProcessArchitecture(DWORD processId) const;

		/**
		 * Get process session ID
		 * @param processId Process ID
		 * @return Session ID, or 0 if failed
		 */
		DWORD GetProcessSessionId(DWORD processId) const;

		/**
		 * Get process user SID and account name
		 * @param processId Process ID
		 * @param userSid Output: User SID string
		 * @param userName Output: User account name
		 * @param userDomain Output: User domain name
		 * @return true if successful, false otherwise
		 */
		bool GetProcessUser(DWORD processId, std::wstring& userSid, std::wstring& userName, std::wstring& userDomain) const;

	private:
		/**
		 * Helper to get architecture from process handle
		 */
		std::string GetArchitectureFromHandle(HANDLE hProcess) const;

		/**
		 * Helper to get thread start address using NtQueryInformationThread
		 */
		ULONG_PTR GetThreadStartAddress(HANDLE hThread) const;

		/**
		 * Helper to get thread state and wait reason
		 */
		bool GetThreadState(HANDLE hThread, DWORD& state, DWORD& waitReason) const;
	};

} // namespace Core
} // namespace WinProcessInspector
