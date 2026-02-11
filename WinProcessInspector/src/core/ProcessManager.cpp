#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>

#include "ProcessManager.h"
#include "../security/SecurityManager.h"
#include <psapi.h>
#include <sddl.h>
#include <sstream>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

typedef NTSTATUS (WINAPI* pNtQueryInformationThread)(
	HANDLE ThreadHandle,
	ULONG ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength
);

typedef NTSTATUS (WINAPI* pNtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

#define ThreadQuerySetWin32StartAddress 9
#define SystemProcessInformation 5

namespace WinProcessInspector {
namespace Core {

std::vector<ProcessInfo> ProcessManager::EnumerateAllProcesses() const {
	std::vector<ProcessInfo> processes;

	PROCESSENTRY32W pe32 = {};
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	HandleWrapper hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	if (!hSnap.IsValid() || hSnap.Get() == INVALID_HANDLE_VALUE) {
		return processes;
	}

	if (Process32FirstW(hSnap.Get(), &pe32)) {
		do {
			ProcessInfo info;
			info.ProcessId = pe32.th32ProcessID;
			info.ParentProcessId = pe32.th32ParentProcessID;

			int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, nullptr, 0, nullptr, nullptr);
			if (sizeNeeded > 0) {
				std::string processName(sizeNeeded, 0);
				WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, &processName[0], sizeNeeded, nullptr, nullptr);
				processName.pop_back();
				info.ProcessName = processName;
			}


			info.Architecture = GetProcessArchitecture(pe32.th32ProcessID);
			info.SessionId = GetProcessSessionId(pe32.th32ProcessID);
			Security::SecurityManager secMgr;
			info.IntegrityLevel = secMgr.GetProcessIntegrityLevel(pe32.th32ProcessID);
			GetProcessUser(pe32.th32ProcessID, info.UserSid, info.UserName, info.UserDomain);

			processes.push_back(info);
		} while (Process32NextW(hSnap.Get(), &pe32));
	}

	return processes;
}

ProcessInfo ProcessManager::GetProcessDetails(DWORD processId) const {
	ProcessInfo info;
	info.ProcessId = processId;

	HandleWrapper hProcess = OpenProcess(processId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
	if (!hProcess.IsValid()) {
		return info;
	}

	WCHAR processName[MAX_PATH] = {};
	DWORD processNameLen = MAX_PATH;
	if (QueryFullProcessImageNameW(hProcess.Get(), 0, processName, &processNameLen)) {
		int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, processName, -1, nullptr, 0, nullptr, nullptr);
		if (sizeNeeded > 0) {
			std::string name(sizeNeeded, 0);
			WideCharToMultiByte(CP_UTF8, 0, processName, -1, &name[0], sizeNeeded, nullptr, nullptr);
			name.pop_back();
			info.ProcessName = name;
		}
	}

	info.Architecture = GetArchitectureFromHandle(hProcess.Get());

	PROCESSENTRY32W pe32 = {};
	pe32.dwSize = sizeof(PROCESSENTRY32W);
	HandleWrapper hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	if (hSnap.IsValid() && Process32FirstW(hSnap.Get(), &pe32)) {
		do {
			if (pe32.th32ProcessID == processId) {
				info.ParentProcessId = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32NextW(hSnap.Get(), &pe32));
	}

	info.SessionId = GetProcessSessionId(processId);
	Security::SecurityManager secMgr;
	info.IntegrityLevel = secMgr.GetProcessIntegrityLevel(processId);
	GetProcessUser(processId, info.UserSid, info.UserName, info.UserDomain);

	return info;
}

DWORD ProcessManager::FindProcessByName(const char* processName) const {
	PROCESSENTRY32W pe32 = {};
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	HandleWrapper hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	if (!hSnap.IsValid() || hSnap.Get() == INVALID_HANDLE_VALUE) {
		return 0;
	}

	int wlen = MultiByteToWideChar(CP_UTF8, 0, processName, -1, nullptr, 0);
	if (wlen <= 0) {
		return 0;
	}

	std::vector<wchar_t> wprocessName(wlen);
	MultiByteToWideChar(CP_UTF8, 0, processName, -1, &wprocessName[0], wlen);

	if (!Process32FirstW(hSnap.Get(), &pe32)) {
		return 0;
	}

	do {
		if (_wcsicmp(pe32.szExeFile, &wprocessName[0]) == 0) {
			return pe32.th32ProcessID;
		}
	} while (Process32NextW(hSnap.Get(), &pe32));

	return 0;
}

std::vector<ThreadInfo> ProcessManager::EnumerateThreads(DWORD processId) const {
	std::vector<ThreadInfo> threads;

	THREADENTRY32 te32 = {};
	te32.dwSize = sizeof(THREADENTRY32);

	HandleWrapper hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
	if (!hSnap.IsValid() || hSnap.Get() == INVALID_HANDLE_VALUE) {
		return threads;
	}

	if (Thread32First(hSnap.Get(), &te32)) {
		do {
			if (te32.th32OwnerProcessID == processId) {
				ThreadInfo info;
				info.ThreadId = te32.th32ThreadID;
				info.ProcessId = te32.th32OwnerProcessID;

				HandleWrapper hThread(OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, info.ThreadId));
				if (hThread.IsValid()) {
					info.StartAddress = GetThreadStartAddress(hThread.Get());
					DWORD state = 0, waitReason = 0;
					if (GetThreadState(hThread.Get(), state, waitReason)) {
						info.State = state;
						info.WaitReason = waitReason;
					}
					info.Priority = GetThreadPriority(hThread.Get());
				}

				threads.push_back(info);
			}
		} while (Thread32Next(hSnap.Get(), &te32));
	}

	return threads;
}

HandleWrapper ProcessManager::OpenProcess(DWORD processId, DWORD desiredAccess) const {
	HANDLE hProcess = ::OpenProcess(desiredAccess, FALSE, processId);
	return HandleWrapper(hProcess);
}

std::string ProcessManager::GetProcessArchitecture(DWORD processId) const {
	HandleWrapper hProcess = OpenProcess(processId, PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION);
	if (!hProcess.IsValid()) {
		return "?";
	}

	return GetArchitectureFromHandle(hProcess.Get());
}

DWORD ProcessManager::GetProcessSessionId(DWORD processId) const {
	DWORD sessionId = 0;
	if (ProcessIdToSessionId(processId, &sessionId)) {
		return sessionId;
	}
	return 0;
}

bool ProcessManager::GetProcessUser(DWORD processId, std::wstring& userSid, std::wstring& userName, std::wstring& userDomain) const {
	HandleWrapper hProcess = OpenProcess(processId, PROCESS_QUERY_INFORMATION);
	if (!hProcess.IsValid()) {
		return false;
	}

	HANDLE hToken = nullptr;
	if (!OpenProcessToken(hProcess.Get(), TOKEN_QUERY, &hToken)) {
		return false;
	}

	DWORD length = 0;
	GetTokenInformation(hToken, TokenUser, nullptr, 0, &length);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		CloseHandle(hToken);
		return false;
	}

	std::vector<BYTE> buffer(length);
	PTOKEN_USER ptu = reinterpret_cast<PTOKEN_USER>(buffer.data());
	if (!GetTokenInformation(hToken, TokenUser, ptu, length, &length)) {
		CloseHandle(hToken);
		return false;
	}

	LPWSTR sidString = nullptr;
	if (ConvertSidToStringSidW(ptu->User.Sid, &sidString)) {
		userSid = sidString;
		LocalFree(sidString);
	}

	WCHAR name[256] = {};
	WCHAR domain[256] = {};
	DWORD nameLen = sizeof(name) / sizeof(name[0]);
	DWORD domainLen = sizeof(domain) / sizeof(domain[0]);
	SID_NAME_USE use;

	if (LookupAccountSidW(nullptr, ptu->User.Sid, name, &nameLen, domain, &domainLen, &use)) {
		userName = name;
		userDomain = domain;
	}

	CloseHandle(hToken);
	return true;
}

std::string ProcessManager::GetArchitectureFromHandle(HANDLE hProcess) const {
	BOOL isWow64 = FALSE;
	if (IsWow64Process(hProcess, &isWow64)) {
		if (isWow64) {
			return "x86";
		} else {
			SYSTEM_INFO si;
			GetNativeSystemInfo(&si);
			if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
				si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
				return "x64";
			} else {
				return "x86";
			}
		}
	} else {
		SYSTEM_INFO si;
		GetNativeSystemInfo(&si);
		if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
			si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
			return "x64";
		} else {
			return "x86";
		}
	}
}

ULONG_PTR ProcessManager::GetThreadStartAddress(HANDLE hThread) const {
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll) {
		return 0;
	}

	pNtQueryInformationThread NtQueryInformationThread = reinterpret_cast<pNtQueryInformationThread>(
		GetProcAddress(hNtdll, "NtQueryInformationThread"));
	if (!NtQueryInformationThread) {
		return 0;
	}

	ULONG_PTR startAddress = 0;
	ULONG returnLength = 0;
	NTSTATUS status = NtQueryInformationThread(
		hThread,
		static_cast<ULONG>(ThreadQuerySetWin32StartAddress),
		&startAddress,
		sizeof(startAddress),
		&returnLength
	);

	if (NT_SUCCESS(status)) {
		return startAddress;
	}

	return 0;
}

bool ProcessManager::GetThreadState(HANDLE hThread, DWORD& state, DWORD& waitReason) const {
	DWORD suspendCount = SuspendThread(hThread);
	if (suspendCount != (DWORD)-1) {
		if (suspendCount > 0) {
			ResumeThread(hThread);
			state = 5; // THREAD_STATE_WAITING (suspended)
		} else {
			state = 2; // THREAD_STATE_RUNNING
		}
		waitReason = 0;
		return true;
	}

	return false;
}

}
} 
