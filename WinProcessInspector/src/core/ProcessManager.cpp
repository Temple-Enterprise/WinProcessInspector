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

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _UNICODE_STRING32 {
	USHORT Length;
	USHORT MaximumLength;
	ULONG Buffer;
} UNICODE_STRING32;

typedef struct _UNICODE_STRING64 {
	USHORT Length;
	USHORT MaximumLength;
	ULONGLONG Buffer;
} UNICODE_STRING64;

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
			
			info.CommandLine = GetProcessCommandLine(pe32.th32ProcessID);
			info.ThreadCount = pe32.cntThreads;
			
			FILETIME creationTime, exitTime, kernelTime, userTime;
			if (GetProcessTimes(pe32.th32ProcessID, creationTime, exitTime, kernelTime, userTime)) {
				info.CreationTime = creationTime;
			}
			
			DWORD threadCount, handleCount;
			if (GetProcessCounts(pe32.th32ProcessID, threadCount, handleCount)) {
				info.HandleCount = handleCount;
			}
			
			GetProcessGdiUserCounts(pe32.th32ProcessID, info.GdiObjectCount, info.UserObjectCount);
			GetProcessIoCounters(pe32.th32ProcessID, info.ReadOperationCount, info.WriteOperationCount, 
				info.ReadTransferCount, info.WriteTransferCount);
			
			HandleWrapper hProc = OpenProcess(pe32.th32ProcessID, PROCESS_QUERY_INFORMATION);
			if (hProc.IsValid()) {
				PROCESS_MEMORY_COUNTERS_EX pmc = {};
				pmc.cb = sizeof(pmc);
				if (GetProcessMemoryInfo(hProc.Get(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
					info.PeakWorkingSetSize = pmc.PeakWorkingSetSize;
					info.PageFaultCount = pmc.PageFaultCount;
				}
			}
			
			GetProcessMitigations(pe32.th32ProcessID, info.DEPEnabled, info.ASLREnabled, info.CFGEnabled);
			info.IsVirtualized = IsProcessVirtualized(pe32.th32ProcessID);
			info.IsAppContainer = IsProcessAppContainer(pe32.th32ProcessID);
			info.IsInJob = IsProcessInJob(pe32.th32ProcessID);
			
			GetProcessPriorityClass(pe32.th32ProcessID, info.PriorityClass);
			DWORD_PTR processAffinity, systemAffinity;
			if (GetProcessAffinityMask(pe32.th32ProcessID, processAffinity, systemAffinity)) {
				info.AffinityMask = processAffinity;
			}

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
			state = 5;
		} else {
			state = 2;
		}
		waitReason = 0;
		return true;
	}

	return false;
}

std::wstring ProcessManager::GetProcessCommandLine(DWORD processId) const {
	HandleWrapper hProcess = OpenProcess(processId, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ);
	if (!hProcess.IsValid()) {
		return L"";
	}

	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll) {
		return L"";
	}

	typedef NTSTATUS (WINAPI* pNtQueryInformationProcess)(
		HANDLE ProcessHandle,
		ULONG ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength,
		PULONG ReturnLength
	);

	pNtQueryInformationProcess NtQueryInformationProcess = 
		reinterpret_cast<pNtQueryInformationProcess>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
	
	if (!NtQueryInformationProcess) {
		return L"";
	}

	PROCESS_BASIC_INFORMATION pbi = {};
	ULONG returnLength = 0;
	NTSTATUS status = NtQueryInformationProcess(hProcess.Get(), 0, &pbi, sizeof(pbi), &returnLength);
	
	if (!NT_SUCCESS(status) || !pbi.PebBaseAddress) {
		return L"";
	}

	BOOL isWow64 = FALSE;
	IsWow64Process(hProcess.Get(), &isWow64);

#ifdef _WIN64
	if (isWow64) {
		ULONG pebAddress32 = 0;
		status = NtQueryInformationProcess(hProcess.Get(), ProcessWow64Information, &pebAddress32, sizeof(pebAddress32), &returnLength);
		if (!NT_SUCCESS(status) || pebAddress32 == 0) {
			return L"";
		}

		ULONG rtlUserProcParamsAddress32 = 0;
		SIZE_T bytesRead = 0;
		if (!ReadProcessMemory(hProcess.Get(), (PVOID)(ULONG_PTR)(pebAddress32 + 0x10), &rtlUserProcParamsAddress32, sizeof(rtlUserProcParamsAddress32), &bytesRead)) {
			return L"";
		}

		if (rtlUserProcParamsAddress32 == 0) {
			return L"";
		}

		UNICODE_STRING32 commandLine32 = {};
		if (!ReadProcessMemory(hProcess.Get(), (PVOID)(ULONG_PTR)(rtlUserProcParamsAddress32 + 0x40), &commandLine32, sizeof(commandLine32), &bytesRead)) {
			return L"";
		}

		if (commandLine32.Length == 0 || commandLine32.Length > 32768 || commandLine32.Buffer == 0) {
			return L"";
		}

		std::vector<WCHAR> buffer(commandLine32.Length / sizeof(WCHAR) + 1);
		if (!ReadProcessMemory(hProcess.Get(), (PVOID)(ULONG_PTR)commandLine32.Buffer, buffer.data(), commandLine32.Length, &bytesRead)) {
			return L"";
		}

		buffer[commandLine32.Length / sizeof(WCHAR)] = L'\0';
		return std::wstring(buffer.data());
	}
#endif

	PVOID rtlUserProcParamsAddress = nullptr;
	SIZE_T bytesRead = 0;
	
	if (!ReadProcessMemory(hProcess.Get(), 
		(PCHAR)pbi.PebBaseAddress + 0x20,
		&rtlUserProcParamsAddress, sizeof(rtlUserProcParamsAddress), &bytesRead)) {
		return L"";
	}

	if (!rtlUserProcParamsAddress) {
		return L"";
	}

	UNICODE_STRING commandLine = {};
	if (!ReadProcessMemory(hProcess.Get(),
		(PCHAR)rtlUserProcParamsAddress + 0x70,
		&commandLine, sizeof(commandLine), &bytesRead)) {
		return L"";
	}

	if (commandLine.Length == 0 || commandLine.Length > 32768 || !commandLine.Buffer) {
		return L"";
	}

	std::vector<WCHAR> buffer(commandLine.Length / sizeof(WCHAR) + 1);
	if (!ReadProcessMemory(hProcess.Get(), commandLine.Buffer, buffer.data(), commandLine.Length, &bytesRead)) {
		return L"";
	}

	buffer[commandLine.Length / sizeof(WCHAR)] = L'\0';
	return std::wstring(buffer.data());
}

bool ProcessManager::GetProcessTimes(DWORD processId, FILETIME& creationTime, FILETIME& exitTime, 
	FILETIME& kernelTime, FILETIME& userTime) const {
	HandleWrapper hProcess = OpenProcess(processId, PROCESS_QUERY_INFORMATION);
	if (!hProcess.IsValid()) {
		return false;
	}

	return ::GetProcessTimes(hProcess.Get(), &creationTime, &exitTime, &kernelTime, &userTime) != FALSE;
}

bool ProcessManager::GetProcessCounts(DWORD processId, DWORD& threadCount, DWORD& handleCount) const {
	HandleWrapper hProcess = OpenProcess(processId, PROCESS_QUERY_INFORMATION);
	if (!hProcess.IsValid()) {
		return false;
	}

	DWORD handleCountLocal = 0;
	if (::GetProcessHandleCount(hProcess.Get(), &handleCountLocal)) {
		handleCount = handleCountLocal;
	}

	HandleWrapper hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
	if (hSnap.IsValid()) {
		THREADENTRY32 te32 = {};
		te32.dwSize = sizeof(THREADENTRY32);
		
		threadCount = 0;
		if (Thread32First(hSnap.Get(), &te32)) {
			do {
				if (te32.th32OwnerProcessID == processId) {
					threadCount++;
				}
			} while (Thread32Next(hSnap.Get(), &te32));
		}
	}

	return true;
}

bool ProcessManager::GetProcessGdiUserCounts(DWORD processId, DWORD& gdiCount, DWORD& userCount) const {
	HandleWrapper hProcess = OpenProcess(processId, PROCESS_QUERY_INFORMATION);
	if (!hProcess.IsValid()) {
		return false;
	}

	gdiCount = GetGuiResources(hProcess.Get(), GR_GDIOBJECTS);
	userCount = GetGuiResources(hProcess.Get(), GR_USEROBJECTS);
	
	return (gdiCount > 0 || userCount > 0);
}

bool ProcessManager::GetProcessIoCounters(DWORD processId, ULONGLONG& readOps, ULONGLONG& writeOps, 
	ULONGLONG& readBytes, ULONGLONG& writeBytes) const {
	HandleWrapper hProcess = OpenProcess(processId, PROCESS_QUERY_INFORMATION);
	if (!hProcess.IsValid()) {
		return false;
	}

	IO_COUNTERS ioCounters = {};
	if (!::GetProcessIoCounters(hProcess.Get(), &ioCounters)) {
		return false;
	}

	readOps = ioCounters.ReadOperationCount;
	writeOps = ioCounters.WriteOperationCount;
	readBytes = ioCounters.ReadTransferCount;
	writeBytes = ioCounters.WriteTransferCount;

	return true;
}

bool ProcessManager::GetProcessMitigations(DWORD processId, bool& depEnabled, bool& aslrEnabled, bool& cfgEnabled) const {
	HandleWrapper hProcess = OpenProcess(processId, PROCESS_QUERY_INFORMATION);
	if (!hProcess.IsValid()) {
		return false;
	}

	PROCESS_MITIGATION_DEP_POLICY depPolicy = {};
	PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = {};
	PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy = {};

	typedef BOOL (WINAPI* pGetProcessMitigationPolicy)(
		HANDLE hProcess,
		DWORD MitigationPolicy,
		PVOID lpBuffer,
		SIZE_T dwLength
	);

	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	if (!hKernel32) {
		return false;
	}

	pGetProcessMitigationPolicy GetProcessMitigationPolicy =
		reinterpret_cast<pGetProcessMitigationPolicy>(GetProcAddress(hKernel32, "GetProcessMitigationPolicy"));

	if (!GetProcessMitigationPolicy) {
		return false;
	}

	if (GetProcessMitigationPolicy(hProcess.Get(), 0, &depPolicy, sizeof(depPolicy))) {
		depEnabled = depPolicy.Enable != 0;
	}

	if (GetProcessMitigationPolicy(hProcess.Get(), 1, &aslrPolicy, sizeof(aslrPolicy))) {
		aslrEnabled = aslrPolicy.EnableBottomUpRandomization != 0 || aslrPolicy.EnableForceRelocateImages != 0;
	}

	if (GetProcessMitigationPolicy(hProcess.Get(), 7, &cfgPolicy, sizeof(cfgPolicy))) {
		cfgEnabled = cfgPolicy.EnableControlFlowGuard != 0;
	}

	return true;
}

bool ProcessManager::IsProcessVirtualized(DWORD processId) const {
	HandleWrapper hProcess = OpenProcess(processId, PROCESS_QUERY_INFORMATION);
	if (!hProcess.IsValid()) {
		return false;
	}

	HANDLE hToken = nullptr;
	if (!OpenProcessToken(hProcess.Get(), TOKEN_QUERY, &hToken)) {
		return false;
	}

	DWORD virtualized = 0;
	DWORD returnLength = 0;
	bool result = false;

	if (GetTokenInformation(hToken, static_cast<TOKEN_INFORMATION_CLASS>(24), &virtualized, sizeof(virtualized), &returnLength)) {
		result = (virtualized != 0);
	}

	CloseHandle(hToken);
	return result;
}

bool ProcessManager::IsProcessAppContainer(DWORD processId) const {
	HandleWrapper hProcess = OpenProcess(processId, PROCESS_QUERY_INFORMATION);
	if (!hProcess.IsValid()) {
		return false;
	}

	HANDLE hToken = nullptr;
	if (!OpenProcessToken(hProcess.Get(), TOKEN_QUERY, &hToken)) {
		return false;
	}

	DWORD isAppContainer = 0;
	DWORD returnLength = 0;
	bool result = false;

	if (GetTokenInformation(hToken, static_cast<TOKEN_INFORMATION_CLASS>(29), &isAppContainer, sizeof(isAppContainer), &returnLength)) {
		result = (isAppContainer != 0);
	}

	CloseHandle(hToken);
	return result;
}

bool ProcessManager::IsProcessInJob(DWORD processId) const {
	HandleWrapper hProcess = OpenProcess(processId, PROCESS_QUERY_INFORMATION);
	if (!hProcess.IsValid()) {
		return false;
	}

	BOOL isInJob = FALSE;
	if (::IsProcessInJob(hProcess.Get(), nullptr, &isInJob)) {
		return isInJob != FALSE;
	}

	return false;
}

bool ProcessManager::GetProcessPriorityClass(DWORD processId, DWORD& priorityClass) const {
	HandleWrapper hProcess = OpenProcess(processId, PROCESS_QUERY_INFORMATION);
	if (!hProcess.IsValid()) {
		return false;
	}
	
	priorityClass = GetPriorityClass(hProcess.Get());
	return priorityClass != 0;
}

bool ProcessManager::SetProcessPriorityClass(DWORD processId, DWORD priorityClass) const {
	HandleWrapper hProcess = OpenProcess(processId, PROCESS_SET_INFORMATION);
	if (!hProcess.IsValid()) {
		return false;
	}
	
	return SetPriorityClass(hProcess.Get(), priorityClass) != FALSE;
}

bool ProcessManager::GetProcessAffinityMask(DWORD processId, DWORD_PTR& processAffinityMask, DWORD_PTR& systemAffinityMask) const {
	HandleWrapper hProcess = OpenProcess(processId, PROCESS_QUERY_INFORMATION);
	if (!hProcess.IsValid()) {
		return false;
	}
	
	return ::GetProcessAffinityMask(hProcess.Get(), &processAffinityMask, &systemAffinityMask) != FALSE;
}

bool ProcessManager::SetProcessAffinityMask(DWORD processId, DWORD_PTR affinityMask) const {
	HandleWrapper hProcess = OpenProcess(processId, PROCESS_SET_INFORMATION);
	if (!hProcess.IsValid()) {
		return false;
	}
	
	return ::SetProcessAffinityMask(hProcess.Get(), affinityMask) != FALSE;
}

std::wstring ProcessManager::GetPriorityClassString(DWORD priorityClass) const {
	switch (priorityClass) {
		case IDLE_PRIORITY_CLASS:
			return L"Idle";
		case BELOW_NORMAL_PRIORITY_CLASS:
			return L"Below Normal";
		case NORMAL_PRIORITY_CLASS:
			return L"Normal";
		case ABOVE_NORMAL_PRIORITY_CLASS:
			return L"Above Normal";
		case HIGH_PRIORITY_CLASS:
			return L"High";
		case REALTIME_PRIORITY_CLASS:
			return L"Realtime";
		default:
			return L"Unknown";
	}
}

} // namespace Core
} // namespace WinProcessInspector
