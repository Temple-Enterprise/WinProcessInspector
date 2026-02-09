// NT API includes - must define WIN32_NO_STATUS before windows.h
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>

#include "HandleManager.h"
#include "HandleWrapper.h"
#include <psapi.h>
#include <vector>
#include <map>
#include <sstream>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

// NT API structures and constants
#define SystemHandleInformation 16

typedef struct _SYSTEM_HANDLE_INFORMATION {
	USHORT ProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
	ULONG_PTR NumberOfHandles;
	SYSTEM_HANDLE_INFORMATION Information[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

// Object type names mapping (common types)
static const std::map<WORD, std::wstring> ObjectTypeNames = {
	{ 2, L"Type" },
	{ 3, L"Directory" },
	{ 4, L"SymbolicLink" },
	{ 5, L"Token" },
	{ 6, L"Job" },
	{ 7, L"Process" },
	{ 8, L"Thread" },
	{ 9, L"UserApcReserve" },
	{ 10, L"IoCompletionReserve" },
	{ 11, L"DebugObject" },
	{ 12, L"Event" },
	{ 13, L"EventPair" },
	{ 14, L"Mutant" },
	{ 15, L"Callback" },
	{ 16, L"Semaphore" },
	{ 17, L"Timer" },
	{ 18, L"Profile" },
	{ 19, L"KeyedEvent" },
	{ 20, L"WindowStation" },
	{ 21, L"Desktop" },
	{ 22, L"Composition" },
	{ 23, L"RawInputManager" },
	{ 24, L"CoreMessaging" },
	{ 25, L"File" },
	{ 26, L"TpWorkerFactory" },
	{ 27, L"Adapter" },
	{ 28, L"Controller" },
	{ 29, L"Device" },
	{ 30, L"Driver" },
	{ 31, L"IoCompletion" },
	{ 32, L"WaitCompletionPacket" },
	{ 33, L"Section" },
	{ 34, L"Session" },
	{ 35, L"Key" },
	{ 36, L"ALPC Port" },
	{ 37, L"PowerRequest" },
	{ 38, L"WmiGuid" },
	{ 39, L"EtwRegistration" },
	{ 40, L"EtwSession" },
	{ 41, L"EtwConsumer" },
	{ 42, L"EtwProvider" },
	{ 43, L"FilterConnectionPort" },
	{ 44, L"FilterCommunicationPort" },
	{ 45, L"PcwObject" },
	{ 46, L"FilterCommunicationPort" },
};

namespace WinProcessInspector {
namespace Core {

std::vector<HandleInfo> HandleManager::EnumerateHandles(DWORD processId) const {
	std::vector<HandleInfo> allHandles;
	if (!QuerySystemHandles(allHandles)) {
		return std::vector<HandleInfo>();
	}

	// Filter handles for the specific process
	std::vector<HandleInfo> processHandles;
	for (const auto& handle : allHandles) {
		if (handle.ProcessId == processId) {
			processHandles.push_back(handle);
		}
	}

	return processHandles;
}

std::vector<HandleInfo> HandleManager::EnumerateAllHandles() const {
	std::vector<HandleInfo> handles;
	QuerySystemHandles(handles);
	return handles;
}

std::wstring HandleManager::GetObjectTypeName(WORD typeIndex) const {
	auto it = ObjectTypeNames.find(typeIndex);
	if (it != ObjectTypeNames.end()) {
		return it->second;
	}

	// Try to query object type name from system
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (hNtdll) {
		typedef NTSTATUS (WINAPI* pNtQueryObject)(
			HANDLE Handle,
			ULONG ObjectInformationClass,
			PVOID ObjectInformation,
			ULONG ObjectInformationLength,
			PULONG ReturnLength
		);

		pNtQueryObject NtQueryObject = reinterpret_cast<pNtQueryObject>(
			GetProcAddress(hNtdll, "NtQueryObject"));
		if (NtQueryObject) {
			// ObjectTypeInformation = 2
			ULONG returnLength = 0;
			NtQueryObject(nullptr, 2, nullptr, 0, &returnLength);
			if (returnLength > 0) {
				std::vector<BYTE> buffer(returnLength);
				if (NT_SUCCESS(NtQueryObject(nullptr, 2, buffer.data(), returnLength, &returnLength))) {
					// Parse object type information
					// This is complex and requires parsing UNICODE_STRING structures
				}
			}
		}
	}

	// Fallback to type index
	std::wostringstream oss;
	oss << L"Type" << typeIndex;
	return oss.str();
}

std::wstring HandleManager::GetObjectName(HANDLE hProcess, HANDLE handleValue) const {
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll) {
		return L"";
	}

	typedef NTSTATUS (WINAPI* pNtQueryObject)(
		HANDLE Handle,
		ULONG ObjectInformationClass,
		PVOID ObjectInformation,
		ULONG ObjectInformationLength,
		PULONG ReturnLength
	);

	pNtQueryObject NtQueryObject = reinterpret_cast<pNtQueryObject>(
		GetProcAddress(hNtdll, "NtQueryObject"));
	if (!NtQueryObject) {
		return L"";
	}

	// ObjectNameInformation = 1
	ULONG returnLength = 0;
	NTSTATUS status = NtQueryObject(handleValue, 1, nullptr, 0, &returnLength);
	if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL) {
		return L"";
	}

	if (returnLength == 0 || returnLength > 65536) {
		return L"";
	}

	std::vector<BYTE> buffer(returnLength);
	status = NtQueryObject(handleValue, 1, buffer.data(), returnLength, &returnLength);
	if (!NT_SUCCESS(status)) {
		return L"";
	}

	// Parse UNICODE_STRING structure
	UNICODE_STRING* us = reinterpret_cast<UNICODE_STRING*>(buffer.data());
	if (us && us->Buffer && us->Length > 0) {
		return std::wstring(us->Buffer, us->Length / sizeof(WCHAR));
	}

	return L"";
}

bool HandleManager::QuerySystemHandles(std::vector<HandleInfo>& handles) const {
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll) {
		return false;
	}

	typedef NTSTATUS (WINAPI* pNtQuerySystemInformation)(
		ULONG SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	);

	pNtQuerySystemInformation NtQuerySystemInformation = reinterpret_cast<pNtQuerySystemInformation>(
		GetProcAddress(hNtdll, "NtQuerySystemInformation"));
	if (!NtQuerySystemInformation) {
		return false;
	}

	// Query required buffer size
	ULONG bufferSize = 0;
	NTSTATUS status = NtQuerySystemInformation(
		SystemHandleInformation,
		nullptr,
		0,
		&bufferSize
	);

	if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL) {
		return false;
	}

	// Allocate buffer
	bufferSize += 1024 * 1024; // Add extra space
	std::vector<BYTE> buffer(bufferSize);

	status = NtQuerySystemInformation(
		SystemHandleInformation,
		buffer.data(),
		bufferSize,
		&bufferSize
	);

	if (!NT_SUCCESS(status)) {
		return false;
	}

	PSYSTEM_HANDLE_INFORMATION_EX handleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer.data());
	if (!handleInfo) {
		return false;
	}

	ULONG_PTR handleCount = handleInfo->NumberOfHandles;
	if (handleCount == 0) {
		return true;
	}

	// Parse handles
	for (ULONG_PTR i = 0; i < handleCount; ++i) {
		SYSTEM_HANDLE_INFORMATION& sysHandle = handleInfo->Information[i];

		HandleInfo info;
		info.ProcessId = sysHandle.ProcessId;
		info.ObjectTypeIndex = sysHandle.ObjectTypeNumber;
		info.AccessMask = sysHandle.GrantedAccess;
		info.ObjectAddress = reinterpret_cast<ULONG_PTR>(sysHandle.Object);

		// Convert handle value (it's actually an index in the process handle table)
		info.HandleValue = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(sysHandle.Handle));

		// Get object type name
		info.ObjectTypeName = GetObjectTypeName(sysHandle.ObjectTypeNumber);

		// Try to get object name (requires opening the process and duplicating the handle)
		HandleWrapper hProcess(::OpenProcess(PROCESS_DUP_HANDLE, FALSE, sysHandle.ProcessId));
		if (hProcess.IsValid()) {
			HANDLE hDup = nullptr;
			if (DuplicateHandle(hProcess.Get(), info.HandleValue, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
				info.ObjectName = GetObjectName(GetCurrentProcess(), hDup);
				CloseHandle(hDup);
			}
		}

		handles.push_back(info);
	}

	return true;
}

} // namespace Core
} // namespace WinProcessInspector
