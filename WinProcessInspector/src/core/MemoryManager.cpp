#include "MemoryManager.h"
#include "HandleWrapper.h"
#include <sstream>
#include <iomanip>

namespace WinProcessInspector {
namespace Core {

std::vector<MemoryRegionInfo> MemoryManager::EnumerateMemoryRegions(DWORD processId) const {
	std::vector<MemoryRegionInfo> regions;

	HandleWrapper hProcess(::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId));
	if (!hProcess.IsValid()) {
		return regions; // Access denied or process not found
	}

	MEMORY_BASIC_INFORMATION mbi = {};
	ULONG_PTR address = 0;

	// Enumerate memory regions
	while (VirtualQueryEx(hProcess.Get(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi)) {
		MemoryRegionInfo info;
		info.BaseAddress = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress);
		info.RegionSize = mbi.RegionSize;
		info.State = mbi.State;
		info.Protect = mbi.Protect;
		info.Type = mbi.Type;

		// Convert to human-readable strings
		info.ProtectionString = ProtectionToString(mbi.Protect);
		info.StateString = StateToString(mbi.State);
		info.TypeString = TypeToString(mbi.Type);

		regions.push_back(info);

		// Move to next region
		address = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + mbi.RegionSize;

		// Safety check to prevent infinite loop
		if (address == 0 || address < reinterpret_cast<ULONG_PTR>(mbi.BaseAddress)) {
			break;
		}
	}

	return regions;
}

std::wstring MemoryManager::ProtectionToString(DWORD protect) {
	if (protect == 0) {
		return L"";
	}

	std::wstring result;

	// Base protection types
	switch (protect & 0xFF) {
		case PAGE_NOACCESS:
			result = L"No Access";
			break;
		case PAGE_READONLY:
			result = L"Read-Only";
			break;
		case PAGE_READWRITE:
			result = L"Read/Write";
			break;
		case PAGE_WRITECOPY:
			result = L"Write Copy";
			break;
		case PAGE_EXECUTE:
			result = L"Execute";
			break;
		case PAGE_EXECUTE_READ:
			result = L"Execute/Read";
			break;
		case PAGE_EXECUTE_READWRITE:
			result = L"Execute/Read/Write";
			break;
		case PAGE_EXECUTE_WRITECOPY:
			result = L"Execute/Write Copy";
			break;
		case PAGE_GUARD:
			result = L"Guard";
			break;
		case PAGE_NOCACHE:
			result = L"No Cache";
			break;
		case PAGE_WRITECOMBINE:
			result = L"Write Combine";
			break;
		default:
			result = L"Unknown";
			break;
	}

	// Add modifiers
	if (protect & PAGE_GUARD) {
		result += L" | Guard";
	}
	if (protect & PAGE_NOCACHE) {
		result += L" | No Cache";
	}
	if (protect & PAGE_WRITECOMBINE) {
		result += L" | Write Combine";
	}

	return result;
}

std::wstring MemoryManager::StateToString(DWORD state) {
	switch (state) {
		case MEM_COMMIT:
			return L"Committed";
		case MEM_RESERVE:
			return L"Reserved";
		case MEM_FREE:
			return L"Free";
		case MEM_DECOMMIT:
			return L"Decommitted";
		case MEM_RELEASE:
			return L"Released";
		default:
			return L"Unknown";
	}
}

std::wstring MemoryManager::TypeToString(DWORD type) {
	switch (type) {
		case MEM_IMAGE:
			return L"Image";
		case MEM_MAPPED:
			return L"Mapped";
		case MEM_PRIVATE:
			return L"Private";
		default:
			return L"Unknown";
	}
}

void MemoryManager::FormatProtection(DWORD protect, std::wstring& result) {
	result = ProtectionToString(protect);
}

} // namespace Core
} // namespace WinProcessInspector
