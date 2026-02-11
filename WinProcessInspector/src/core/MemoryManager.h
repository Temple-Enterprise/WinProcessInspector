#pragma once

#include <Windows.h>
#include <vector>
#include <string>

namespace WinProcessInspector {
namespace Core {

	struct MemoryRegionInfo {
		ULONG_PTR BaseAddress = 0;
		SIZE_T RegionSize = 0; 
		DWORD State = 0;               
		DWORD Protect = 0;              
		DWORD Type = 0;                 
		std::wstring ProtectionString;  
		std::wstring StateString;       
		std::wstring TypeString;        
	};

	class MemoryManager {
	public:
		MemoryManager() = default;
		~MemoryManager() = default;
		MemoryManager(const MemoryManager&) = delete;
		MemoryManager& operator=(const MemoryManager&) = delete;
		MemoryManager(MemoryManager&&) = default;
		MemoryManager& operator=(MemoryManager&&) = default;

		std::vector<MemoryRegionInfo> EnumerateMemoryRegions(DWORD processId) const;
		static std::wstring ProtectionToString(DWORD protect);
		static std::wstring StateToString(DWORD state);
		static std::wstring TypeToString(DWORD type);

	private:
		static void FormatProtection(DWORD protect, std::wstring& result);
	};

} 
}
