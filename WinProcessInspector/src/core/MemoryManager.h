#pragma once

#include <Windows.h>
#include <vector>
#include <string>

namespace WinProcessInspector {
namespace Core {

	/**
	 * Memory region information structure
	 */
	struct MemoryRegionInfo {
		ULONG_PTR BaseAddress = 0;      // Base address of region
		SIZE_T RegionSize = 0;          // Size of region
		DWORD State = 0;                // MEM_COMMIT, MEM_RESERVE, MEM_FREE
		DWORD Protect = 0;              // Protection flags (PAGE_READONLY, etc.)
		DWORD Type = 0;                 // MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
		std::wstring ProtectionString;  // Human-readable protection string
		std::wstring StateString;       // Human-readable state string
		std::wstring TypeString;        // Human-readable type string
	};

	/**
	 * Memory manager for enumerating virtual memory regions
	 * Read-only inspection - no memory modification
	 */
	class MemoryManager {
	public:
		MemoryManager() = default;
		~MemoryManager() = default;

		// Non-copyable, movable
		MemoryManager(const MemoryManager&) = delete;
		MemoryManager& operator=(const MemoryManager&) = delete;
		MemoryManager(MemoryManager&&) = default;
		MemoryManager& operator=(MemoryManager&&) = default;

		/**
		 * Enumerate all memory regions in a process
		 * @param processId Process ID
		 * @return Vector of memory region information
		 */
		std::vector<MemoryRegionInfo> EnumerateMemoryRegions(DWORD processId) const;

		/**
		 * Convert protection flags to human-readable string
		 * @param protect Protection flags
		 * @return Human-readable protection string
		 */
		static std::wstring ProtectionToString(DWORD protect);

		/**
		 * Convert state flags to human-readable string
		 * @param state State flags
		 * @return Human-readable state string
		 */
		static std::wstring StateToString(DWORD state);

		/**
		 * Convert type flags to human-readable string
		 * @param type Type flags
		 * @return Human-readable type string
		 */
		static std::wstring TypeToString(DWORD type);

	private:
		/**
		 * Helper to format protection flags
		 */
		static void FormatProtection(DWORD protect, std::wstring& result);
	};

} // namespace Core
} // namespace WinProcessInspector
