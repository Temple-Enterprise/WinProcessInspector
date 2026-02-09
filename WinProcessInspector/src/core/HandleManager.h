#pragma once

#include <Windows.h>
#include <vector>
#include <string>

namespace WinProcessInspector {
namespace Core {

	/**
	 * Handle information structure
	 */
	struct HandleInfo {
		HANDLE HandleValue = nullptr;    // Handle value
		DWORD ProcessId = 0;            // Process ID that owns the handle
		WORD ObjectTypeIndex = 0;        // Object type index
		DWORD AccessMask = 0;            // Access mask
		std::wstring ObjectTypeName;     // Object type name (File, Mutex, Event, etc.)
		std::wstring ObjectName;         // Object name (if available)
		ULONG_PTR ObjectAddress = 0;     // Object address (kernel address)
	};

	/**
	 * Handle manager for enumerating handles
	 * Uses NtQuerySystemInformation for handle enumeration
	 */
	class HandleManager {
	public:
		HandleManager() = default;
		~HandleManager() = default;

		// Non-copyable, movable
		HandleManager(const HandleManager&) = delete;
		HandleManager& operator=(const HandleManager&) = delete;
		HandleManager(HandleManager&&) = default;
		HandleManager& operator=(HandleManager&&) = default;

		/**
		 * Enumerate all handles for a specific process
		 * @param processId Process ID
		 * @return Vector of handle information
		 */
		std::vector<HandleInfo> EnumerateHandles(DWORD processId) const;

		/**
		 * Enumerate all handles in the system (requires admin privileges)
		 * @return Vector of handle information
		 */
		std::vector<HandleInfo> EnumerateAllHandles() const;

	private:
		/**
		 * Get object type name from type index
		 */
		std::wstring GetObjectTypeName(WORD typeIndex) const;

		/**
		 * Get object name from handle (if accessible)
		 */
		std::wstring GetObjectName(HANDLE hProcess, HANDLE handleValue) const;

		/**
		 * Query system information for handles
		 */
		bool QuerySystemHandles(std::vector<HandleInfo>& handles) const;
	};

} // namespace Core
} // namespace WinProcessInspector
