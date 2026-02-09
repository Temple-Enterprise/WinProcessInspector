#pragma once

#include <Windows.h>
#include <string>

namespace WinProcessInspector {
namespace Core {

	/**
	 * System information query facade
	 * Thin wrapper for system queries only - no security or UI logic
	 */
	class SystemInfo {
	public:
		SystemInfo() = default;
		~SystemInfo() = default;

		// Non-copyable, movable
		SystemInfo(const SystemInfo&) = delete;
		SystemInfo& operator=(const SystemInfo&) = delete;
		SystemInfo(SystemInfo&&) = default;
		SystemInfo& operator=(SystemInfo&&) = default;

		/**
		 * Get Windows version information
		 * @return Windows version string (empty if detection failed)
		 */
		std::string GetWindowsVersion() const;

		/**
		 * Get system architecture (x86/x64)
		 * @return Architecture string
		 */
		std::string GetSystemArchitecture() const;

		/**
		 * Check if system is 64-bit
		 * @return true if 64-bit
		 */
		bool Is64BitSystem() const;
	};

} // namespace Core
} // namespace WinProcessInspector
