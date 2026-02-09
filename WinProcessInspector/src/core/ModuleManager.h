#pragma once

#include <Windows.h>
#include <vector>
#include <string>

namespace WinProcessInspector {
namespace Core {

	/**
	 * Module information structure
	 */
	struct ModuleInfo {
		std::wstring Name;           // Module file name
		std::wstring FullPath;       // Full file path
		ULONG_PTR BaseAddress = 0;   // Base address in process memory
		DWORD Size = 0;              // Image size
		bool IsMissing = false;      // File no longer exists on disk
		bool IsSigned = false;       // Module is code-signed
		std::wstring SignatureInfo;  // Signature information if available
	};

	/**
	 * Module manager for enumerating and inspecting loaded modules
	 */
	class ModuleManager {
	public:
		ModuleManager() = default;
		~ModuleManager() = default;

		// Non-copyable, movable
		ModuleManager(const ModuleManager&) = delete;
		ModuleManager& operator=(const ModuleManager&) = delete;
		ModuleManager(ModuleManager&&) = default;
		ModuleManager& operator=(ModuleManager&&) = default;

		/**
		 * Enumerate all modules loaded in a process
		 * @param processId Process ID
		 * @return Vector of module information
		 */
		std::vector<ModuleInfo> EnumerateModules(DWORD processId) const;

		/**
		 * Check if a module file exists on disk
		 * @param filePath Full path to module file
		 * @return true if file exists, false otherwise
		 */
		bool IsFileMissing(const std::wstring& filePath) const;

		/**
		 * Check if a module is code-signed
		 * @param filePath Full path to module file
		 * @param signatureInfo Output: Signature information if signed
		 * @return true if module is signed, false otherwise
		 */
		bool IsModuleSigned(const std::wstring& filePath, std::wstring& signatureInfo) const;

	private:
		/**
		 * Extract file name from full path
		 */
		std::wstring ExtractFileName(const std::wstring& fullPath) const;
	};

} // namespace Core
} // namespace WinProcessInspector
