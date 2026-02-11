#pragma once

#include <Windows.h>
#include <vector>
#include <string>

namespace WinProcessInspector {
namespace Core {

	struct ModuleInfo {
		std::wstring Name;           
		std::wstring FullPath;       
		ULONG_PTR BaseAddress = 0;   
		DWORD Size = 0;              
		bool IsMissing = false;      
		bool IsSigned = false;       
		std::wstring SignatureInfo;  
	};

	class ModuleManager {
	public:
		ModuleManager() = default;
		~ModuleManager() = default;

		ModuleManager(const ModuleManager&) = delete;
		ModuleManager& operator=(const ModuleManager&) = delete;
		ModuleManager(ModuleManager&&) = default;
		ModuleManager& operator=(ModuleManager&&) = default;

		std::vector<ModuleInfo> EnumerateModules(DWORD processId) const;
		bool IsFileMissing(const std::wstring& filePath) const;
		bool IsModuleSigned(const std::wstring& filePath, std::wstring& signatureInfo) const;

	private:
		std::wstring ExtractFileName(const std::wstring& fullPath) const;
	};

}
} 
