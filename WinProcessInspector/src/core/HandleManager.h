#pragma once

#include <Windows.h>
#include <vector>
#include <string>

namespace WinProcessInspector {
namespace Core {

	struct HandleInfo {
		HANDLE HandleValue = nullptr;
		DWORD ProcessId = 0;
		WORD ObjectTypeIndex = 0;
		DWORD AccessMask = 0;
		std::wstring ObjectTypeName;
		std::wstring ObjectName;         
		ULONG_PTR ObjectAddress = 0;     
	};

	class HandleManager {
	public:
		HandleManager() = default;
		~HandleManager() = default;

		
		HandleManager(const HandleManager&) = delete;
		HandleManager& operator=(const HandleManager&) = delete;
		HandleManager(HandleManager&&) = default;
		HandleManager& operator=(HandleManager&&) = default;
		std::vector<HandleInfo> EnumerateHandles(DWORD processId) const;
		std::vector<HandleInfo> EnumerateAllHandles() const;

	private:
		std::wstring GetObjectTypeName(WORD typeIndex) const;
		std::wstring GetObjectName(HANDLE hProcess, HANDLE handleValue) const;
		bool QuerySystemHandles(std::vector<HandleInfo>& handles) const;
	};

}
} 
