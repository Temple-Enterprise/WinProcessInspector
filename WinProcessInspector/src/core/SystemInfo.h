#pragma once

#include <Windows.h>
#include <string>

namespace WinProcessInspector {
namespace Core {

	class SystemInfo {
	public:
		SystemInfo() = default;
		~SystemInfo() = default;

		SystemInfo(const SystemInfo&) = delete;
		SystemInfo& operator=(const SystemInfo&) = delete;
		SystemInfo(SystemInfo&&) = default;
		SystemInfo& operator=(SystemInfo&&) = default;

		std::string GetWindowsVersion() const;

		std::string GetSystemArchitecture() const;

		bool Is64BitSystem() const;
	};

}
}
