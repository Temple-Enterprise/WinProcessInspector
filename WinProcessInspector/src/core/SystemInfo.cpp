#include "SystemInfo.h"
#include <string>
#include <sstream>

namespace WinProcessInspector {
namespace Core {

std::string SystemInfo::GetWindowsVersion() const {
	OSVERSIONINFOEXW osvi = {};
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

	typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (hNtdll) {
		RtlGetVersionPtr RtlGetVersion = reinterpret_cast<RtlGetVersionPtr>(
			GetProcAddress(hNtdll, "RtlGetVersion"));
		if (RtlGetVersion) {
			RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&osvi));
		}
	}

	if (osvi.dwMajorVersion == 0) {
		#pragma warning(push)
		#pragma warning(disable: 4996)
		GetVersionExW(reinterpret_cast<OSVERSIONINFOW*>(&osvi));
		#pragma warning(pop)
	}

	std::ostringstream oss;
	if (osvi.dwPlatformId == VER_PLATFORM_WIN32_NT) {
		oss << "Windows NT " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion;
		if (osvi.dwBuildNumber > 0) {
			oss << " (Build " << osvi.dwBuildNumber << ")";
		}
		return oss.str();
	}

	return "";
}

std::string SystemInfo::GetSystemArchitecture() const {
	SYSTEM_INFO si;
	GetNativeSystemInfo(&si);
	
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
		return "x64";
	} else {
		return "x86";
	}
}

bool SystemInfo::Is64BitSystem() const {
	SYSTEM_INFO si;
	GetNativeSystemInfo(&si);
	return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
			si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
}

}
}
