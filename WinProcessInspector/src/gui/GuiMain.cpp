#include "MainWindow.h"
#include "../core/SystemInfo.h"
#include "../security/SecurityManager.h"
#include <Windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	using namespace WinProcessInspector::GUI;
	using namespace WinProcessInspector::Core;
	using namespace WinProcessInspector::Security;

	// Check system info (non-critical, just for logging)
	SystemInfo sysInfo;
	std::string version = sysInfo.GetWindowsVersion();
	if (version.empty()) {
		// Non-fatal, continue anyway
	}

	// Elevate privileges using SecurityManager
	int epResult = SecurityManager::ElevatePrivileges();
	if (epResult != 0) {
		MessageBoxW(nullptr, L"Warning: Failed to elevate privileges. Some operations may fail.", L"Warning", MB_OK | MB_ICONWARNING);
	}

	MainWindow window(hInstance);
	if (!window.Initialize()) {
		MessageBoxW(nullptr, L"Failed to initialize GUI", L"Error", MB_OK | MB_ICONERROR);
		return 1;
	}

	return window.Run();
}
