#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include "ServiceManager.h"
#include <winsvc.h>
#include <sstream>

#pragma comment(lib, "advapi32.lib")

namespace WinProcessInspector {
namespace Core {

std::vector<ServiceInfo> ServiceManager::EnumerateServices() const {
	std::vector<ServiceInfo> services;

	SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
	if (!hSCManager) {
		return services;
	}

	DWORD bytesNeeded = 0;
	DWORD servicesReturned = 0;
	DWORD resumeHandle = 0;

	EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL,
		nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);

	if (GetLastError() != ERROR_MORE_DATA) {
		CloseServiceHandle(hSCManager);
		return services;
	}

	std::vector<BYTE> buffer(bytesNeeded);
	ENUM_SERVICE_STATUS_PROCESSW* pServices = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

	if (EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL,
		reinterpret_cast<LPBYTE>(pServices), bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr)) {
		
		for (DWORD i = 0; i < servicesReturned; ++i) {
			ServiceInfo info;
			info.Name = pServices[i].lpServiceName;
			info.DisplayName = pServices[i].lpDisplayName;
			info.State = static_cast<ServiceState>(pServices[i].ServiceStatusProcess.dwCurrentState);
			info.Type = static_cast<ServiceType>(pServices[i].ServiceStatusProcess.dwServiceType);
			info.ProcessId = pServices[i].ServiceStatusProcess.dwProcessId;

			SC_HANDLE hService = OpenServiceW(hSCManager, pServices[i].lpServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
			if (hService) {
				PopulateServiceInfo(hService, info);
				CloseServiceHandle(hService);
			}

			services.push_back(info);
		}
	}

	CloseServiceHandle(hSCManager);
	return services;
}

std::vector<ServiceInfo> ServiceManager::GetServicesForProcess(DWORD processId) const {
	std::vector<ServiceInfo> allServices = EnumerateServices();
	std::vector<ServiceInfo> result;

	for (const auto& service : allServices) {
		if (service.ProcessId == processId) {
			result.push_back(service);
		}
	}

	return result;
}

bool ServiceManager::StartService(const std::wstring& serviceName) const {
	SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager) {
		return false;
	}

	SC_HANDLE hService = OpenServiceW(hSCManager, serviceName.c_str(), SERVICE_START);
	bool result = false;
	if (hService) {
		result = ::StartServiceW(hService, 0, nullptr) != FALSE;
		CloseServiceHandle(hService);
	}

	CloseServiceHandle(hSCManager);
	return result;
}

bool ServiceManager::StopService(const std::wstring& serviceName) const {
	SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager) {
		return false;
	}

	SC_HANDLE hService = OpenServiceW(hSCManager, serviceName.c_str(), SERVICE_STOP);
	bool result = false;
	if (hService) {
		SERVICE_STATUS status;
		result = ControlService(hService, SERVICE_CONTROL_STOP, &status) != FALSE;
		CloseServiceHandle(hService);
	}

	CloseServiceHandle(hSCManager);
	return result;
}

bool ServiceManager::PauseService(const std::wstring& serviceName) const {
	SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager) {
		return false;
	}

	SC_HANDLE hService = OpenServiceW(hSCManager, serviceName.c_str(), SERVICE_PAUSE_CONTINUE);
	bool result = false;
	if (hService) {
		SERVICE_STATUS status;
		result = ControlService(hService, SERVICE_CONTROL_PAUSE, &status) != FALSE;
		CloseServiceHandle(hService);
	}

	CloseServiceHandle(hSCManager);
	return result;
}

bool ServiceManager::ContinueService(const std::wstring& serviceName) const {
	SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager) {
		return false;
	}

	SC_HANDLE hService = OpenServiceW(hSCManager, serviceName.c_str(), SERVICE_PAUSE_CONTINUE);
	bool result = false;
	if (hService) {
		SERVICE_STATUS status;
		result = ControlService(hService, SERVICE_CONTROL_CONTINUE, &status) != FALSE;
		CloseServiceHandle(hService);
	}

	CloseServiceHandle(hSCManager);
	return result;
}

std::wstring ServiceManager::GetStateString(ServiceState state) {
	switch (state) {
		case ServiceState::Stopped:
			return L"Stopped";
		case ServiceState::StartPending:
			return L"Start Pending";
		case ServiceState::StopPending:
			return L"Stop Pending";
		case ServiceState::Running:
			return L"Running";
		case ServiceState::ContinuePending:
			return L"Continue Pending";
		case ServiceState::PausePending:
			return L"Pause Pending";
		case ServiceState::Paused:
			return L"Paused";
		default:
			return L"Unknown";
	}
}

std::wstring ServiceManager::GetTypeString(ServiceType type) {
	std::wstring result;
	if (type == ServiceType::KernelDriver) {
		return L"Kernel Driver";
	} else if (type == ServiceType::FileSystemDriver) {
		return L"File System Driver";
	} else if (type == ServiceType::Win32OwnProcess) {
		return L"Win32 Own Process";
	} else if (type == ServiceType::Win32ShareProcess) {
		return L"Win32 Share Process";
	} else {
		return L"Unknown";
	}
}

void ServiceManager::PopulateServiceInfo(SC_HANDLE hService, ServiceInfo& info) const {
	DWORD bytesNeeded = 0;
	QueryServiceConfigW(hService, nullptr, 0, &bytesNeeded);

	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		return;
	}

	std::vector<BYTE> buffer(bytesNeeded);
	QUERY_SERVICE_CONFIGW* pConfig = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());

	if (QueryServiceConfigW(hService, pConfig, bytesNeeded, &bytesNeeded)) {
		info.StartType = pConfig->dwStartType;
		info.BinaryPathName = pConfig->lpBinaryPathName ? pConfig->lpBinaryPathName : L"";
		info.ServiceAccount = pConfig->lpServiceStartName ? pConfig->lpServiceStartName : L"";
		info.LoadOrderGroup = pConfig->lpLoadOrderGroup ? pConfig->lpLoadOrderGroup : L"";
		info.Dependencies = GetServiceDependencies(hService);
	}

	SERVICE_STATUS_PROCESS statusProcess = {};
	DWORD bytesNeededStatus = 0;
	if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&statusProcess),
		sizeof(statusProcess), &bytesNeededStatus)) {
		info.CanStop = (statusProcess.dwControlsAccepted & SERVICE_ACCEPT_STOP) != 0;
		info.CanPauseContinue = (statusProcess.dwControlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE) != 0;
	}

	bytesNeeded = 0;
	QueryServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, nullptr, 0, &bytesNeeded);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		std::vector<BYTE> descBuffer(bytesNeeded);
		SERVICE_DESCRIPTIONW* pDesc = reinterpret_cast<SERVICE_DESCRIPTIONW*>(descBuffer.data());
		if (QueryServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, reinterpret_cast<LPBYTE>(pDesc),
			bytesNeeded, &bytesNeeded)) {
			if (pDesc->lpDescription) {
				info.Description = pDesc->lpDescription;
			}
		}
	}
}

std::vector<std::wstring> ServiceManager::GetServiceDependencies(SC_HANDLE hService) const {
	std::vector<std::wstring> dependencies;

	DWORD bytesNeeded = 0;
	QueryServiceConfigW(hService, nullptr, 0, &bytesNeeded);

	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		return dependencies;
	}

	std::vector<BYTE> buffer(bytesNeeded);
	QUERY_SERVICE_CONFIGW* pConfig = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());

	if (QueryServiceConfigW(hService, pConfig, bytesNeeded, &bytesNeeded) && pConfig->lpDependencies) {
		LPWSTR pDep = pConfig->lpDependencies;
		while (*pDep) {
			dependencies.push_back(pDep);
			pDep += wcslen(pDep) + 1;
		}
	}

	return dependencies;
}

} // namespace Core
} // namespace WinProcessInspector
