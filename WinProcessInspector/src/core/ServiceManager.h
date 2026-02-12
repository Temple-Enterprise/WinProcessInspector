#pragma once

#include <Windows.h>
#include <vector>
#include <string>

namespace WinProcessInspector {
namespace Core {

	enum class ServiceState {
		Stopped = 1,
		StartPending = 2,
		StopPending = 3,
		Running = 4,
		ContinuePending = 5,
		PausePending = 6,
		Paused = 7
	};

	enum class ServiceType {
		KernelDriver = 1,
		FileSystemDriver = 2,
		Adapter = 4,
		RecognizerDriver = 8,
		Win32OwnProcess = 16,
		Win32ShareProcess = 32,
		InteractiveProcess = 256
	};

	struct ServiceInfo {
		std::wstring Name;
		std::wstring DisplayName;
		std::wstring Description;
		DWORD ProcessId = 0;
		ServiceState State = ServiceState::Stopped;
		ServiceType Type = ServiceType::Win32OwnProcess;
		DWORD StartType = 0;
		bool CanStop = false;
		bool CanPauseContinue = false;
		std::wstring BinaryPathName;
		std::wstring ServiceAccount;
		std::wstring LoadOrderGroup;
		std::vector<std::wstring> Dependencies;
	};

	class ServiceManager {
	public:
		ServiceManager() = default;
		~ServiceManager() = default;

		ServiceManager(const ServiceManager&) = delete;
		ServiceManager& operator=(const ServiceManager&) = delete;
		ServiceManager(ServiceManager&&) = default;
		ServiceManager& operator=(ServiceManager&&) = default;

		std::vector<ServiceInfo> EnumerateServices() const;
		std::vector<ServiceInfo> GetServicesForProcess(DWORD processId) const;
		bool StartService(const std::wstring& serviceName) const;
		bool StopService(const std::wstring& serviceName) const;
		bool PauseService(const std::wstring& serviceName) const;
		bool ContinueService(const std::wstring& serviceName) const;
		
		static std::wstring GetStateString(ServiceState state);
		static std::wstring GetTypeString(ServiceType type);

	private:
		void PopulateServiceInfo(SC_HANDLE hService, ServiceInfo& info) const;
		std::vector<std::wstring> GetServiceDependencies(SC_HANDLE hService) const;
	};

} // namespace Core
} // namespace WinProcessInspector
