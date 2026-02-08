#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <psapi.h>
#include <tlHelp32.h>
#include "../core/ProcessManager.h"
#include "../core/SystemInfo.h"
#include "../core/Config.h"
#include "../core/Logger.h"
#include "../core/HandleWrapper.h"
#include "../injection/InjectionEngine.h"
#include "DirectXRenderer.h"

struct ImGuiContext;

namespace RuntimeInspector {
namespace GUI {

	struct ProcessInfo {
		DWORD ProcessId = 0;
		DWORD ParentProcessId = 0;
		std::string ProcessName;
		std::string Architecture;
	};

	struct ThreadInfo {
		DWORD ThreadId;
		DWORD ProcessId;
		HANDLE Handle;
		std::string State;
	};

	struct ModuleInfo {
		std::string Name;
		std::string Path;
		ULONG_PTR BaseAddress;
		DWORD Size;
	};

	struct ProcessDetails {
		DWORD ProcessId;
		std::string ProcessName;
		std::string ExePath;
		std::string CommandLine;
		DWORD ParentProcessId;
		std::string Architecture;
		SIZE_T WorkingSetSize;
		SIZE_T PageFileUsage;
		SIZE_T PeakWorkingSetSize;
		DWORD ThreadCount;
		DWORD HandleCount;
		FILETIME CreationTime;
		FILETIME ExitTime;
		FILETIME KernelTime;
		FILETIME UserTime;
		std::vector<ThreadInfo> Threads;
		std::vector<ModuleInfo> Modules;
	};

	class MainWindow {
	public:
		MainWindow(HINSTANCE hInstance);
		~MainWindow();

		bool Initialize();
		int Run();

	private:
		void RenderUI();
		void RenderProcessList();
		void RenderDllSelection();
		void RenderInjectionMethod();
		void RenderStatusBar();
		void RenderProcessDetails();
		void RenderProcessPropertiesWindow();
		void RenderThreadManager();
		void RenderModuleInspector();
		void RenderMemoryAnalyzer();
		void RefreshProcessList();
		bool BrowseForDll();
		void PerformInjection();
		RuntimeInspector::Core::IconWrapper GetProcessIcon(DWORD processId);
		void* GetProcessIconTexture(DWORD processId);
		void OpenProcessFileLocation(DWORD processId);
		void CopyProcessId(DWORD processId);
		void TerminateProcess(DWORD processId);
		void CopyProcessName(const std::string& processName);
		void SearchProcessOnline(const std::string& processName);
		void ShowProcessProperties(DWORD processId);
		void ExportProcessList();
		void RefreshProcessDetails();
		void RefreshThreads(DWORD processId);
		void RefreshModules(DWORD processId);
		void SuspendThread(DWORD threadId);
		void ResumeThread(DWORD threadId);
		void ReadProcessMemory(DWORD processId, LPCVOID address, SIZE_T size);
		void SearchMemoryStrings(DWORD processId);
		void EnumerateHandles(DWORD processId);

		static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
		LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam);
		bool CreateMainWindow();
		void Cleanup();

		bool InitializeImGui();
		void ShutdownImGui();
		void NewFrame();
		void Render();

		HWND m_hWnd;
		HINSTANCE m_hInstance;
		bool m_bRunning;

		ImGuiContext* m_pImGuiContext;
		std::unique_ptr<DirectXRenderer> m_Renderer;

		std::vector<ProcessInfo> m_Processes;
		std::string m_DllPath;
		int m_SelectedProcessIndex;
		int m_SelectedInjectionMethod;
		std::string m_StatusMessage;
		
		std::unordered_map<DWORD, void*> m_IconCache;

		char m_DllPathBuffer[RuntimeInspector::Core::Config::MAX_DLL_PATH_LENGTH];
		char m_ProcessFilter[RuntimeInspector::Core::Config::MAX_PROCESS_FILTER_LENGTH];
		bool m_AutoRefresh;
		
		bool m_ShowProcessDetails;
		bool m_ShowThreadManager;
		bool m_ShowModuleInspector;
		bool m_ShowMemoryAnalyzer;
		bool m_ShowProcessProperties;
		ProcessDetails m_CurrentProcessDetails;
		std::vector<ThreadInfo> m_CurrentThreads;
		std::vector<ModuleInfo> m_CurrentModules;
		char m_MemoryAddressBuffer[RuntimeInspector::Core::Config::MAX_MEMORY_ADDRESS_LENGTH];
		char m_MemorySizeBuffer[RuntimeInspector::Core::Config::MAX_MEMORY_SIZE_LENGTH];
		char m_SearchStringBuffer[RuntimeInspector::Core::Config::MAX_SEARCH_STRING_LENGTH];
		std::vector<std::string> m_MemorySearchResults;
		std::vector<std::string> m_HandleList;
	};

}
}
