#pragma once

#include <Windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include "../core/ProcessManager.h"
#include "../core/ModuleManager.h"
#include "../core/MemoryManager.h"
#include "../core/HandleManager.h"
#include "../core/SystemInfo.h"
#include "../utils/Logger.h"
#include "../core/HandleWrapper.h"

#pragma comment(lib, "comctl32.lib")

namespace WinProcessInspector {
namespace GUI {

	// Forward declarations
	class ProcessPropertiesDialog;

	/**
	 * Main application window - native Win32 implementation
	 */
	class MainWindow {
	public:
		MainWindow(HINSTANCE hInstance);
		~MainWindow();

		bool Initialize();
		int Run();

	private:
		// Window creation and message handling
		bool CreateMainWindow();
		bool CreateMenuBar();
		bool CreateToolbar();
		bool CreateSearchFilter();
		bool CreateProcessListView();
		bool CreateStatusBar();
		void Cleanup();

		// Message handling
		static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
		LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam);
		LRESULT OnCreate();
		LRESULT OnDestroy();
		LRESULT OnSize();
		LRESULT OnCommand(WPARAM wParam, LPARAM lParam);
		LRESULT OnNotify(WPARAM wParam, LPARAM lParam);
		LRESULT OnContextMenu(WPARAM wParam, LPARAM lParam);
		LRESULT OnTimer(WPARAM wParam);

		// Process list management
		void RefreshProcessList();
		void UpdateProcessList();
		void SortProcessList(int column, bool ascending);
		void BuildProcessHierarchy();
		void OnProcessListDoubleClick();
		void OnProcessListSelectionChanged();
		void ShowProcessContextMenu(int x, int y);

		// Menu handlers
		void OnFileRefresh();
		void OnFileExport();
		void OnFileExit();
		
		// Export functions
		bool ExportToCSV(const std::wstring& filePath);
		bool ExportToJSON(const std::wstring& filePath);
		bool ExportToText(const std::wstring& filePath);
		
		void OnViewTreeView();
		void OnViewToolbar();
		void OnViewSearchBar();
		void OnViewAutoRefresh();
		void OnViewColumns();
		void OnHelpAbout();
		void OnHelpGitHub();
		void UpdateProcessMenuState();

		// Process operations
		void ShowProcessProperties(DWORD processId);
		void TerminateProcess(DWORD processId);
		void SuspendProcess(DWORD processId);
		void ResumeProcess(DWORD processId);
		void InjectDll(DWORD processId);
		int SelectInjectionMethod(DWORD processId);
		void OpenProcessFileLocation(DWORD processId);
		void CopyProcessId(DWORD processId);
		void CopyProcessName(DWORD processId);
		void SearchProcessOnline(DWORD processId);

		// Validation layer
		bool ValidateProcess(DWORD processId, std::wstring& errorMsg);
		bool ValidateProcessAccess(DWORD processId, DWORD desiredAccess, std::wstring& errorMsg);
		bool ValidateArchitectureCompatibility(DWORD processId, std::wstring& errorMsg);
		bool ValidateIntegrityLevel(DWORD processId, std::wstring& errorMsg);

		// Utility
		std::wstring FormatIntegrityLevel(WinProcessInspector::Security::IntegrityLevel level);
		std::wstring FormatMemorySize(SIZE_T bytes);
		std::wstring FormatTime(const FILETIME& ft);
		int GetProcessIconIndex(const std::wstring& imagePath);
		std::wstring GetProcessImagePath(DWORD processId);
		void CalculateCpuUsage();
		void UpdateMemoryUsage();
		double GetCpuUsage(DWORD processId) const;
		void GroupSvchostServices(std::unordered_map<DWORD, std::vector<DWORD>>& processChildren);
		void GroupAppContainerProcesses(std::unordered_map<DWORD, std::vector<DWORD>>& processChildren);

		HWND m_hWnd;
		HINSTANCE m_hInstance;
		HWND m_hProcessListView;
		HWND m_hStatusBar;
		HWND m_hToolbar;
		HWND m_hSearchFilter;
		HWND m_hSearchIcon;
		HWND m_hSearchLabel;
		HMENU m_hMenu;
		HMENU m_hContextMenu;
		HACCEL m_hAccel;

		WinProcessInspector::Core::ProcessManager m_ProcessManager;
		WinProcessInspector::Core::ModuleManager m_ModuleManager;
		WinProcessInspector::Core::MemoryManager m_MemoryManager;
		WinProcessInspector::Core::HandleManager m_HandleManager;

		std::vector<WinProcessInspector::Core::ProcessInfo> m_Processes;
		std::vector<WinProcessInspector::Core::ProcessInfo> m_FilteredProcesses;
		std::unordered_map<DWORD, bool> m_ExpandedProcesses; // Track which processes are expanded
		std::unordered_map<DWORD, std::vector<DWORD>> m_ProcessChildren; // PID -> children PIDs
		std::unordered_map<DWORD, ULONGLONG> m_ProcessCpuTime; // PID -> last CPU time (for delta calculation)
		std::unordered_map<DWORD, DWORD> m_ProcessCpuTimePrev; // PID -> previous CPU time snapshot
		std::unordered_map<DWORD, double> m_ProcessCpuPercent; // PID -> CPU usage percentage
		std::unordered_map<DWORD, SIZE_T> m_ProcessMemory; // PID -> private memory bytes
		ULONGLONG m_LastCpuUpdateTime; // Last time CPU was calculated
		std::unordered_map<DWORD, int> m_ProcessDepth; // PID -> tree depth for display
		DWORD m_SelectedProcessId;
		int m_SortColumn;
		bool m_SortAscending;
		bool m_AutoRefresh;
		bool m_ToolbarVisible;
		bool m_SearchBarVisible;
		bool m_TreeViewEnabled;
		UINT_PTR m_RefreshTimerId;
		bool m_IsRefreshing;
		ULONGLONG m_LastRefreshTime;
		std::wstring m_FilterText;
		
		// Icon cache for process icons
		HIMAGELIST m_hProcessIconList;
		std::unordered_map<std::wstring, int> m_IconCache; // path -> image index
		int m_DefaultIconIndex;

		std::unique_ptr<ProcessPropertiesDialog> m_PropertiesDialog;
	};

} // namespace GUI
} // namespace WinProcessInspector
