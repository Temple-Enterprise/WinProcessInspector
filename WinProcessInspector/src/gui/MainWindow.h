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

	class ProcessPropertiesDialog;

	class MainWindow {
	public:
		MainWindow(HINSTANCE hInstance);
		~MainWindow();

		bool Initialize();
		int Run();
		
		std::vector<bool>& GetColumnVisible() { return m_ColumnVisible; }
		void UpdateColumnVisibility();

	private:
		LRESULT OnCustomDraw(LPNMLVCUSTOMDRAW lplvcd);
		COLORREF GetProcessColor(DWORD processId, const WinProcessInspector::Core::ProcessInfo& info);
		void DrawCpuBar(HDC hdc, RECT rect, double cpuPercent);
		void DrawMemoryBar(HDC hdc, RECT rect, SIZE_T memory, SIZE_T totalMemory);
		bool IsSystemProcess(DWORD processId);
		bool IsVerifiedProcess(const std::wstring& imagePath);
		std::wstring GetFileDescription(const std::wstring& filePath);
		std::wstring GetFileCompany(const std::wstring& filePath);
		bool CreateMainWindow();
		bool CreateMenuBar();
		bool CreateToolbar();
		bool CreateSearchFilter();
		bool CreateProcessListView();
		bool CreateStatusBar();
		void Cleanup();

		static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
		LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam);
		LRESULT OnCreate();
		LRESULT OnDestroy();
		LRESULT OnSize();
		LRESULT OnCommand(WPARAM wParam, LPARAM lParam);
		LRESULT OnNotify(WPARAM wParam, LPARAM lParam);
		LRESULT OnContextMenu(WPARAM wParam, LPARAM lParam);
		LRESULT OnTimer(WPARAM wParam);

		void RefreshProcessList();
		void UpdateProcessList();
		void SortProcessList(int column, bool ascending);
		void BuildProcessHierarchy();
		void OnProcessListDoubleClick();
		void OnProcessListSelectionChanged();
		void ShowProcessContextMenu(int x, int y);

		void OnFileRefresh();
		void OnFileExport();
		void OnFileExit();
		
		bool ExportToCSV(const std::wstring& filePath, const std::vector<WinProcessInspector::Core::ProcessInfo>& processes);
		bool ExportToJSON(const std::wstring& filePath, const std::vector<WinProcessInspector::Core::ProcessInfo>& processes);
		bool ExportToText(const std::wstring& filePath, const std::vector<WinProcessInspector::Core::ProcessInfo>& processes);
		
		void OnViewTreeView();
		void OnViewToolbar();
		void OnViewSearchBar();
		void OnViewAutoRefresh();
		void OnViewColumns();
		void ShowNetworkConnectionsWindow();
		void ShowSystemInformationWindow();
		void ShowColumnChooserDialog();
		void OnHelpAbout();
		void OnHelpGitHub();
		void UpdateProcessMenuState();

		void ShowProcessProperties(DWORD processId);
		void TerminateProcess(DWORD processId);
		void SuspendProcess(DWORD processId);
		void ResumeProcess(DWORD processId);
		void InjectDll(DWORD processId);
		void SetProcessPriority(DWORD processId);
		void SetProcessAffinity(DWORD processId);
		void CreateProcessDump(DWORD processId);
		int SelectInjectionMethod(DWORD processId);
		void OpenProcessFileLocation(DWORD processId);
		void CopyProcessId(DWORD processId);
		void CopyProcessName(DWORD processId);
		void SearchProcessOnline(DWORD processId);
		void ShowCommandLineDialog(DWORD processId);

		bool ValidateProcess(DWORD processId, std::wstring& errorMsg);
		bool ValidateProcessAccess(DWORD processId, DWORD desiredAccess, std::wstring& errorMsg);
		bool ValidateArchitectureCompatibility(DWORD processId, std::wstring& errorMsg);
		bool ValidateIntegrityLevel(DWORD processId, std::wstring& errorMsg);

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
		std::unordered_map<DWORD, bool> m_ExpandedProcesses;
		std::unordered_map<DWORD, std::vector<DWORD>> m_ProcessChildren;
		std::unordered_map<DWORD, ULONGLONG> m_ProcessCpuTime;
		std::unordered_map<DWORD, ULONGLONG> m_ProcessCpuTimePrev;
		std::unordered_map<DWORD, double> m_ProcessCpuPercent;
		std::unordered_map<DWORD, SIZE_T> m_ProcessMemory;
		ULONGLONG m_LastCpuUpdateTime;
		std::unordered_map<DWORD, int> m_ProcessDepth;
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
		
		std::vector<bool> m_ColumnVisible;
		
		HIMAGELIST m_hProcessIconList;
		std::unordered_map<std::wstring, int> m_IconCache;
		int m_DefaultIconIndex;
		
		std::unordered_map<DWORD, bool> m_SystemProcessCache;
		std::unordered_map<std::wstring, bool> m_VerifiedCache;
		std::unordered_map<std::wstring, std::wstring> m_DescriptionCache;
		std::unordered_map<std::wstring, std::wstring> m_CompanyCache;
		SIZE_T m_TotalSystemMemory;
		DWORD m_CurrentProcessId;

		std::unique_ptr<ProcessPropertiesDialog> m_PropertiesDialog;
	};

} // namespace GUI
} // namespace WinProcessInspector
