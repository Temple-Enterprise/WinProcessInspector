#pragma once

#include <Windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <memory>
#include "../core/ProcessManager.h"
#include "../core/ModuleManager.h"
#include "../core/MemoryManager.h"
#include "../core/HandleManager.h"
#include "../core/ServiceManager.h"
#include "../security/SecurityManager.h"

namespace WinProcessInspector {
namespace GUI {

	class ProcessPropertiesDialog {
	public:
		ProcessPropertiesDialog(HINSTANCE hInstance, HWND hParent);
		~ProcessPropertiesDialog();

		bool Show(DWORD processId);
		void Close();

	private:
		bool CreateDialogWindow();
		bool CreateTabs();
		void CreateGeneralTab();
		void CreatePerformanceTab();
		void CreateThreadsTab();
		void CreateModulesTab();
		void CreateMemoryTab();
		void CreateHandlesTab();
		void CreateSecurityTab();
		void CreateEnvironmentTab();
		void CreateNetworkTab();
		void CreateServicesTab();
		
		void AddStaticText(HWND hParent, const wchar_t* text, int x, int y, int width, int height, bool bold = false);
		void AddEditBox(HWND hParent, const wchar_t* text, int x, int y, int width, int height, bool multiline = false, bool readonly = true);
		std::wstring FormatFileTime(const FILETIME& ft);
		std::wstring FormatBytes(ULONGLONG bytes);
		std::wstring FormatNumber(ULONGLONG number);

		static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
		LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam);
		LRESULT OnCreate();
		LRESULT OnCommand(WPARAM wParam);
		LRESULT OnNotify(WPARAM wParam);
		LRESULT OnClose();
		LRESULT OnSize();

		void OnTabChanged(int tabIndex);
		void RefreshCurrentTab();
		void RefreshGeneralTab();
		void RefreshPerformanceTab();
		void RefreshThreadsTab();
		void RefreshModulesTab();
		void RefreshMemoryTab();
		void RefreshHandlesTab();
		void RefreshSecurityTab();
		void RefreshEnvironmentTab();
		void RefreshNetworkTab();
		void RefreshServicesTab();
		void OnSearchOnline();

		HWND m_hDlg;
		HWND m_hParent;
		HINSTANCE m_hInstance;
		HWND m_hTabControl;
		HWND m_hGeneralTab;
		HWND m_hPerformanceTab;
		HWND m_hThreadsTab;
		HWND m_hModulesTab;
		HWND m_hMemoryTab;
		HWND m_hHandlesTab;
		HWND m_hSecurityTab;
		HWND m_hEnvironmentTab;
		HWND m_hNetworkTab;
		HWND m_hServicesTab;

		HWND m_hThreadListView;
		HWND m_hModuleListView;
		HWND m_hMemoryListView;
		HWND m_hHandleListView;
		HWND m_hServicesListView;

		DWORD m_ProcessId;
		WinProcessInspector::Core::ProcessInfo m_ProcessInfo;

		WinProcessInspector::Core::ProcessManager m_ProcessManager;
		WinProcessInspector::Core::ModuleManager m_ModuleManager;
		WinProcessInspector::Core::MemoryManager m_MemoryManager;
		WinProcessInspector::Core::HandleManager m_HandleManager;
		WinProcessInspector::Core::ServiceManager m_ServiceManager;
		WinProcessInspector::Security::SecurityManager m_SecurityManager;
		
		HFONT m_hBoldFont;
		HFONT m_hNormalFont;
	};

} // namespace GUI
} // namespace WinProcessInspector
