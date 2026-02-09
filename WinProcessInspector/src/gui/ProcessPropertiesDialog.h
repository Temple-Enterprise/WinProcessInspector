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
#include "../security/SecurityManager.h"

namespace WinProcessInspector {
namespace GUI {

	/**
	 * Process properties dialog - tabbed interface
	 */
	class ProcessPropertiesDialog {
	public:
		ProcessPropertiesDialog(HINSTANCE hInstance, HWND hParent);
		~ProcessPropertiesDialog();

		bool Show(DWORD processId);
		void Close();

	private:
		// Dialog creation
		bool CreateDialogWindow();
		bool CreateTabs();
		void CreateGeneralTab();
		void CreateThreadsTab();
		void CreateModulesTab();
		void CreateMemoryTab();
		void CreateHandlesTab();
		void CreateSecurityTab();

		// Message handling
		static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
		LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam);
		LRESULT OnCreate();
		LRESULT OnCommand(WPARAM wParam);
		LRESULT OnNotify(WPARAM wParam);
		LRESULT OnClose();
		LRESULT OnSize();

		// Tab management
		void OnTabChanged(int tabIndex);
		void RefreshCurrentTab();
		void RefreshGeneralTab();
		void RefreshThreadsTab();
		void RefreshModulesTab();
		void RefreshMemoryTab();
		void RefreshHandlesTab();
		void RefreshSecurityTab();

		HWND m_hDlg;
		HWND m_hParent;
		HINSTANCE m_hInstance;
		HWND m_hTabControl;
		HWND m_hGeneralTab;
		HWND m_hThreadsTab;
		HWND m_hModulesTab;
		HWND m_hMemoryTab;
		HWND m_hHandlesTab;
		HWND m_hSecurityTab;

		HWND m_hThreadListView;
		HWND m_hModuleListView;
		HWND m_hMemoryListView;
		HWND m_hHandleListView;

		DWORD m_ProcessId;
		WinProcessInspector::Core::ProcessInfo m_ProcessInfo;

		WinProcessInspector::Core::ProcessManager m_ProcessManager;
		WinProcessInspector::Core::ModuleManager m_ModuleManager;
		WinProcessInspector::Core::MemoryManager m_MemoryManager;
		WinProcessInspector::Core::HandleManager m_HandleManager;
		WinProcessInspector::Security::SecurityManager m_SecurityManager;
	};

} // namespace GUI
} // namespace WinProcessInspector
