#include "ProcessPropertiesDialog.h"
#include "../core/ProcessManager.h"
#include "../core/ModuleManager.h"
#include "../core/MemoryManager.h"
#include "../core/HandleManager.h"
#include "../security/SecurityManager.h"
#include "../utils/Logger.h"
#include "../../resource.h"
#include <commctrl.h>
#include <sstream>
#include <iomanip>

using namespace WinProcessInspector::GUI;
using namespace WinProcessInspector::Core;
using namespace WinProcessInspector::Security;
using namespace WinProcessInspector::Utils;

ProcessPropertiesDialog::ProcessPropertiesDialog(HINSTANCE hInstance, HWND hParent)
	: m_hDlg(nullptr)
	, m_hParent(hParent)
	, m_hInstance(hInstance)
	, m_hTabControl(nullptr)
	, m_hGeneralTab(nullptr)
	, m_hThreadsTab(nullptr)
	, m_hModulesTab(nullptr)
	, m_hMemoryTab(nullptr)
	, m_hHandlesTab(nullptr)
	, m_hSecurityTab(nullptr)
	, m_hThreadListView(nullptr)
	, m_hModuleListView(nullptr)
	, m_hMemoryListView(nullptr)
	, m_hHandleListView(nullptr)
	, m_ProcessId(0)
{
}

ProcessPropertiesDialog::~ProcessPropertiesDialog() {
	if (m_hDlg) {
		DestroyWindow(m_hDlg);
	}
}

bool ProcessPropertiesDialog::Show(DWORD processId) {
	m_ProcessId = processId;
	
	if (!m_hDlg) {
		if (!CreateDialogWindow()) {
			return false;
		}
		ShowWindow(m_hDlg, SW_HIDE); // Hide until ready
	}

	m_ProcessInfo = m_ProcessManager.GetProcessDetails(processId);
	if (m_ProcessInfo.ProcessId == 0) {
		return false;
	}

	// Update dialog title
	std::wostringstream title;
	title << L"Process Properties - " << m_ProcessInfo.ProcessId;
	std::wstring titleWStr = title.str();
	SetWindowTextW(m_hDlg, titleWStr.c_str());

	RefreshCurrentTab();
	ShowWindow(m_hDlg, SW_SHOW);
	SetForegroundWindow(m_hDlg);
	return true;
}

void ProcessPropertiesDialog::Close() {
	if (m_hDlg) {
		ShowWindow(m_hDlg, SW_HIDE);
	}
}

bool ProcessPropertiesDialog::CreateDialogWindow() {
	// Register window class for dialog
	WNDCLASSEXW wc = {};
	wc.cbSize = sizeof(WNDCLASSEXW);
	wc.style = CS_HREDRAW | CS_VREDRAW;
	wc.lpfnWndProc = WindowProc;
	wc.hInstance = m_hInstance;
	wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
	wc.lpszClassName = L"WinProcessInspectorPropertiesDialog";

	if (!RegisterClassExW(&wc)) {
		DWORD err = GetLastError();
		if (err != ERROR_CLASS_ALREADY_EXISTS) {
			return false;
		}
	}

	// Create modeless dialog window
	m_hDlg = CreateWindowExW(
		WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT,
		L"WinProcessInspectorPropertiesDialog",
		L"Process Properties",
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT,
		800, 600,
		m_hParent,
		nullptr,
		m_hInstance,
		this
	);

	if (!m_hDlg) {
		return false;
	}

	// Create OK button
	RECT rc;
	GetClientRect(m_hDlg, &rc);
	HWND hOkButton = CreateWindowW(
		L"BUTTON",
		L"OK",
		WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | WS_TABSTOP,
		rc.right - 85, rc.bottom - 35,
		75, 23,
		m_hDlg,
		reinterpret_cast<HMENU>(IDOK),
		m_hInstance,
		nullptr
	);

	return true;
}

bool ProcessPropertiesDialog::CreateTabs() {
	INITCOMMONCONTROLSEX icex = {};
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_TAB_CLASSES;
	InitCommonControlsEx(&icex);

	RECT rc;
	GetClientRect(m_hDlg, &rc);
	rc.top += 10;
	rc.left += 10;
	rc.right -= 10;
	rc.bottom -= 40;

	m_hTabControl = CreateWindowExW(
		0,
		WC_TABCONTROLW,
		L"",
		WS_VISIBLE | WS_CHILD | WS_CLIPSIBLINGS,
		rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
		m_hDlg,
		reinterpret_cast<HMENU>(IDC_TAB_CONTROL),
		m_hInstance,
		nullptr
	);

	if (!m_hTabControl) {
		return false;
	}

	TCITEMW tie = {};
	tie.mask = TCIF_TEXT;

	const wchar_t* tabTexts[] = {
		L"General",
		L"Threads",
		L"Modules",
		L"Memory",
		L"Handles",
		L"Security"
	};

	for (int i = 0; i < 6; ++i) {
		tie.pszText = const_cast<LPWSTR>(tabTexts[i]);
		TabCtrl_InsertItem(m_hTabControl, i, &tie);
	}

	CreateGeneralTab();
	CreateThreadsTab();
	CreateModulesTab();
	CreateMemoryTab();
	CreateHandlesTab();
	CreateSecurityTab();

	return true;
}

void ProcessPropertiesDialog::CreateGeneralTab() {
	RECT rc;
	GetWindowRect(m_hTabControl, &rc);
	ScreenToClient(m_hDlg, reinterpret_cast<LPPOINT>(&rc));
	TabCtrl_AdjustRect(m_hTabControl, FALSE, &rc);

	m_hGeneralTab = CreateWindowExW(
		WS_EX_CONTROLPARENT,
		L"STATIC",
		L"",
		WS_VISIBLE | WS_CHILD | WS_TABSTOP,
		rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
		m_hDlg,
		reinterpret_cast<HMENU>(IDC_GENERAL_TAB),
		m_hInstance,
		nullptr
	);
}

void ProcessPropertiesDialog::CreateThreadsTab() {
	RECT rc;
	GetWindowRect(m_hTabControl, &rc);
	ScreenToClient(m_hDlg, reinterpret_cast<LPPOINT>(&rc));
	TabCtrl_AdjustRect(m_hTabControl, FALSE, &rc);

	m_hThreadsTab = CreateWindowExW(
		WS_EX_CONTROLPARENT,
		L"STATIC",
		L"",
		WS_CHILD | WS_TABSTOP,
		rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
		m_hDlg,
		reinterpret_cast<HMENU>(IDC_THREADS_TAB),
		m_hInstance,
		nullptr
	);

	m_hThreadListView = CreateWindowExW(
		WS_EX_CLIENTEDGE,
		WC_LISTVIEWW,
		L"",
		WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
		rc.left + 10, rc.top + 10, rc.right - rc.left - 20, rc.bottom - rc.top - 20,
		m_hThreadsTab,
		reinterpret_cast<HMENU>(IDC_THREAD_LIST),
		m_hInstance,
		nullptr
	);

	if (m_hThreadListView) {
		LVCOLUMNW lvc = {};
		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
		lvc.fmt = LVCFMT_LEFT;

		lvc.pszText = const_cast<LPWSTR>(L"TID");
		lvc.cx = 100;
		ListView_InsertColumn(m_hThreadListView, 0, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"Start Address");
		lvc.cx = 150;
		ListView_InsertColumn(m_hThreadListView, 1, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"Priority");
		lvc.cx = 100;
		ListView_InsertColumn(m_hThreadListView, 2, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"State");
		lvc.cx = 100;
		ListView_InsertColumn(m_hThreadListView, 3, &lvc);
	}
}

void ProcessPropertiesDialog::CreateModulesTab() {
	RECT rc;
	GetWindowRect(m_hTabControl, &rc);
	ScreenToClient(m_hDlg, reinterpret_cast<LPPOINT>(&rc));
	TabCtrl_AdjustRect(m_hTabControl, FALSE, &rc);

	m_hModulesTab = CreateWindowExW(
		WS_EX_CONTROLPARENT,
		L"STATIC",
		L"",
		WS_CHILD | WS_TABSTOP,
		rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
		m_hDlg,
		reinterpret_cast<HMENU>(IDC_MODULES_TAB),
		m_hInstance,
		nullptr
	);

	m_hModuleListView = CreateWindowExW(
		WS_EX_CLIENTEDGE,
		WC_LISTVIEWW,
		L"",
		WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
		rc.left + 10, rc.top + 10, rc.right - rc.left - 20, rc.bottom - rc.top - 20,
		m_hModulesTab,
		reinterpret_cast<HMENU>(IDC_MODULE_LIST),
		m_hInstance,
		nullptr
	);

	if (m_hModuleListView) {
		LVCOLUMNW lvc = {};
		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
		lvc.fmt = LVCFMT_LEFT;

		lvc.pszText = const_cast<LPWSTR>(L"Name");
		lvc.cx = 200;
		ListView_InsertColumn(m_hModuleListView, 0, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"Base Address");
		lvc.cx = 150;
		ListView_InsertColumn(m_hModuleListView, 1, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"Size");
		lvc.cx = 100;
		ListView_InsertColumn(m_hModuleListView, 2, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"Path");
		lvc.cx = 300;
		ListView_InsertColumn(m_hModuleListView, 3, &lvc);
	}
}

void ProcessPropertiesDialog::CreateMemoryTab() {
	RECT rc;
	GetWindowRect(m_hTabControl, &rc);
	ScreenToClient(m_hDlg, reinterpret_cast<LPPOINT>(&rc));
	TabCtrl_AdjustRect(m_hTabControl, FALSE, &rc);

	m_hMemoryTab = CreateWindowExW(
		WS_EX_CONTROLPARENT,
		L"STATIC",
		L"",
		WS_CHILD | WS_TABSTOP,
		rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
		m_hDlg,
		reinterpret_cast<HMENU>(IDC_MEMORY_TAB),
		m_hInstance,
		nullptr
	);

	m_hMemoryListView = CreateWindowExW(
		WS_EX_CLIENTEDGE,
		WC_LISTVIEWW,
		L"",
		WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
		rc.left + 10, rc.top + 10, rc.right - rc.left - 20, rc.bottom - rc.top - 20,
		m_hMemoryTab,
		reinterpret_cast<HMENU>(IDC_MEMORY_LIST),
		m_hInstance,
		nullptr
	);

	if (m_hMemoryListView) {
		LVCOLUMNW lvc = {};
		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
		lvc.fmt = LVCFMT_LEFT;

		lvc.pszText = const_cast<LPWSTR>(L"Base Address");
		lvc.cx = 150;
		ListView_InsertColumn(m_hMemoryListView, 0, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"Size");
		lvc.cx = 120;
		ListView_InsertColumn(m_hMemoryListView, 1, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"State");
		lvc.cx = 100;
		ListView_InsertColumn(m_hMemoryListView, 2, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"Protection");
		lvc.cx = 150;
		ListView_InsertColumn(m_hMemoryListView, 3, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"Type");
		lvc.cx = 100;
		ListView_InsertColumn(m_hMemoryListView, 4, &lvc);
	}
}

void ProcessPropertiesDialog::CreateHandlesTab() {
	RECT rc;
	GetWindowRect(m_hTabControl, &rc);
	ScreenToClient(m_hDlg, reinterpret_cast<LPPOINT>(&rc));
	TabCtrl_AdjustRect(m_hTabControl, FALSE, &rc);

	m_hHandlesTab = CreateWindowExW(
		WS_EX_CONTROLPARENT,
		L"STATIC",
		L"",
		WS_CHILD | WS_TABSTOP,
		rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
		m_hDlg,
		reinterpret_cast<HMENU>(IDC_HANDLES_TAB),
		m_hInstance,
		nullptr
	);

	m_hHandleListView = CreateWindowExW(
		WS_EX_CLIENTEDGE,
		WC_LISTVIEWW,
		L"",
		WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
		rc.left + 10, rc.top + 10, rc.right - rc.left - 20, rc.bottom - rc.top - 20,
		m_hHandlesTab,
		reinterpret_cast<HMENU>(IDC_HANDLE_LIST),
		m_hInstance,
		nullptr
	);

	if (m_hHandleListView) {
		LVCOLUMNW lvc = {};
		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
		lvc.fmt = LVCFMT_LEFT;

		lvc.pszText = const_cast<LPWSTR>(L"Handle");
		lvc.cx = 100;
		ListView_InsertColumn(m_hHandleListView, 0, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"Type");
		lvc.cx = 120;
		ListView_InsertColumn(m_hHandleListView, 1, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"Access");
		lvc.cx = 100;
		ListView_InsertColumn(m_hHandleListView, 2, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"Name");
		lvc.cx = 300;
		ListView_InsertColumn(m_hHandleListView, 3, &lvc);
	}
}

void ProcessPropertiesDialog::CreateSecurityTab() {
	RECT rc;
	GetWindowRect(m_hTabControl, &rc);
	ScreenToClient(m_hDlg, reinterpret_cast<LPPOINT>(&rc));
	TabCtrl_AdjustRect(m_hTabControl, FALSE, &rc);

	m_hSecurityTab = CreateWindowExW(
		WS_EX_CONTROLPARENT,
		L"STATIC",
		L"",
		WS_CHILD | WS_TABSTOP,
		rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
		m_hDlg,
		reinterpret_cast<HMENU>(IDC_SECURITY_TAB),
		m_hInstance,
		nullptr
	);
}

LRESULT CALLBACK ProcessPropertiesDialog::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	ProcessPropertiesDialog* pThis = nullptr;

	if (uMsg == WM_NCCREATE) {
		CREATESTRUCT* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
		pThis = reinterpret_cast<ProcessPropertiesDialog*>(pCreate->lpCreateParams);
		SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
	} else {
		pThis = reinterpret_cast<ProcessPropertiesDialog*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
	}

	if (pThis) {
		return pThis->HandleMessage(uMsg, wParam, lParam);
	}

	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT ProcessPropertiesDialog::HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
		case WM_CREATE:
			return OnCreate();
		case WM_COMMAND:
			if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
				return OnClose();
			}
			return OnCommand(wParam);
		case WM_NOTIFY:
			return OnNotify(wParam);
		case WM_CLOSE:
			return OnClose();
		case WM_SIZE:
			return OnSize();
		default:
			return DefWindowProc(m_hDlg, uMsg, wParam, lParam);
	}
}

LRESULT ProcessPropertiesDialog::OnCreate() {
	CreateTabs();
	return 0;
}

LRESULT ProcessPropertiesDialog::OnCommand(WPARAM wParam) {
	return 0;
}

LRESULT ProcessPropertiesDialog::OnNotify(WPARAM wParam) {
	NMHDR* pnmh = reinterpret_cast<NMHDR*>(wParam);
	if (pnmh->idFrom == IDC_TAB_CONTROL && pnmh->code == TCN_SELCHANGE) {
		int sel = TabCtrl_GetCurSel(m_hTabControl);
		OnTabChanged(sel);
		return TRUE;
	}
	return 0;
}

LRESULT ProcessPropertiesDialog::OnClose() {
	ShowWindow(m_hDlg, SW_HIDE);
	return 0;
}

LRESULT ProcessPropertiesDialog::OnSize() {
	if (m_hTabControl) {
		RECT rc;
		GetClientRect(m_hDlg, &rc);
		rc.top += 10;
		rc.left += 10;
		rc.right -= 10;
		rc.bottom -= 50; // Space for OK button
		SetWindowPos(m_hTabControl, nullptr, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, SWP_NOZORDER);
		
		// Resize tab pages
		RECT tabRc = rc;
		TabCtrl_AdjustRect(m_hTabControl, FALSE, &tabRc);
		if (m_hGeneralTab) SetWindowPos(m_hGeneralTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		if (m_hThreadsTab) SetWindowPos(m_hThreadsTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		if (m_hModulesTab) SetWindowPos(m_hModulesTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		if (m_hMemoryTab) SetWindowPos(m_hMemoryTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		if (m_hHandlesTab) SetWindowPos(m_hHandlesTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		if (m_hSecurityTab) SetWindowPos(m_hSecurityTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		
		// Resize list views
		RECT listRc = tabRc;
		listRc.left += 10;
		listRc.top += 10;
		listRc.right -= 10;
		listRc.bottom -= 10;
		if (m_hThreadListView) SetWindowPos(m_hThreadListView, nullptr, listRc.left, listRc.top, listRc.right - listRc.left, listRc.bottom - listRc.top, SWP_NOZORDER);
		if (m_hModuleListView) SetWindowPos(m_hModuleListView, nullptr, listRc.left, listRc.top, listRc.right - listRc.left, listRc.bottom - listRc.top, SWP_NOZORDER);
		if (m_hMemoryListView) SetWindowPos(m_hMemoryListView, nullptr, listRc.left, listRc.top, listRc.right - listRc.left, listRc.bottom - listRc.top, SWP_NOZORDER);
		if (m_hHandleListView) SetWindowPos(m_hHandleListView, nullptr, listRc.left, listRc.top, listRc.right - listRc.left, listRc.bottom - listRc.top, SWP_NOZORDER);
		
		// Position OK button
		HWND hOkButton = GetDlgItem(m_hDlg, IDOK);
		if (hOkButton) {
			RECT btnRc;
			GetWindowRect(hOkButton, &btnRc);
			int btnWidth = btnRc.right - btnRc.left;
			int btnHeight = btnRc.bottom - btnRc.top;
			SetWindowPos(hOkButton, nullptr, rc.right - btnWidth - 10, rc.bottom + 10, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
		}
	}
	return 0;
}

void ProcessPropertiesDialog::OnTabChanged(int tabIndex) {
	// Hide all tabs
	ShowWindow(m_hGeneralTab, SW_HIDE);
	ShowWindow(m_hThreadsTab, SW_HIDE);
	ShowWindow(m_hModulesTab, SW_HIDE);
	ShowWindow(m_hMemoryTab, SW_HIDE);
	ShowWindow(m_hHandlesTab, SW_HIDE);
	ShowWindow(m_hSecurityTab, SW_HIDE);

	// Show selected tab
	switch (tabIndex) {
		case 0:
			ShowWindow(m_hGeneralTab, SW_SHOW);
			RefreshGeneralTab();
			break;
		case 1:
			ShowWindow(m_hThreadsTab, SW_SHOW);
			RefreshThreadsTab();
			break;
		case 2:
			ShowWindow(m_hModulesTab, SW_SHOW);
			RefreshModulesTab();
			break;
		case 3:
			ShowWindow(m_hMemoryTab, SW_SHOW);
			RefreshMemoryTab();
			break;
		case 4:
			ShowWindow(m_hHandlesTab, SW_SHOW);
			RefreshHandlesTab();
			break;
		case 5:
			ShowWindow(m_hSecurityTab, SW_SHOW);
			RefreshSecurityTab();
			break;
	}
}

void ProcessPropertiesDialog::RefreshCurrentTab() {
	int sel = TabCtrl_GetCurSel(m_hTabControl);
	if (sel >= 0) {
		OnTabChanged(sel);
	}
}

void ProcessPropertiesDialog::RefreshGeneralTab() {
	// TODO: Populate general tab with process info
}

void ProcessPropertiesDialog::RefreshThreadsTab() {
	if (!m_hThreadListView) return;

	ListView_DeleteAllItems(m_hThreadListView);
	auto threads = m_ProcessManager.EnumerateThreads(m_ProcessId);

	for (size_t i = 0; i < threads.size(); ++i) {
		const auto& thread = threads[i];

		LVITEMW lvi = {};
		lvi.mask = LVIF_TEXT;
		lvi.iItem = static_cast<int>(i);

		std::wostringstream tidStr;
		tidStr << thread.ThreadId;
		std::wstring tidWStr = tidStr.str();
		LPCWSTR tidText = tidWStr.c_str();
		lvi.pszText = const_cast<LPWSTR>(tidText);
		ListView_InsertItem(m_hThreadListView, &lvi);

		std::wostringstream addrStr;
		addrStr << std::hex << thread.StartAddress;
		std::wstring addrWStr = L"0x" + addrStr.str();
		LPCWSTR addrText = addrWStr.c_str();
		ListView_SetItemText(m_hThreadListView, i, 1, const_cast<LPWSTR>(addrText));

		std::wostringstream priStr;
		priStr << thread.Priority;
		std::wstring priWStr = priStr.str();
		LPCWSTR priText = priWStr.c_str();
		ListView_SetItemText(m_hThreadListView, i, 2, const_cast<LPWSTR>(priText));

		std::wstring stateStr = thread.State == 2 ? L"Running" : L"Suspended";
		LPCWSTR stateText = stateStr.c_str();
		ListView_SetItemText(m_hThreadListView, i, 3, const_cast<LPWSTR>(stateText));
	}
}

void ProcessPropertiesDialog::RefreshModulesTab() {
	if (!m_hModuleListView) return;

	ListView_DeleteAllItems(m_hModuleListView);
	auto modules = m_ModuleManager.EnumerateModules(m_ProcessId);

	for (size_t i = 0; i < modules.size(); ++i) {
		const auto& mod = modules[i];

		LVITEMW lvi = {};
		lvi.mask = LVIF_TEXT;
		lvi.iItem = static_cast<int>(i);
		LPCWSTR modNameText = mod.Name.c_str();
		lvi.pszText = const_cast<LPWSTR>(modNameText);
		ListView_InsertItem(m_hModuleListView, &lvi);

		std::wostringstream addrStr;
		addrStr << std::hex << mod.BaseAddress;
		std::wstring addrWStr = L"0x" + addrStr.str();
		LPCWSTR addrText = addrWStr.c_str();
		ListView_SetItemText(m_hModuleListView, i, 1, const_cast<LPWSTR>(addrText));

		std::wostringstream sizeStr;
		sizeStr << mod.Size;
		std::wstring sizeWStr = sizeStr.str();
		LPCWSTR sizeText = sizeWStr.c_str();
		ListView_SetItemText(m_hModuleListView, i, 2, const_cast<LPWSTR>(sizeText));

		LPCWSTR pathText = mod.FullPath.c_str();
		ListView_SetItemText(m_hModuleListView, i, 3, const_cast<LPWSTR>(pathText));
	}
}

void ProcessPropertiesDialog::RefreshMemoryTab() {
	if (!m_hMemoryListView) return;

	ListView_DeleteAllItems(m_hMemoryListView);
	auto regions = m_MemoryManager.EnumerateMemoryRegions(m_ProcessId);

	for (size_t i = 0; i < regions.size(); ++i) {
		const auto& region = regions[i];

		std::wostringstream addrStr;
		addrStr << std::hex << region.BaseAddress;
		std::wstring addrWStr = L"0x" + addrStr.str();
		LPCWSTR addrText = addrWStr.c_str();

		LVITEMW lvi = {};
		lvi.mask = LVIF_TEXT;
		lvi.iItem = static_cast<int>(i);
		lvi.pszText = const_cast<LPWSTR>(addrText);
		ListView_InsertItem(m_hMemoryListView, &lvi);

		std::wostringstream sizeStr;
		sizeStr << region.RegionSize;
		std::wstring sizeWStr = sizeStr.str();
		LPCWSTR sizeText = sizeWStr.c_str();
		ListView_SetItemText(m_hMemoryListView, i, 1, const_cast<LPWSTR>(sizeText));

		LPCWSTR stateText = region.StateString.c_str();
		ListView_SetItemText(m_hMemoryListView, i, 2, const_cast<LPWSTR>(stateText));
		LPCWSTR protectText = region.ProtectionString.c_str();
		ListView_SetItemText(m_hMemoryListView, i, 3, const_cast<LPWSTR>(protectText));
		LPCWSTR typeText = region.TypeString.c_str();
		ListView_SetItemText(m_hMemoryListView, i, 4, const_cast<LPWSTR>(typeText));
	}
}

void ProcessPropertiesDialog::RefreshHandlesTab() {
	if (!m_hHandleListView) return;

	ListView_DeleteAllItems(m_hHandleListView);
	auto handles = m_HandleManager.EnumerateHandles(m_ProcessId);

	for (size_t i = 0; i < handles.size(); ++i) {
		const auto& handle = handles[i];

		std::wostringstream handleStr;
		handleStr << std::hex << reinterpret_cast<ULONG_PTR>(handle.HandleValue);
		std::wstring handleWStr = L"0x" + handleStr.str();
		LPCWSTR handleText = handleWStr.c_str();

		LVITEMW lvi = {};
		lvi.mask = LVIF_TEXT;
		lvi.iItem = static_cast<int>(i);
		lvi.pszText = const_cast<LPWSTR>(handleText);
		ListView_InsertItem(m_hHandleListView, &lvi);

		LPCWSTR typeNameText = handle.ObjectTypeName.c_str();
		ListView_SetItemText(m_hHandleListView, i, 1, const_cast<LPWSTR>(typeNameText));

		std::wostringstream accessStr;
		accessStr << std::hex << handle.AccessMask;
		std::wstring accessWStr = L"0x" + accessStr.str();
		LPCWSTR accessText = accessWStr.c_str();
		ListView_SetItemText(m_hHandleListView, i, 2, const_cast<LPWSTR>(accessText));

		std::wstring nameStr = handle.ObjectName.empty() ? L"N/A" : handle.ObjectName;
		LPCWSTR nameText = nameStr.c_str();
		ListView_SetItemText(m_hHandleListView, i, 3, const_cast<LPWSTR>(nameText));
	}
}

void ProcessPropertiesDialog::RefreshSecurityTab() {
	// TODO: Populate security tab with token info
}
