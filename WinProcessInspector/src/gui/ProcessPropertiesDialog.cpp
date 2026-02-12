#include "ProcessPropertiesDialog.h"
#include "../core/ProcessManager.h"
#include "../core/ModuleManager.h"
#include "../core/MemoryManager.h"
#include "../core/HandleManager.h"
#include "../core/NetworkManager.h"
#include "../core/ServiceManager.h"
#include "../security/SecurityManager.h"
#include "../utils/Logger.h"
#include "../utils/CryptoHelper.h"
#include "../../resource.h"
#include <commctrl.h>
#include <sstream>
#include <iomanip>
#include <psapi.h>

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
	, m_hPerformanceTab(nullptr)
	, m_hThreadsTab(nullptr)
	, m_hModulesTab(nullptr)
	, m_hMemoryTab(nullptr)
	, m_hHandlesTab(nullptr)
	, m_hSecurityTab(nullptr)
	, m_hEnvironmentTab(nullptr)
	, m_hNetworkTab(nullptr)
	, m_hServicesTab(nullptr)
	, m_hThreadListView(nullptr)
	, m_hModuleListView(nullptr)
	, m_hMemoryListView(nullptr)
	, m_hHandleListView(nullptr)
	, m_hServicesListView(nullptr)
	, m_ProcessId(0)
	, m_hBoldFont(nullptr)
	, m_hNormalFont(nullptr)
{
	m_hNormalFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
		CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
	
	m_hBoldFont = CreateFontW(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
		CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
}

ProcessPropertiesDialog::~ProcessPropertiesDialog() {
	if (m_hBoldFont) {
		DeleteObject(m_hBoldFont);
	}
	if (m_hNormalFont) {
		DeleteObject(m_hNormalFont);
	}
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
		ShowWindow(m_hDlg, SW_HIDE);
	}

	m_ProcessInfo = m_ProcessManager.GetProcessDetails(processId);
	if (m_ProcessInfo.ProcessId == 0) {
		return false;
	}
	
	DWORD priorityClass = 0;
	if (m_ProcessManager.GetProcessPriorityClass(processId, priorityClass)) {
		m_ProcessInfo.PriorityClass = priorityClass;
	}
	
	DWORD_PTR processAffinity = 0, systemAffinity = 0;
	if (m_ProcessManager.GetProcessAffinityMask(processId, processAffinity, systemAffinity)) {
		m_ProcessInfo.AffinityMask = processAffinity;
	}

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

	m_hDlg = CreateWindowExW(
		WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT,
		L"WinProcessInspectorPropertiesDialog",
		L"Process Properties",
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT,
		900, 700,
		m_hParent,
		nullptr,
		m_hInstance,
		this
	);

	if (!m_hDlg) {
		return false;
	}

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
		L"Performance",
		L"Threads",
		L"Modules",
		L"Memory",
		L"Handles",
		L"Security",
		L"Environment",
		L"Network",
		L"Services"
	};

	for (int i = 0; i < 10; ++i) {
		tie.pszText = const_cast<LPWSTR>(tabTexts[i]);
		TabCtrl_InsertItem(m_hTabControl, i, &tie);
	}

	CreateGeneralTab();
	CreatePerformanceTab();
	CreateThreadsTab();
	CreateModulesTab();
	CreateMemoryTab();
	CreateHandlesTab();
	CreateSecurityTab();
	CreateEnvironmentTab();
	CreateNetworkTab();
	CreateServicesTab();

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
	
	HWND hSearchButton = CreateWindowW(
		L"BUTTON",
		L"Search Online",
		WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP,
		rc.left + 10, rc.top + 10,
		120, 25,
		m_hGeneralTab,
		reinterpret_cast<HMENU>(IDC_SEARCH_ONLINE_BUTTON),
		m_hInstance,
		nullptr
	);
}

void ProcessPropertiesDialog::CreatePerformanceTab() {
	RECT rc;
	GetWindowRect(m_hTabControl, &rc);
	ScreenToClient(m_hDlg, reinterpret_cast<LPPOINT>(&rc));
	TabCtrl_AdjustRect(m_hTabControl, FALSE, &rc);

	m_hPerformanceTab = CreateWindowExW(
		WS_EX_CONTROLPARENT,
		L"STATIC",
		L"",
		WS_CHILD | WS_TABSTOP,
		rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
		m_hDlg,
		reinterpret_cast<HMENU>(IDC_PERFORMANCE_TAB),
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
		rc.bottom -= 50;
		SetWindowPos(m_hTabControl, nullptr, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, SWP_NOZORDER);
		
		RECT tabRc = rc;
		TabCtrl_AdjustRect(m_hTabControl, FALSE, &tabRc);
		if (m_hGeneralTab) SetWindowPos(m_hGeneralTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		if (m_hPerformanceTab) SetWindowPos(m_hPerformanceTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		if (m_hThreadsTab) SetWindowPos(m_hThreadsTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		if (m_hModulesTab) SetWindowPos(m_hModulesTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		if (m_hMemoryTab) SetWindowPos(m_hMemoryTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		if (m_hHandlesTab) SetWindowPos(m_hHandlesTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		if (m_hSecurityTab) SetWindowPos(m_hSecurityTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		if (m_hEnvironmentTab) SetWindowPos(m_hEnvironmentTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		if (m_hNetworkTab) SetWindowPos(m_hNetworkTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		if (m_hServicesTab) SetWindowPos(m_hServicesTab, nullptr, tabRc.left, tabRc.top, tabRc.right - tabRc.left, tabRc.bottom - tabRc.top, SWP_NOZORDER);
		
		RECT listRc = tabRc;
		listRc.left += 10;
		listRc.top += 10;
		listRc.right -= 10;
		listRc.bottom -= 10;
		if (m_hThreadListView) SetWindowPos(m_hThreadListView, nullptr, listRc.left, listRc.top, listRc.right - listRc.left, listRc.bottom - listRc.top, SWP_NOZORDER);
		if (m_hModuleListView) SetWindowPos(m_hModuleListView, nullptr, listRc.left, listRc.top, listRc.right - listRc.left, listRc.bottom - listRc.top, SWP_NOZORDER);
		if (m_hMemoryListView) SetWindowPos(m_hMemoryListView, nullptr, listRc.left, listRc.top, listRc.right - listRc.left, listRc.bottom - listRc.top, SWP_NOZORDER);
		if (m_hHandleListView) SetWindowPos(m_hHandleListView, nullptr, listRc.left, listRc.top, listRc.right - listRc.left, listRc.bottom - listRc.top, SWP_NOZORDER);
		if (m_hServicesListView) SetWindowPos(m_hServicesListView, nullptr, listRc.left, listRc.top, listRc.right - listRc.left, listRc.bottom - listRc.top, SWP_NOZORDER);
		
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
	ShowWindow(m_hGeneralTab, SW_HIDE);
	ShowWindow(m_hPerformanceTab, SW_HIDE);
	ShowWindow(m_hThreadsTab, SW_HIDE);
	ShowWindow(m_hModulesTab, SW_HIDE);
	ShowWindow(m_hMemoryTab, SW_HIDE);
	ShowWindow(m_hHandlesTab, SW_HIDE);
	ShowWindow(m_hSecurityTab, SW_HIDE);
	ShowWindow(m_hEnvironmentTab, SW_HIDE);
	ShowWindow(m_hNetworkTab, SW_HIDE);
	ShowWindow(m_hServicesTab, SW_HIDE);

	switch (tabIndex) {
		case 0:
			ShowWindow(m_hGeneralTab, SW_SHOW);
			RefreshGeneralTab();
			break;
		case 1:
			ShowWindow(m_hPerformanceTab, SW_SHOW);
			RefreshPerformanceTab();
			break;
		case 2:
			ShowWindow(m_hThreadsTab, SW_SHOW);
			RefreshThreadsTab();
			break;
		case 3:
			ShowWindow(m_hModulesTab, SW_SHOW);
			RefreshModulesTab();
			break;
		case 4:
			ShowWindow(m_hMemoryTab, SW_SHOW);
			RefreshMemoryTab();
			break;
		case 5:
			ShowWindow(m_hHandlesTab, SW_SHOW);
			RefreshHandlesTab();
			break;
		case 6:
			ShowWindow(m_hSecurityTab, SW_SHOW);
			RefreshSecurityTab();
			break;
		case 7:
			ShowWindow(m_hEnvironmentTab, SW_SHOW);
			RefreshEnvironmentTab();
			break;
		case 8:
			ShowWindow(m_hNetworkTab, SW_SHOW);
			RefreshNetworkTab();
			break;
		case 9:
			ShowWindow(m_hServicesTab, SW_SHOW);
			RefreshServicesTab();
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
	if (!m_hGeneralTab) return;
	
	HWND hChild = GetWindow(m_hGeneralTab, GW_CHILD);
	while (hChild) {
		HWND hNext = GetWindow(hChild, GW_HWNDNEXT);
		if (GetDlgCtrlID(hChild) != IDC_SEARCH_ONLINE_BUTTON) {
			DestroyWindow(hChild);
		}
		hChild = hNext;
	}
	
	int yPos = 45;
	int leftCol = 20;
	int rightCol = 180;
	int lineHeight = 25;
	
	AddStaticText(m_hGeneralTab, L"Process Information", leftCol, yPos, 300, 20, true);
	yPos += lineHeight + 5;
	
	AddStaticText(m_hGeneralTab, L"Name:", leftCol, yPos, 150, 20);
	std::wstring nameW(m_ProcessInfo.ProcessName.begin(), m_ProcessInfo.ProcessName.end());
	AddStaticText(m_hGeneralTab, nameW.c_str(), rightCol, yPos, 400, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hGeneralTab, L"Process ID (PID):", leftCol, yPos, 150, 20);
	std::wstring pidStr = std::to_wstring(m_ProcessInfo.ProcessId);
	AddStaticText(m_hGeneralTab, pidStr.c_str(), rightCol, yPos, 400, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hGeneralTab, L"Parent PID:", leftCol, yPos, 150, 20);
	std::wstring ppidStr = std::to_wstring(m_ProcessInfo.ParentProcessId);
	AddStaticText(m_hGeneralTab, ppidStr.c_str(), rightCol, yPos, 400, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hGeneralTab, L"Session ID:", leftCol, yPos, 150, 20);
	std::wstring sessionStr = std::to_wstring(m_ProcessInfo.SessionId);
	AddStaticText(m_hGeneralTab, sessionStr.c_str(), rightCol, yPos, 400, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hGeneralTab, L"Architecture:", leftCol, yPos, 150, 20);
	std::wstring archW(m_ProcessInfo.Architecture.begin(), m_ProcessInfo.Architecture.end());
	AddStaticText(m_hGeneralTab, archW.c_str(), rightCol, yPos, 400, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hGeneralTab, L"Creation Time:", leftCol, yPos, 150, 20);
	std::wstring timeStr = FormatFileTime(m_ProcessInfo.CreationTime);
	AddStaticText(m_hGeneralTab, timeStr.c_str(), rightCol, yPos, 400, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hGeneralTab, L"User:", leftCol, yPos, 150, 20);
	std::wstring userStr = m_ProcessInfo.UserDomain + L"\\" + m_ProcessInfo.UserName;
	if (userStr == L"\\") userStr = L"N/A";
	AddStaticText(m_hGeneralTab, userStr.c_str(), rightCol, yPos, 400, 20);
	yPos += lineHeight + 10;
	
	AddStaticText(m_hGeneralTab, L"Command Line", leftCol, yPos, 300, 20, true);
	yPos += lineHeight;
	
	std::wstring cmdLine = m_ProcessInfo.CommandLine.empty() ? L"N/A" : m_ProcessInfo.CommandLine;
	AddEditBox(m_hGeneralTab, cmdLine.c_str(), leftCol, yPos, 720, 80, true, true);
	yPos += 90;
	
	HandleWrapper hProcess = m_ProcessManager.OpenProcess(m_ProcessId, PROCESS_QUERY_INFORMATION);
	if (hProcess.IsValid()) {
		WCHAR imagePath[MAX_PATH] = {};
		if (GetModuleFileNameExW(hProcess.Get(), nullptr, imagePath, MAX_PATH)) {
			AddStaticText(m_hGeneralTab, L"Image Path", leftCol, yPos, 300, 20, true);
			yPos += lineHeight;
			AddEditBox(m_hGeneralTab, imagePath, leftCol, yPos, 720, 60, true, true);
		}
	}
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
	if (!m_hSecurityTab) return;
	
	HWND hChild = GetWindow(m_hSecurityTab, GW_CHILD);
	while (hChild) {
		HWND hNext = GetWindow(hChild, GW_HWNDNEXT);
		DestroyWindow(hChild);
		hChild = hNext;
	}
	
	int yPos = 20;
	int leftCol = 20;
	int rightCol = 220;
	int lineHeight = 25;
	
	AddStaticText(m_hSecurityTab, L"Integrity & Privileges", leftCol, yPos, 300, 20, true);
	yPos += lineHeight + 5;
	
	AddStaticText(m_hSecurityTab, L"Integrity Level:", leftCol, yPos, 190, 20);
	std::wstring integrityStr;
	switch (m_ProcessInfo.IntegrityLevel) {
		case IntegrityLevel::Untrusted: integrityStr = L"Untrusted"; break;
		case IntegrityLevel::Low: integrityStr = L"Low"; break;
		case IntegrityLevel::Medium: integrityStr = L"Medium"; break;
		case IntegrityLevel::High: integrityStr = L"High"; break;
		case IntegrityLevel::System: integrityStr = L"System"; break;
		default: integrityStr = L"Unknown"; break;
	}
	AddStaticText(m_hSecurityTab, integrityStr.c_str(), rightCol, yPos, 200, 20);
	yPos += lineHeight + 15;
	
	AddStaticText(m_hSecurityTab, L"Security Mitigations", leftCol, yPos, 300, 20, true);
	yPos += lineHeight + 5;
	
	AddStaticText(m_hSecurityTab, L"DEP (Data Execution Prevention):", leftCol, yPos, 190, 20);
	AddStaticText(m_hSecurityTab, m_ProcessInfo.DEPEnabled ? L"✓ Enabled" : L"✗ Disabled", rightCol, yPos, 200, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hSecurityTab, L"ASLR (Address Randomization):", leftCol, yPos, 190, 20);
	AddStaticText(m_hSecurityTab, m_ProcessInfo.ASLREnabled ? L"✓ Enabled" : L"✗ Disabled", rightCol, yPos, 200, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hSecurityTab, L"CFG (Control Flow Guard):", leftCol, yPos, 190, 20);
	AddStaticText(m_hSecurityTab, m_ProcessInfo.CFGEnabled ? L"✓ Enabled" : L"✗ Disabled", rightCol, yPos, 200, 20);
	yPos += lineHeight + 15;
	
	AddStaticText(m_hSecurityTab, L"Sandboxing & Isolation", leftCol, yPos, 300, 20, true);
	yPos += lineHeight + 5;
	
	AddStaticText(m_hSecurityTab, L"UAC Virtualized:", leftCol, yPos, 190, 20);
	AddStaticText(m_hSecurityTab, m_ProcessInfo.IsVirtualized ? L"Yes" : L"No", rightCol, yPos, 200, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hSecurityTab, L"AppContainer (UWP):", leftCol, yPos, 190, 20);
	AddStaticText(m_hSecurityTab, m_ProcessInfo.IsAppContainer ? L"Yes" : L"No", rightCol, yPos, 200, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hSecurityTab, L"In Job Object:", leftCol, yPos, 190, 20);
	AddStaticText(m_hSecurityTab, m_ProcessInfo.IsInJob ? L"Yes" : L"No", rightCol, yPos, 200, 20);
	yPos += lineHeight + 15;
	
	AddStaticText(m_hSecurityTab, L"User Information", leftCol, yPos, 300, 20, true);
	yPos += lineHeight + 5;
	
	AddStaticText(m_hSecurityTab, L"User Name:", leftCol, yPos, 190, 20);
	std::wstring fullUser = m_ProcessInfo.UserDomain + L"\\" + m_ProcessInfo.UserName;
	if (fullUser == L"\\") fullUser = L"N/A";
	AddEditBox(m_hSecurityTab, fullUser.c_str(), rightCol, yPos, 520, 20, false, true);
	yPos += lineHeight;
	
	AddStaticText(m_hSecurityTab, L"User SID:", leftCol, yPos, 190, 20);
	std::wstring sidStr = m_ProcessInfo.UserSid.empty() ? L"N/A" : m_ProcessInfo.UserSid;
	AddEditBox(m_hSecurityTab, sidStr.c_str(), rightCol, yPos, 520, 20, false, true);
}

void ProcessPropertiesDialog::CreateEnvironmentTab() {
	RECT rc;
	GetWindowRect(m_hTabControl, &rc);
	ScreenToClient(m_hDlg, reinterpret_cast<LPPOINT>(&rc));
	TabCtrl_AdjustRect(m_hTabControl, FALSE, &rc);

	m_hEnvironmentTab = CreateWindowExW(
		WS_EX_CONTROLPARENT,
		L"STATIC",
		L"",
		WS_CHILD | WS_TABSTOP,
		rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
		m_hDlg,
		reinterpret_cast<HMENU>(IDC_ENVIRONMENT_TAB),
		m_hInstance,
		nullptr
	);
}

void ProcessPropertiesDialog::CreateNetworkTab() {
	RECT rc;
	GetWindowRect(m_hTabControl, &rc);
	ScreenToClient(m_hDlg, reinterpret_cast<LPPOINT>(&rc));
	TabCtrl_AdjustRect(m_hTabControl, FALSE, &rc);

	m_hNetworkTab = CreateWindowExW(
		WS_EX_CONTROLPARENT,
		L"STATIC",
		L"",
		WS_CHILD | WS_TABSTOP,
		rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
		m_hDlg,
		reinterpret_cast<HMENU>(IDC_NETWORK_TAB),
		m_hInstance,
		nullptr
	);
}

void ProcessPropertiesDialog::CreateServicesTab() {
	RECT rc;
	GetWindowRect(m_hTabControl, &rc);
	ScreenToClient(m_hDlg, reinterpret_cast<LPPOINT>(&rc));
	TabCtrl_AdjustRect(m_hTabControl, FALSE, &rc);

	m_hServicesTab = CreateWindowExW(
		WS_EX_CONTROLPARENT,
		L"STATIC",
		L"",
		WS_CHILD | WS_TABSTOP,
		rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
		m_hDlg,
		reinterpret_cast<HMENU>(IDC_SERVICES_TAB),
		m_hInstance,
		nullptr
	);

	m_hServicesListView = CreateWindowExW(
		WS_EX_CLIENTEDGE,
		WC_LISTVIEWW,
		L"",
		WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
		rc.left + 10, rc.top + 10, rc.right - rc.left - 20, rc.bottom - rc.top - 20,
		m_hServicesTab,
		reinterpret_cast<HMENU>(IDC_SERVICES_LIST),
		m_hInstance,
		nullptr
	);

	if (m_hServicesListView) {
		ListView_SetExtendedListViewStyle(m_hServicesListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
		
		LVCOLUMNW lvc = {};
		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
		lvc.fmt = LVCFMT_LEFT;

		lvc.pszText = const_cast<LPWSTR>(L"Service Name");
		lvc.cx = 200;
		ListView_InsertColumn(m_hServicesListView, 0, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"Display Name");
		lvc.cx = 250;
		ListView_InsertColumn(m_hServicesListView, 1, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"State");
		lvc.cx = 120;
		ListView_InsertColumn(m_hServicesListView, 2, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"Type");
		lvc.cx = 150;
		ListView_InsertColumn(m_hServicesListView, 3, &lvc);

		lvc.pszText = const_cast<LPWSTR>(L"Description");
		lvc.cx = 300;
		ListView_InsertColumn(m_hServicesListView, 4, &lvc);
	}
}

void ProcessPropertiesDialog::RefreshPerformanceTab() {
	if (!m_hPerformanceTab) return;
	
	HWND hChild = GetWindow(m_hPerformanceTab, GW_CHILD);
	while (hChild) {
		HWND hNext = GetWindow(hChild, GW_HWNDNEXT);
		DestroyWindow(hChild);
		hChild = hNext;
	}
	
	m_ProcessInfo = m_ProcessManager.GetProcessDetails(m_ProcessId);
	
	int yPos = 20;
	int leftCol = 20;
	int rightCol = 200;
	int lineHeight = 25;
	
	AddStaticText(m_hPerformanceTab, L"Resource Usage", leftCol, yPos, 300, 20, true);
	yPos += lineHeight + 5;
	
	AddStaticText(m_hPerformanceTab, L"Thread Count:", leftCol, yPos, 170, 20);
	AddStaticText(m_hPerformanceTab, std::to_wstring(m_ProcessInfo.ThreadCount).c_str(), rightCol, yPos, 200, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hPerformanceTab, L"Handle Count:", leftCol, yPos, 170, 20);
	AddStaticText(m_hPerformanceTab, FormatNumber(m_ProcessInfo.HandleCount).c_str(), rightCol, yPos, 200, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hPerformanceTab, L"GDI Objects:", leftCol, yPos, 170, 20);
	AddStaticText(m_hPerformanceTab, std::to_wstring(m_ProcessInfo.GdiObjectCount).c_str(), rightCol, yPos, 200, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hPerformanceTab, L"USER Objects:", leftCol, yPos, 170, 20);
	AddStaticText(m_hPerformanceTab, std::to_wstring(m_ProcessInfo.UserObjectCount).c_str(), rightCol, yPos, 200, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hPerformanceTab, L"Peak Memory:", leftCol, yPos, 170, 20);
	AddStaticText(m_hPerformanceTab, FormatBytes(m_ProcessInfo.PeakWorkingSetSize).c_str(), rightCol, yPos, 200, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hPerformanceTab, L"Page Faults:", leftCol, yPos, 170, 20);
	AddStaticText(m_hPerformanceTab, FormatNumber(m_ProcessInfo.PageFaultCount).c_str(), rightCol, yPos, 200, 20);
	yPos += lineHeight + 15;
	
	AddStaticText(m_hPerformanceTab, L"I/O Statistics", leftCol, yPos, 300, 20, true);
	yPos += lineHeight + 5;
	
	AddStaticText(m_hPerformanceTab, L"Read Operations:", leftCol, yPos, 170, 20);
	AddStaticText(m_hPerformanceTab, FormatNumber(m_ProcessInfo.ReadOperationCount).c_str(), rightCol, yPos, 200, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hPerformanceTab, L"Write Operations:", leftCol, yPos, 170, 20);
	AddStaticText(m_hPerformanceTab, FormatNumber(m_ProcessInfo.WriteOperationCount).c_str(), rightCol, yPos, 200, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hPerformanceTab, L"Bytes Read:", leftCol, yPos, 170, 20);
	AddStaticText(m_hPerformanceTab, FormatBytes(m_ProcessInfo.ReadTransferCount).c_str(), rightCol, yPos, 200, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hPerformanceTab, L"Bytes Written:", leftCol, yPos, 170, 20);
	AddStaticText(m_hPerformanceTab, FormatBytes(m_ProcessInfo.WriteTransferCount).c_str(), rightCol, yPos, 200, 20);
	yPos += lineHeight + 15;
	
	AddStaticText(m_hPerformanceTab, L"Process Priority", leftCol, yPos, 300, 20, true);
	yPos += lineHeight + 5;
	
	AddStaticText(m_hPerformanceTab, L"Priority Class:", leftCol, yPos, 170, 20);
	std::wstring priorityStr = m_ProcessManager.GetPriorityClassString(m_ProcessInfo.PriorityClass);
	AddStaticText(m_hPerformanceTab, priorityStr.c_str(), rightCol, yPos, 200, 20);
	yPos += lineHeight;
	
	AddStaticText(m_hPerformanceTab, L"Affinity Mask:", leftCol, yPos, 170, 20);
	std::wostringstream affinityStr;
	affinityStr << L"0x" << std::hex << m_ProcessInfo.AffinityMask;
	AddStaticText(m_hPerformanceTab, affinityStr.str().c_str(), rightCol, yPos, 200, 20);
}

void ProcessPropertiesDialog::RefreshEnvironmentTab() {
	if (!m_hEnvironmentTab) return;
	
	HWND hChild = GetWindow(m_hEnvironmentTab, GW_CHILD);
	while (hChild) {
		HWND hNext = GetWindow(hChild, GW_HWNDNEXT);
		DestroyWindow(hChild);
		hChild = hNext;
	}
	
	RECT rc;
	GetClientRect(m_hEnvironmentTab, &rc);
	
	AddStaticText(m_hEnvironmentTab, L"File Hashes (Integrity Verification)", 20, 20, 500, 20, true);
	
	HandleWrapper hProcess = m_ProcessManager.OpenProcess(m_ProcessId, PROCESS_QUERY_INFORMATION);
	if (hProcess.IsValid()) {
		WCHAR imagePath[MAX_PATH] = {};
		if (GetModuleFileNameExW(hProcess.Get(), nullptr, imagePath, MAX_PATH)) {
			int yPos = 50;
			
			AddStaticText(m_hEnvironmentTab, L"MD5:", 20, yPos, 100, 20);
			std::wstring md5 = CryptoHelper::CalculateMD5(imagePath);
			if (md5.empty()) md5 = L"Unable to calculate";
			AddEditBox(m_hEnvironmentTab, md5.c_str(), 130, yPos, 600, 22, false, true);
			yPos += 35;
			
			AddStaticText(m_hEnvironmentTab, L"SHA-1:", 20, yPos, 100, 20);
			std::wstring sha1 = CryptoHelper::CalculateSHA1(imagePath);
			if (sha1.empty()) sha1 = L"Unable to calculate";
			AddEditBox(m_hEnvironmentTab, sha1.c_str(), 130, yPos, 600, 22, false, true);
			yPos += 35;
			
			AddStaticText(m_hEnvironmentTab, L"SHA-256:", 20, yPos, 100, 20);
			std::wstring sha256 = CryptoHelper::CalculateSHA256(imagePath);
			if (sha256.empty()) sha256 = L"Unable to calculate";
			AddEditBox(m_hEnvironmentTab, sha256.c_str(), 130, yPos, 600, 22, false, true);
			yPos += 50;
			
			AddStaticText(m_hEnvironmentTab, L"Process Attributes", 20, yPos, 300, 20, true);
			yPos += 30;
			
			DWORD fileAttr = GetFileAttributesW(imagePath);
			std::wstring attrStr;
			if (fileAttr != INVALID_FILE_ATTRIBUTES) {
				if (fileAttr & FILE_ATTRIBUTE_READONLY) attrStr += L"Read-Only, ";
				if (fileAttr & FILE_ATTRIBUTE_HIDDEN) attrStr += L"Hidden, ";
				if (fileAttr & FILE_ATTRIBUTE_SYSTEM) attrStr += L"System, ";
				if (fileAttr & FILE_ATTRIBUTE_COMPRESSED) attrStr += L"Compressed, ";
				if (fileAttr & FILE_ATTRIBUTE_ENCRYPTED) attrStr += L"Encrypted, ";
				if (!attrStr.empty()) attrStr = attrStr.substr(0, attrStr.length() - 2);
				else attrStr = L"Normal";
			} else {
				attrStr = L"Unable to retrieve";
			}
			
			AddStaticText(m_hEnvironmentTab, L"File Attributes:", 20, yPos, 150, 20);
			AddEditBox(m_hEnvironmentTab, attrStr.c_str(), 180, yPos, 550, 22, false, true);
			yPos += 35;
			
			WIN32_FILE_ATTRIBUTE_DATA fileData;
			if (GetFileAttributesExW(imagePath, GetFileExInfoStandard, &fileData)) {
				AddStaticText(m_hEnvironmentTab, L"File Size:", 20, yPos, 150, 20);
				ULONGLONG fileSize = (static_cast<ULONGLONG>(fileData.nFileSizeHigh) << 32) | fileData.nFileSizeLow;
				AddStaticText(m_hEnvironmentTab, FormatBytes(fileSize).c_str(), 180, yPos, 200, 20);
			}
		}
	}
}

void ProcessPropertiesDialog::RefreshNetworkTab() {
	if (!m_hNetworkTab) return;
	
	HWND hChild = GetWindow(m_hNetworkTab, GW_CHILD);
	while (hChild) {
		HWND hNext = GetWindow(hChild, GW_HWNDNEXT);
		DestroyWindow(hChild);
		hChild = hNext;
	}
	
	RECT rc;
	GetClientRect(m_hNetworkTab, &rc);
	
	HWND hListView = CreateWindowExW(
		WS_EX_CLIENTEDGE,
		WC_LISTVIEWW,
		L"",
		WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
		10, 10, rc.right - 20, rc.bottom - 20,
		m_hNetworkTab,
		reinterpret_cast<HMENU>(IDC_NETWORK_LIST),
		m_hInstance,
		nullptr
	);
	
	if (hListView) {
		ListView_SetExtendedListViewStyle(hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
		
		LVCOLUMNW lvc = {};
		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
		lvc.fmt = LVCFMT_LEFT;
		
		lvc.pszText = const_cast<LPWSTR>(L"Protocol");
		lvc.cx = 80;
		ListView_InsertColumn(hListView, 0, &lvc);
		
		lvc.pszText = const_cast<LPWSTR>(L"Local Address");
		lvc.cx = 150;
		ListView_InsertColumn(hListView, 1, &lvc);
		
		lvc.pszText = const_cast<LPWSTR>(L"Local Port");
		lvc.cx = 80;
		ListView_InsertColumn(hListView, 2, &lvc);
		
		lvc.pszText = const_cast<LPWSTR>(L"Remote Address");
		lvc.cx = 150;
		ListView_InsertColumn(hListView, 3, &lvc);
		
		lvc.pszText = const_cast<LPWSTR>(L"Remote Port");
		lvc.cx = 80;
		ListView_InsertColumn(hListView, 4, &lvc);
		
		lvc.pszText = const_cast<LPWSTR>(L"State");
		lvc.cx = 120;
		ListView_InsertColumn(hListView, 5, &lvc);
		
		NetworkManager netMgr;
		auto connections = netMgr.GetConnectionsForProcess(m_ProcessId);
		
		for (size_t i = 0; i < connections.size(); ++i) {
			const auto& conn = connections[i];
			
			LVITEMW lvi = {};
			lvi.mask = LVIF_TEXT;
			lvi.iItem = static_cast<int>(i);
			
			std::wstring protocol = NetworkManager::GetProtocolString(conn.Protocol);
			lvi.pszText = const_cast<LPWSTR>(protocol.c_str());
			ListView_InsertItem(hListView, &lvi);
			
			ListView_SetItemText(hListView, i, 1, const_cast<LPWSTR>(conn.LocalAddress.c_str()));
			ListView_SetItemText(hListView, i, 2, const_cast<LPWSTR>(std::to_wstring(conn.LocalPort).c_str()));
			ListView_SetItemText(hListView, i, 3, const_cast<LPWSTR>(conn.RemoteAddress.c_str()));
			ListView_SetItemText(hListView, i, 4, const_cast<LPWSTR>(std::to_wstring(conn.RemotePort).c_str()));
			
			std::wstring state = NetworkManager::GetStateString(conn.State);
			ListView_SetItemText(hListView, i, 5, const_cast<LPWSTR>(state.c_str()));
		}
		
		AddStaticText(m_hNetworkTab, (L"Total Connections: " + std::to_wstring(connections.size())).c_str(), 
			10, rc.bottom - 30, 300, 20);
	}
}

void ProcessPropertiesDialog::RefreshServicesTab() {
	if (!m_hServicesListView) return;

	ListView_DeleteAllItems(m_hServicesListView);
	auto services = m_ServiceManager.GetServicesForProcess(m_ProcessId);

	for (size_t i = 0; i < services.size(); ++i) {
		const auto& service = services[i];

		LVITEMW lvi = {};
		lvi.mask = LVIF_TEXT;
		lvi.iItem = static_cast<int>(i);
		lvi.pszText = const_cast<LPWSTR>(service.Name.c_str());
		ListView_InsertItem(m_hServicesListView, &lvi);

		ListView_SetItemText(m_hServicesListView, i, 1, const_cast<LPWSTR>(service.DisplayName.c_str()));
		
		std::wstring stateStr = ServiceManager::GetStateString(service.State);
		ListView_SetItemText(m_hServicesListView, i, 2, const_cast<LPWSTR>(stateStr.c_str()));
		
		std::wstring typeStr = ServiceManager::GetTypeString(service.Type);
		ListView_SetItemText(m_hServicesListView, i, 3, const_cast<LPWSTR>(typeStr.c_str()));
		
		std::wstring descStr = service.Description.empty() ? L"N/A" : service.Description;
		ListView_SetItemText(m_hServicesListView, i, 4, const_cast<LPWSTR>(descStr.c_str()));
	}
}

void ProcessPropertiesDialog::OnSearchOnline() {
	if (m_ProcessId == 0) return;
	
	std::wstring processName(m_ProcessInfo.ProcessName.begin(), m_ProcessInfo.ProcessName.end());
	
	std::wstring encoded;
	for (wchar_t c : processName) {
		if ((c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') || c == L'.' || c == L'-' || c == L'_') {
			encoded += c;
		} else if (c == L' ') {
			encoded += L"+";
		} else {
			wchar_t buf[4];
			swprintf_s(buf, L"%%%02X", static_cast<unsigned int>(c));
			encoded += buf;
		}
	}
	
	std::wstring query = L"https://www.google.com/search?q=" + encoded + L"+process";
	ShellExecuteW(nullptr, L"open", query.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void ProcessPropertiesDialog::AddStaticText(HWND hParent, const wchar_t* text, int x, int y, int width, int height, bool bold) {
	HWND hStatic = CreateWindowW(
		L"STATIC",
		text,
		WS_VISIBLE | WS_CHILD | SS_LEFT,
		x, y, width, height,
		hParent,
		nullptr,
		m_hInstance,
		nullptr
	);
	
	if (hStatic && bold && m_hBoldFont) {
		SendMessage(hStatic, WM_SETFONT, reinterpret_cast<WPARAM>(m_hBoldFont), TRUE);
	} else if (hStatic && m_hNormalFont) {
		SendMessage(hStatic, WM_SETFONT, reinterpret_cast<WPARAM>(m_hNormalFont), TRUE);
	}
}

void ProcessPropertiesDialog::AddEditBox(HWND hParent, const wchar_t* text, int x, int y, int width, int height, bool multiline, bool readonly) {
	DWORD style = WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL;
	if (multiline) {
		style |= ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL;
	}
	if (readonly) {
		style |= ES_READONLY;
	}
	
	HWND hEdit = CreateWindowW(
		L"EDIT",
		text,
		style,
		x, y, width, height,
		hParent,
		nullptr,
		m_hInstance,
		nullptr
	);
	
	if (hEdit && m_hNormalFont) {
		SendMessage(hEdit, WM_SETFONT, reinterpret_cast<WPARAM>(m_hNormalFont), TRUE);
	}
}

std::wstring ProcessPropertiesDialog::FormatFileTime(const FILETIME& ft) {
	if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) {
		return L"N/A";
	}
	
	FILETIME localFt;
	FileTimeToLocalFileTime(&ft, &localFt);
	
	SYSTEMTIME st;
	FileTimeToSystemTime(&localFt, &st);
	
	std::wostringstream oss;
	oss << std::setfill(L'0')
		<< st.wYear << L"-"
		<< std::setw(2) << st.wMonth << L"-"
		<< std::setw(2) << st.wDay << L" "
		<< std::setw(2) << st.wHour << L":"
		<< std::setw(2) << st.wMinute << L":"
		<< std::setw(2) << st.wSecond;
	
	return oss.str();
}

std::wstring ProcessPropertiesDialog::FormatBytes(ULONGLONG bytes) {
	const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB", L"TB" };
	int unitIndex = 0;
	double size = static_cast<double>(bytes);
	
	while (size >= 1024.0 && unitIndex < 4) {
		size /= 1024.0;
		unitIndex++;
	}
	
	std::wostringstream oss;
	oss << std::fixed << std::setprecision(2) << size << L" " << units[unitIndex];
	return oss.str();
}

std::wstring ProcessPropertiesDialog::FormatNumber(ULONGLONG number) {
	std::wstring numStr = std::to_wstring(number);
	std::wstring result;
	
	int count = 0;
	for (auto it = numStr.rbegin(); it != numStr.rend(); ++it) {
		if (count > 0 && count % 3 == 0) {
			result = L',' + result;
		}
		result = *it + result;
		count++;
	}
	
	return result;
}
