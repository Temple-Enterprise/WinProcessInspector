#include "MainWindow.h"
#include "ProcessPropertiesDialog.h"
#include "../core/ProcessManager.h"
#include "../core/SystemInfo.h"
#include "../core/NetworkManager.h"
#include "../utils/Logger.h"
#include "../security/SecurityManager.h"
#include "../injection/InjectionEngine.h"
#include "../../resource.h"
#include <commctrl.h>
#include <shellapi.h>
#include <commdlg.h>
#include <winsvc.h>
#include <sddl.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <chrono>
#include <functional>
#include <unordered_set>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "version.lib")

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "advapi32.lib")

using namespace WinProcessInspector::GUI;
using namespace WinProcessInspector::Core;
using namespace WinProcessInspector::Utils;
using namespace WinProcessInspector::Security;

enum ProcessListColumns {
	COL_NAME = 0,
	COL_PID,
	COL_PPID,
	COL_CPU,
	COL_MEMORY,
	COL_SESSION,
	COL_INTEGRITY,
	COL_USER,
	COL_ARCHITECTURE,
	COL_DESCRIPTION,
	COL_IMAGEPATH,
	COL_COMMANDLINE,
	COL_COMPANY,
	COL_COUNT
};


MainWindow::MainWindow(HINSTANCE hInstance)
	: m_hWnd(nullptr)
	, m_hInstance(hInstance)
	, m_hProcessListView(nullptr)
	, m_hStatusBar(nullptr)
	, m_hToolbar(nullptr)
	, m_hSearchFilter(nullptr)
	, m_hSearchIcon(nullptr)
	, m_hSearchLabel(nullptr)
	, m_hMenu(nullptr)
	, m_hContextMenu(nullptr)
	, m_hAccel(nullptr)
	, m_SelectedProcessId(0)
	, m_SortColumn(COL_NAME)
	, m_SortAscending(true)
	, m_AutoRefresh(false)
	, m_ToolbarVisible(true)
	, m_SearchBarVisible(true)
	, m_TreeViewEnabled(false)
	, m_RefreshTimerId(0)
	, m_IsRefreshing(false)
	, m_LastRefreshTime(0)
	, m_LastCpuUpdateTime(0)
	, m_hProcessIconList(nullptr)
	, m_DefaultIconIndex(-1)
	, m_ColumnVisible(COL_COUNT, true)
	, m_TotalSystemMemory(0)
	, m_CurrentProcessId(GetCurrentProcessId())
{
	m_ColumnVisible[COL_PPID] = false;
	m_ColumnVisible[COL_SESSION] = false;
	m_ColumnVisible[COL_DESCRIPTION] = true;
	m_ColumnVisible[COL_IMAGEPATH] = false;
	m_ColumnVisible[COL_COMMANDLINE] = false;
	m_ColumnVisible[COL_COMPANY] = true;
	
	MEMORYSTATUSEX memStatus = {};
	memStatus.dwLength = sizeof(memStatus);
	if (GlobalMemoryStatusEx(&memStatus)) {
		m_TotalSystemMemory = memStatus.ullTotalPhys;
	}
	
	Logger::GetInstance().LogInfo("WinProcessInspector initialized with Phase 2 features");
	Logger::GetInstance().LogInfo("Features: Command-line, Network, I/O, Security mitigations, File hashing");
}

MainWindow::~MainWindow() {
	Cleanup();
}

bool MainWindow::Initialize() {
	INITCOMMONCONTROLSEX icc = {};
	icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_BAR_CLASSES;
	if (!InitCommonControlsEx(&icc)) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to initialize common controls. Error: " << error;
		MessageBoxW(nullptr, oss.str().c_str(), L"Initialization Error", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Failed to initialize common controls. Error: " + std::to_string(error));
		return false;
	}

	if (!CreateMainWindow()) {
		return false;
	}

	if (!CreateMenuBar()) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create menu bar. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
		Logger::GetInstance().LogWarning("Failed to create menu bar. Error: " + std::to_string(error));
	}

	if (!CreateToolbar()) {
		Logger::GetInstance().LogWarning("Failed to create toolbar. Continuing without toolbar.");
	}

	if (!CreateSearchFilter()) {
		Logger::GetInstance().LogWarning("Failed to create search filter. Continuing without filter.");
	}

	if (!CreateProcessListView()) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create process list view. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Error", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Failed to create process list view. Error: " + std::to_string(error));
		return false;
	}

	if (!CreateStatusBar()) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create status bar. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
		Logger::GetInstance().LogWarning("Failed to create status bar. Error: " + std::to_string(error));
	}

	ACCEL accels[3] = {};
	accels[0].fVirt = FVIRTKEY | FNOINVERT;
	accels[0].key = VK_F5;
	accels[0].cmd = IDM_FILE_REFRESH;
	
	accels[1].fVirt = FVIRTKEY | FCONTROL | FNOINVERT;
	accels[1].key = 'F';
	accels[1].cmd = IDC_SEARCH_FILTER;
	
	accels[2].fVirt = FVIRTKEY | FNOINVERT;
	accels[2].key = VK_RETURN;
	accels[2].cmd = IDM_CONTEXT_PROPERTIES;
	
	m_hAccel = CreateAcceleratorTable(accels, 3);
	if (!m_hAccel) {
		Logger::GetInstance().LogWarning("Failed to create accelerator table");
	}

	RECT rc;
	GetClientRect(m_hWnd, &rc);
	SendMessage(m_hWnd, WM_SIZE, SIZE_RESTORED, MAKELPARAM(rc.right, rc.bottom));

	m_FilteredProcesses = m_Processes;

	RefreshProcessList();
	Logger::GetInstance().LogInfo("Application initialized successfully");
	return true;
}

int MainWindow::Run() {
	MSG msg = {};
	while (GetMessage(&msg, nullptr, 0, 0) > 0) {
		if (m_hAccel && TranslateAccelerator(m_hWnd, m_hAccel, &msg)) {
			continue;
		}
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return static_cast<int>(msg.wParam);
}

bool MainWindow::CreateMainWindow() {
	if (!m_hInstance) {
		MessageBoxW(nullptr, L"Invalid hInstance (NULL)", L"Initialization Error", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Invalid hInstance (NULL)");
		return false;
	}

	WNDCLASSEXW wc = {};
	wc.cbSize = sizeof(WNDCLASSEXW);
	wc.style = CS_HREDRAW | CS_VREDRAW;
	wc.lpfnWndProc = WindowProc;
	wc.hInstance = m_hInstance;
	wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
	wc.lpszClassName = L"WinProcessInspectorMainWindow";
	
	wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
	if (!wc.hCursor) {
		DWORD error = GetLastError();
		Logger::GetInstance().LogWarning("Failed to load cursor. Error: " + std::to_string(error) + ". Using default.");
		wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
	}
	
	HICON hIcon = static_cast<HICON>(LoadImage(m_hInstance, MAKEINTRESOURCE(IDI_APP_ICON), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE));
	if (!hIcon) {
		DWORD error = GetLastError();
		Logger::GetInstance().LogWarning("Failed to load main icon (IDI_APP_ICON). Error: " + std::to_string(error) + ". Using default icon.");
		hIcon = LoadIcon(nullptr, IDI_APPLICATION);
	}
	
	HICON hIconSm = static_cast<HICON>(LoadImage(m_hInstance, MAKEINTRESOURCE(IDI_APP_ICON), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0));
	if (!hIconSm) {
		DWORD error = GetLastError();
		Logger::GetInstance().LogWarning("Failed to load small icon (IDI_APP_ICON). Error: " + std::to_string(error) + ". Using default icon.");
		hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
	}
	wc.hIcon = hIcon;
	wc.hIconSm = hIconSm;

	UnregisterClassW(L"WinProcessInspectorMainWindow", m_hInstance);
	SetLastError(0);

	ATOM classAtom = RegisterClassExW(&wc);
	if (classAtom == 0) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to register window class. Error: " << error << L" (0x" << std::hex << error << L")";
		oss << L"\n\nhInstance: 0x" << std::hex << reinterpret_cast<ULONG_PTR>(m_hInstance);
		oss << L"\nClass name: WinProcessInspectorMainWindow";
		MessageBoxW(nullptr, oss.str().c_str(), L"Initialization Error", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Failed to register window class. Error: " + std::to_string(error));
		return false;
	}

	WNDCLASSEXW verifyClass = {};
	verifyClass.cbSize = sizeof(WNDCLASSEXW);
	if (!GetClassInfoExW(m_hInstance, L"WinProcessInspectorMainWindow", &verifyClass)) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Window class not found before window creation. Error: " << error << L" (0x" << std::hex << error << L")";
		oss << L"\n\nhInstance: 0x" << std::hex << reinterpret_cast<ULONG_PTR>(m_hInstance);
		oss << L"\nClass registration returned: " << classAtom;
		MessageBoxW(nullptr, oss.str().c_str(), L"Initialization Error", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Window class not found before window creation. Error: " + std::to_string(error));
		return false;
	}

	SetLastError(0);
	m_hWnd = CreateWindowExW(
		0,
		L"WinProcessInspectorMainWindow",
		L"WinProcessInspector",
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT,
		1200, 800,
		nullptr,
		nullptr,
		m_hInstance,
		this
	);
	
	if (m_hWnd) {
		SetWindowTextW(m_hWnd, L"WinProcessInspector");
	}

	if (!m_hWnd) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create main window. Error: " << error << L" (0x" << std::hex << error << L")";
		oss << L"\n\nhInstance: 0x" << std::hex << reinterpret_cast<ULONG_PTR>(m_hInstance);
		oss << L"\nWindow class: WinProcessInspectorMainWindow";
		oss << L"\nClass registered: " << (classAtom != 0 ? L"Yes" : L"No");
		oss << L"\nWindowProc: 0x" << std::hex << reinterpret_cast<ULONG_PTR>(WindowProc);
		MessageBoxW(nullptr, oss.str().c_str(), L"Initialization Error", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Failed to create main window. Error: " + std::to_string(error));
		return false;
	}

	if (!IsWindow(m_hWnd)) {
		std::wostringstream oss;
		oss << L"Created window handle is invalid. Handle: 0x" << std::hex << reinterpret_cast<ULONG_PTR>(m_hWnd);
		MessageBoxW(nullptr, oss.str().c_str(), L"Initialization Error", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Created window handle is invalid");
		m_hWnd = nullptr;
		return false;
	}

	ShowWindow(m_hWnd, SW_SHOWNORMAL);
	UpdateWindow(m_hWnd);
	
	SendMessage(m_hWnd, WM_SIZE, SIZE_RESTORED, MAKELPARAM(1200, 800));
	
	return true;
}

bool MainWindow::CreateMenuBar() {
	if (!m_hWnd || !IsWindow(m_hWnd)) {
		MessageBoxW(nullptr, L"Invalid window handle when creating menu bar", L"Initialization Error", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Invalid window handle when creating menu bar");
		return false;
	}

	m_hMenu = CreateMenu();
	if (!m_hMenu) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create main menu. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
		Logger::GetInstance().LogWarning("Failed to create main menu. Error: " + std::to_string(error));
		return false;
	}

	HMENU hFileMenu = CreatePopupMenu();
	if (!hFileMenu) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create File menu. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
		Logger::GetInstance().LogWarning("Failed to create File menu. Error: " + std::to_string(error));
		return false;
	}
	AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_REFRESH, L"&Refresh\tF5");
	AppendMenuW(hFileMenu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_EXPORT, L"&Export Process List (CSV)...");
	AppendMenuW(hFileMenu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_EXIT, L"E&xit");

	HMENU hProcessMenu = CreatePopupMenu();
	if (!hProcessMenu) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create Process menu. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
		Logger::GetInstance().LogWarning("Failed to create Process menu. Error: " + std::to_string(error));
		return false;
	}
	AppendMenuW(hProcessMenu, MF_STRING | MF_GRAYED, IDM_PROCESS_PROPERTIES, L"&Properties");
	AppendMenuW(hProcessMenu, MF_STRING | MF_GRAYED, IDM_PROCESS_FILE_LOCATION, L"Open File &Location");
	AppendMenuW(hProcessMenu, MF_STRING | MF_GRAYED, IDM_PROCESS_SEARCH_ONLINE, L"Search &Online");
	AppendMenuW(hProcessMenu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW(hProcessMenu, MF_STRING | MF_GRAYED, IDM_PROCESS_INJECT_DLL, L"Inject &DLL...");
	AppendMenuW(hProcessMenu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW(hProcessMenu, MF_STRING | MF_GRAYED, IDM_PROCESS_SUSPEND, L"&Suspend");
	AppendMenuW(hProcessMenu, MF_STRING | MF_GRAYED, IDM_PROCESS_RESUME, L"&Resume");
	AppendMenuW(hProcessMenu, MF_STRING | MF_GRAYED, IDM_PROCESS_TERMINATE, L"&Terminate");

	HMENU hViewMenu = CreatePopupMenu();
	if (!hViewMenu) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create View menu. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
		Logger::GetInstance().LogWarning("Failed to create View menu. Error: " + std::to_string(error));
		return false;
	}
	AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_TREEVIEW, L"&Tree View");
	AppendMenuW(hViewMenu, MF_STRING | MF_CHECKED, IDM_VIEW_TOOLBAR, L"&Toolbar");
	AppendMenuW(hViewMenu, MF_STRING | MF_CHECKED, IDM_VIEW_SEARCHBAR, L"&Search Bar");
	AppendMenuW(hViewMenu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_AUTOREFRESH, L"&Auto Refresh");
	AppendMenuW(hViewMenu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_NETWORK, L"&Network Connections...");
	AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_SYSTEM_INFO, L"&System Information...");
	AppendMenuW(hViewMenu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_COLUMNS, L"C&olumns...");

	HMENU hHelpMenu = CreatePopupMenu();
	if (!hHelpMenu) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create Help menu. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
		Logger::GetInstance().LogWarning("Failed to create Help menu. Error: " + std::to_string(error));
		return false;
	}
	AppendMenuW(hHelpMenu, MF_STRING, IDM_HELP_ABOUT, L"&About WinProcessInspector");
	AppendMenuW(hHelpMenu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW(hHelpMenu, MF_STRING, IDM_HELP_GITHUB, L"&GitHub Repository");

	AppendMenuW(m_hMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(hFileMenu), L"&File");
	AppendMenuW(m_hMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(hProcessMenu), L"&Process");
	AppendMenuW(m_hMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(hViewMenu), L"&View");
	AppendMenuW(m_hMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(hHelpMenu), L"&Help");

	if (m_hWnd && IsWindow(m_hWnd)) {
		if (!SetMenu(m_hWnd, m_hMenu)) {
			DWORD error = GetLastError();
			std::wostringstream oss;
			oss << L"Failed to set menu on window. Error: " << error << L" (0x" << std::hex << error << L")";
			MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
			Logger::GetInstance().LogWarning("Failed to set menu on window. Error: " + std::to_string(error));
		}
	} else {
		MessageBoxW(nullptr, L"Window handle is invalid when setting menu", L"Initialization Error", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Window handle is invalid when setting menu");
		return false;
	}

	m_hContextMenu = CreatePopupMenu();
	if (!m_hContextMenu) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create context menu. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
		Logger::GetInstance().LogWarning("Failed to create context menu. Error: " + std::to_string(error));
	} else {
		AppendMenuW(m_hContextMenu, MF_STRING, IDM_CONTEXT_PROPERTIES, L"&Properties");
		AppendMenuW(m_hContextMenu, MF_STRING, IDM_CONTEXT_VIEW_COMMANDLINE, L"View &Command Line");
		AppendMenuW(m_hContextMenu, MF_SEPARATOR, 0, nullptr);
		AppendMenuW(m_hContextMenu, MF_STRING, IDM_CONTEXT_FILELOCATION, L"Open File &Location");
		AppendMenuW(m_hContextMenu, MF_SEPARATOR, 0, nullptr);
		AppendMenuW(m_hContextMenu, MF_STRING, IDM_CONTEXT_INJECT_DLL, L"Inject &DLL...");
		AppendMenuW(m_hContextMenu, MF_SEPARATOR, 0, nullptr);
		AppendMenuW(m_hContextMenu, MF_STRING, IDM_CONTEXT_SUSPEND, L"&Suspend Process");
		AppendMenuW(m_hContextMenu, MF_STRING, IDM_CONTEXT_RESUME, L"&Resume Process");
		AppendMenuW(m_hContextMenu, MF_STRING, IDM_CONTEXT_TERMINATE, L"&Terminate Process");
		AppendMenuW(m_hContextMenu, MF_SEPARATOR, 0, nullptr);
		AppendMenuW(m_hContextMenu, MF_STRING, IDM_CONTEXT_COPY_PID, L"Copy &PID");
		AppendMenuW(m_hContextMenu, MF_STRING, IDM_CONTEXT_COPY_NAME, L"Copy &Name");
		AppendMenuW(m_hContextMenu, MF_SEPARATOR, 0, nullptr);
		AppendMenuW(m_hContextMenu, MF_STRING, IDM_CONTEXT_SEARCH_ONLINE, L"Search &Online");
	}

	return true;
}

bool MainWindow::CreateProcessListView() {
	RECT rc;
	GetClientRect(m_hWnd, &rc);
	
	m_hProcessListView = CreateWindowExW(
		WS_EX_CLIENTEDGE,
		WC_LISTVIEWW,
		L"",
		WS_VISIBLE | WS_CHILD | WS_BORDER | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
		0, 0,
		rc.right - rc.left,
		rc.bottom - rc.top,
		m_hWnd,
		reinterpret_cast<HMENU>(IDC_PROCESS_LIST),
		m_hInstance,
		nullptr
	);

	if (!m_hProcessListView) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create process ListView control. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Error", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Failed to create process ListView control. Error: " + std::to_string(error));
		return false;
	}

	ListView_SetExtendedListViewStyle(m_hProcessListView, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

	int iconSize = GetSystemMetrics(SM_CXSMICON);
	m_hProcessIconList = ImageList_Create(iconSize, iconSize, ILC_COLOR32 | ILC_MASK, 1, 100);
	if (m_hProcessIconList) {
		SHFILEINFOW sfi = {};
		SHGetFileInfoW(L".exe", FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES);
		if (sfi.hIcon) {
			m_DefaultIconIndex = ImageList_AddIcon(m_hProcessIconList, sfi.hIcon);
			DestroyIcon(sfi.hIcon);
		}
		ListView_SetImageList(m_hProcessListView, m_hProcessIconList, LVSIL_SMALL);
	}

	LVCOLUMNW lvc = {};
	lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvc.fmt = LVCFMT_LEFT;

	lvc.iSubItem = COL_NAME;
	lvc.pszText = const_cast<LPWSTR>(L"Name");
	lvc.cx = 280;
	ListView_InsertColumn(m_hProcessListView, COL_NAME, &lvc);

	lvc.iSubItem = COL_PID;
	lvc.pszText = const_cast<LPWSTR>(L"PID");
	lvc.cx = 90;
	ListView_InsertColumn(m_hProcessListView, COL_PID, &lvc);

	lvc.iSubItem = COL_PPID;
	lvc.pszText = const_cast<LPWSTR>(L"PPID");
	lvc.cx = 90;
	ListView_InsertColumn(m_hProcessListView, COL_PPID, &lvc);

	lvc.iSubItem = COL_CPU;
	lvc.pszText = const_cast<LPWSTR>(L"CPU");
	lvc.cx = 90;
	lvc.fmt = LVCFMT_RIGHT;
	ListView_InsertColumn(m_hProcessListView, COL_CPU, &lvc);
	lvc.fmt = LVCFMT_LEFT;

	lvc.iSubItem = COL_MEMORY;
	lvc.pszText = const_cast<LPWSTR>(L"Memory");
	lvc.cx = 120;
	lvc.fmt = LVCFMT_RIGHT;
	ListView_InsertColumn(m_hProcessListView, COL_MEMORY, &lvc);
	lvc.fmt = LVCFMT_LEFT;

	lvc.iSubItem = COL_USER;
	lvc.pszText = const_cast<LPWSTR>(L"User");
	lvc.cx = 180;
	ListView_InsertColumn(m_hProcessListView, COL_USER, &lvc);

	lvc.iSubItem = COL_INTEGRITY;
	lvc.pszText = const_cast<LPWSTR>(L"Integrity");
	lvc.cx = 120;
	ListView_InsertColumn(m_hProcessListView, COL_INTEGRITY, &lvc);

	lvc.iSubItem = COL_ARCHITECTURE;
	lvc.pszText = const_cast<LPWSTR>(L"Architecture");
	lvc.cx = 120;
	ListView_InsertColumn(m_hProcessListView, COL_ARCHITECTURE, &lvc);

	lvc.iSubItem = COL_SESSION;
	lvc.pszText = const_cast<LPWSTR>(L"Session");
	lvc.cx = 70;
	ListView_InsertColumn(m_hProcessListView, COL_SESSION, &lvc);

	lvc.iSubItem = COL_DESCRIPTION;
	lvc.pszText = const_cast<LPWSTR>(L"Description");
	lvc.cx = 180;
	ListView_InsertColumn(m_hProcessListView, COL_DESCRIPTION, &lvc);

	lvc.iSubItem = COL_IMAGEPATH;
	lvc.pszText = const_cast<LPWSTR>(L"Image Path");
	lvc.cx = 250;
	ListView_InsertColumn(m_hProcessListView, COL_IMAGEPATH, &lvc);

	lvc.iSubItem = COL_COMMANDLINE;
	lvc.pszText = const_cast<LPWSTR>(L"Command Line");
	lvc.cx = 300;
	ListView_InsertColumn(m_hProcessListView, COL_COMMANDLINE, &lvc);

	lvc.iSubItem = COL_COMPANY;
	lvc.pszText = const_cast<LPWSTR>(L"Company");
	lvc.cx = 150;
	ListView_InsertColumn(m_hProcessListView, COL_COMPANY, &lvc);

	for (int i = 0; i < COL_COUNT; ++i) {
		if (!m_ColumnVisible[i]) {
			ListView_SetColumnWidth(m_hProcessListView, i, 0);
		}
	}

	return true;
}

bool MainWindow::CreateStatusBar() {
	m_hStatusBar = CreateWindowExW(
		0,
		STATUSCLASSNAMEW,
		L"Ready",
		WS_VISIBLE | WS_CHILD | SBARS_SIZEGRIP,
		0, 0, 0, 0,
		m_hWnd,
		nullptr,
		m_hInstance,
		nullptr
	);

	if (!m_hStatusBar) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create status bar. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
		Logger::GetInstance().LogWarning("Failed to create status bar. Error: " + std::to_string(error));
		return false;
	}

	return true;
}

bool MainWindow::CreateToolbar() {
	m_hToolbar = CreateWindowExW(
		0,
		TOOLBARCLASSNAMEW,
		L"",
		WS_VISIBLE | WS_CHILD | TBSTYLE_FLAT | TBSTYLE_TOOLTIPS | CCS_TOP | CCS_NODIVIDER | CCS_NORESIZE,
		0, 0, 0, 0,
		m_hWnd,
		reinterpret_cast<HMENU>(IDC_TOOLBAR),
		m_hInstance,
		nullptr
	);

	if (!m_hToolbar) {
		return false;
	}

	SendMessage(m_hToolbar, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);

	HIMAGELIST hImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 3, 0);
	if (hImageList) {
		HICON hIconRefresh = static_cast<HICON>(LoadImage(m_hInstance, MAKEINTRESOURCE(IDI_REFRESH), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
		HICON hIconProperties = static_cast<HICON>(LoadImage(m_hInstance, MAKEINTRESOURCE(IDI_PROPERTIES), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
		HICON hIconSearch = static_cast<HICON>(LoadImage(m_hInstance, MAKEINTRESOURCE(IDI_SEARCH), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
		
		if (!hIconRefresh) hIconRefresh = LoadIcon(nullptr, IDI_APPLICATION);
		if (!hIconProperties) hIconProperties = LoadIcon(nullptr, IDI_APPLICATION);
		if (!hIconSearch) hIconSearch = LoadIcon(nullptr, IDI_APPLICATION);
		
		ImageList_AddIcon(hImageList, hIconRefresh);
		ImageList_AddIcon(hImageList, hIconProperties);
		ImageList_AddIcon(hImageList, hIconSearch);
		
		SendMessage(m_hToolbar, TB_SETIMAGELIST, 0, reinterpret_cast<LPARAM>(hImageList));
	}

	TBBUTTON buttons[3] = {};
	
	buttons[0].iBitmap = 0;
	buttons[0].idCommand = IDM_FILE_REFRESH;
	buttons[0].fsState = TBSTATE_ENABLED;
	buttons[0].fsStyle = BTNS_BUTTON;
	buttons[0].dwData = 0;
	buttons[0].iString = 0;

	buttons[1].iBitmap = 1;
	buttons[1].idCommand = IDM_CONTEXT_PROPERTIES;
	buttons[1].fsState = TBSTATE_ENABLED;
	buttons[1].fsStyle = BTNS_BUTTON;
	buttons[1].dwData = 0;
	buttons[1].iString = 0;

	buttons[2].iBitmap = 2;
	buttons[2].idCommand = IDC_SEARCH_FILTER;
	buttons[2].fsState = TBSTATE_ENABLED;
	buttons[2].fsStyle = BTNS_BUTTON;
	buttons[2].dwData = 0;
	buttons[2].iString = 0;

	SendMessage(m_hToolbar, TB_ADDBUTTONS, 3, reinterpret_cast<LPARAM>(buttons));
	SendMessage(m_hToolbar, TB_AUTOSIZE, 0, 0);

	return true;
}

bool MainWindow::CreateSearchFilter() {
	m_hSearchIcon = CreateWindowExW(
		0,
		L"STATIC",
		L"",
		WS_VISIBLE | WS_CHILD | SS_ICON,
		5, 2, 16, 16,
		m_hWnd,
		nullptr,
		m_hInstance,
		nullptr
	);
	
	if (m_hSearchIcon) {
		HICON hIcon = static_cast<HICON>(LoadImage(m_hInstance, MAKEINTRESOURCE(IDI_SEARCH), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
		if (hIcon) {
			SendMessage(m_hSearchIcon, STM_SETICON, reinterpret_cast<WPARAM>(hIcon), 0);
		}
	}

	m_hSearchLabel = CreateWindowExW(
		0,
		L"STATIC",
		L"Filter:",
		WS_VISIBLE | WS_CHILD | SS_LEFT,
		25, 2, 40, 18,
		m_hWnd,
		nullptr,
		m_hInstance,
		nullptr
	);

	m_hSearchFilter = CreateWindowExW(
		WS_EX_CLIENTEDGE,
		L"EDIT",
		L"",
		WS_VISIBLE | WS_CHILD | ES_LEFT | ES_AUTOHSCROLL,
		70, 0, 200, 22,
		m_hWnd,
		reinterpret_cast<HMENU>(IDC_SEARCH_FILTER),
		m_hInstance,
		nullptr
	);

	if (!m_hSearchFilter) {
		return false;
	}
	
	HFONT hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
		CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
	if (hFont) {
		SendMessageW(m_hSearchFilter, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);
	}

	SendMessage(m_hSearchFilter, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"Search..."));

	return true;
}

void MainWindow::Cleanup() {
	if (m_RefreshTimerId) {
		KillTimer(m_hWnd, m_RefreshTimerId);
		m_RefreshTimerId = 0;
	}

	if (m_hProcessIconList) {
		ImageList_Destroy(m_hProcessIconList);
		m_hProcessIconList = nullptr;
		m_IconCache.clear();
	}

	if (m_hAccel) {
		DestroyAcceleratorTable(m_hAccel);
		m_hAccel = nullptr;
	}

	if (m_hContextMenu) {
		DestroyMenu(m_hContextMenu);
		m_hContextMenu = nullptr;
	}

	if (m_hMenu) {
		DestroyMenu(m_hMenu);
		m_hMenu = nullptr;
	}

	m_PropertiesDialog.reset();
}

LRESULT CALLBACK MainWindow::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	MainWindow* pThis = nullptr;

	if (uMsg == WM_NCCREATE) {
		CREATESTRUCT* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
		if (pCreate && pCreate->lpCreateParams) {
			pThis = reinterpret_cast<MainWindow*>(pCreate->lpCreateParams);
			SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
			return TRUE;
		}
		return FALSE;
	} else {
		pThis = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
	}

	if (pThis) {
		return pThis->HandleMessage(uMsg, wParam, lParam);
	}

	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT MainWindow::OnCreate() {
	PostMessage(m_hWnd, WM_SIZE, SIZE_RESTORED, 0);
	return 0;
}

LRESULT MainWindow::OnDestroy() {
	PostQuitMessage(0);
	return 0;
}

LRESULT MainWindow::OnSize() {
	if (!m_hWnd) {
		return 0;
	}

	RECT rc;
	GetClientRect(m_hWnd, &rc);
	int yPos = 0;

	int toolbarHeight = 0;
	if (m_hToolbar && IsWindow(m_hToolbar) && m_ToolbarVisible) {
		SendMessage(m_hToolbar, WM_SIZE, 0, 0);
		RECT rcToolbar;
		if (GetWindowRect(m_hToolbar, &rcToolbar)) {
			toolbarHeight = rcToolbar.bottom - rcToolbar.top;
			yPos += toolbarHeight;
		}
	}

	int searchHeight = 22;
	if (m_hSearchFilter && IsWindow(m_hSearchFilter) && m_SearchBarVisible) {
		RECT rcSearch;
		if (GetWindowRect(m_hSearchFilter, &rcSearch)) {
			searchHeight = rcSearch.bottom - rcSearch.top;
		}
		SetWindowPos(m_hSearchFilter, nullptr, 0, yPos, 200, searchHeight, SWP_NOZORDER | SWP_NOACTIVATE);
		ShowWindow(m_hSearchFilter, SW_SHOW);
		if (m_hSearchIcon && IsWindow(m_hSearchIcon)) {
			ShowWindow(m_hSearchIcon, SW_SHOW);
		}
		if (m_hSearchLabel && IsWindow(m_hSearchLabel)) {
			ShowWindow(m_hSearchLabel, SW_SHOW);
		}
		yPos += searchHeight;
	} else if (m_hSearchFilter && IsWindow(m_hSearchFilter)) {
		ShowWindow(m_hSearchFilter, SW_HIDE);
		if (m_hSearchIcon && IsWindow(m_hSearchIcon)) {
			ShowWindow(m_hSearchIcon, SW_HIDE);
		}
		if (m_hSearchLabel && IsWindow(m_hSearchLabel)) {
			ShowWindow(m_hSearchLabel, SW_HIDE);
		}
	}

	int statusBarHeight = 0;
	if (m_hStatusBar && IsWindow(m_hStatusBar)) {
		SendMessage(m_hStatusBar, WM_SIZE, 0, 0);
		
		RECT rcStatus;
		if (GetClientRect(m_hStatusBar, &rcStatus)) {
			statusBarHeight = rcStatus.bottom - rcStatus.top;
		} else {
			RECT rcStatusWindow;
			if (GetWindowRect(m_hStatusBar, &rcStatusWindow)) {
				statusBarHeight = rcStatusWindow.bottom - rcStatusWindow.top;
			}
		}
		rc.bottom -= statusBarHeight;
	}

	if (m_hProcessListView && IsWindow(m_hProcessListView)) {
		int width = rc.right - rc.left;
		int height = rc.bottom - rc.top - yPos;
		if (width > 0 && height > 0) {
			SetWindowPos(
				m_hProcessListView,
				nullptr,
				0, yPos,
				width,
				height,
				SWP_NOZORDER | SWP_NOACTIVATE
			);
			ShowWindow(m_hProcessListView, SW_SHOW);
			UpdateWindow(m_hProcessListView);
		}
	}

	return 0;
}

LRESULT MainWindow::OnCommand(WPARAM wParam, LPARAM lParam) {
	WORD id = LOWORD(wParam);
	switch (id) {
		case IDM_FILE_REFRESH:
			OnFileRefresh();
			break;
		case IDM_FILE_EXPORT:
			OnFileExport();
			break;
		case IDM_FILE_EXIT:
			OnFileExit();
			break;
		case IDM_PROCESS_PROPERTIES:
			if (m_SelectedProcessId) {
				ShowProcessProperties(m_SelectedProcessId);
			} else {
				MessageBoxW(m_hWnd, L"Please select a process first.", L"Process", MB_OK | MB_ICONINFORMATION);
			}
			break;
		case IDM_PROCESS_SUSPEND:
			if (m_SelectedProcessId) {
				SuspendProcess(m_SelectedProcessId);
			} else {
				MessageBoxW(m_hWnd, L"Please select a process first.", L"Suspend Process", MB_OK | MB_ICONINFORMATION);
			}
			break;
		case IDM_PROCESS_RESUME:
			if (m_SelectedProcessId) {
				ResumeProcess(m_SelectedProcessId);
			} else {
				MessageBoxW(m_hWnd, L"Please select a process first.", L"Resume Process", MB_OK | MB_ICONINFORMATION);
			}
			break;
		case IDM_PROCESS_TERMINATE:
			if (m_SelectedProcessId) {
				TerminateProcess(m_SelectedProcessId);
			} else {
				MessageBoxW(m_hWnd, L"Please select a process first.", L"Terminate Process", MB_OK | MB_ICONINFORMATION);
			}
			break;
		case IDM_PROCESS_INJECT_DLL:
			if (m_SelectedProcessId) {
				InjectDll(m_SelectedProcessId);
			} else {
				MessageBoxW(m_hWnd, L"Please select a process first.", L"Inject DLL", MB_OK | MB_ICONINFORMATION);
			}
			break;
		case IDM_PROCESS_FILE_LOCATION:
			if (m_SelectedProcessId) {
				OpenProcessFileLocation(m_SelectedProcessId);
			} else {
				MessageBoxW(m_hWnd, L"Please select a process first.", L"Open File Location", MB_OK | MB_ICONINFORMATION);
			}
			break;
		case IDM_PROCESS_SEARCH_ONLINE:
			if (m_SelectedProcessId) {
				SearchProcessOnline(m_SelectedProcessId);
			} else {
				MessageBoxW(m_hWnd, L"Please select a process first.", L"Search Online", MB_OK | MB_ICONINFORMATION);
			}
			break;
		case IDM_VIEW_TREEVIEW:
			OnViewTreeView();
			break;
		case IDM_VIEW_TOOLBAR:
			OnViewToolbar();
			break;
		case IDM_VIEW_SEARCHBAR:
			OnViewSearchBar();
			break;
		case IDM_VIEW_AUTOREFRESH:
			OnViewAutoRefresh();
			break;
		case IDM_VIEW_COLUMNS:
			OnViewColumns();
			break;
		case IDM_VIEW_NETWORK:
			ShowNetworkConnectionsWindow();
			break;
		case IDM_VIEW_SYSTEM_INFO:
			ShowSystemInformationWindow();
			break;
		case IDM_HELP_ABOUT:
			OnHelpAbout();
			break;
		case IDM_HELP_GITHUB:
			OnHelpGitHub();
			break;
		case IDC_SEARCH_FILTER:
			if (HIWORD(wParam) == EN_CHANGE) {
				wchar_t buffer[256] = {};
				GetWindowTextW(m_hSearchFilter, buffer, 256);
				m_FilterText = buffer;
				UpdateProcessList();
			}
			break;
		case IDM_CONTEXT_PROPERTIES:
			if (m_SelectedProcessId) {
				ShowProcessProperties(m_SelectedProcessId);
			}
			break;
		case IDM_CONTEXT_TERMINATE:
			if (m_SelectedProcessId) {
				TerminateProcess(m_SelectedProcessId);
			}
			break;
		case IDM_CONTEXT_FILELOCATION:
			if (m_SelectedProcessId) {
				OpenProcessFileLocation(m_SelectedProcessId);
			}
			break;
		case IDM_CONTEXT_COPY_PID:
			if (m_SelectedProcessId) {
				CopyProcessId(m_SelectedProcessId);
			}
			break;
		case IDM_CONTEXT_COPY_NAME:
			if (m_SelectedProcessId) {
				CopyProcessName(m_SelectedProcessId);
			}
			break;
		case IDM_CONTEXT_INJECT_DLL:
			if (m_SelectedProcessId) {
				InjectDll(m_SelectedProcessId);
			}
			break;
		case IDM_CONTEXT_SUSPEND:
			if (m_SelectedProcessId) {
				SuspendProcess(m_SelectedProcessId);
			}
			break;
		case IDM_CONTEXT_RESUME:
			if (m_SelectedProcessId) {
				ResumeProcess(m_SelectedProcessId);
			}
			break;
		case IDM_CONTEXT_VIEW_COMMANDLINE:
			if (m_SelectedProcessId) {
				ShowCommandLineDialog(m_SelectedProcessId);
			}
			break;
		case IDM_CONTEXT_SEARCH_ONLINE:
			if (m_SelectedProcessId) {
				SearchProcessOnline(m_SelectedProcessId);
			}
			break;
		default:
			break;
	}
	return 0;
}

LRESULT MainWindow::OnNotify(WPARAM wParam, LPARAM lParam) {
	NMHDR* pnmh = reinterpret_cast<NMHDR*>(lParam);
	
	if (pnmh->idFrom == IDC_PROCESS_LIST) {
		if (pnmh->code == NM_CUSTOMDRAW) {
			return OnCustomDraw(reinterpret_cast<LPNMLVCUSTOMDRAW>(lParam));
		} else if (pnmh->code == LVN_BEGINLABELEDIT) {
			return TRUE;
		} else if (pnmh->code == NM_DBLCLK) {
			OnProcessListDoubleClick();
		} else if (pnmh->code == LVN_ITEMCHANGED) {
			OnProcessListSelectionChanged();
		} else if (pnmh->code == LVN_COLUMNCLICK) {
			NMLISTVIEW* pnmv = reinterpret_cast<NMLISTVIEW*>(lParam);
			SortProcessList(pnmv->iSubItem, m_SortColumn == pnmv->iSubItem ? !m_SortAscending : true);
		} else if (pnmh->code == NM_CLICK && m_TreeViewEnabled) {
			NMLISTVIEW* pnmv = reinterpret_cast<NMLISTVIEW*>(lParam);
			if (pnmv->iSubItem == COL_NAME) {
				LVITEMW lvi = {};
				lvi.iItem = pnmv->iItem;
				lvi.mask = LVIF_PARAM;
				ListView_GetItem(m_hProcessListView, &lvi);
				DWORD processId = static_cast<DWORD>(lvi.lParam);
				
				m_ExpandedProcesses[processId] = !m_ExpandedProcesses[processId];
				UpdateProcessList();
			}
		}
	} else if (pnmh->idFrom == IDC_TOOLBAR && pnmh->code == TTN_GETDISPINFO) {
		NMTTDISPINFOW* pttdi = reinterpret_cast<NMTTDISPINFOW*>(lParam);
		switch (pttdi->hdr.idFrom) {
			case IDM_FILE_REFRESH:
				pttdi->lpszText = const_cast<LPWSTR>(L"Refresh process list (F5)");
				break;
			case IDM_CONTEXT_PROPERTIES:
				pttdi->lpszText = const_cast<LPWSTR>(L"Show process properties");
				break;
			case IDC_SEARCH_FILTER:
				pttdi->lpszText = const_cast<LPWSTR>(L"Focus search filter (Ctrl+F)");
				break;
		}
		return 0;
	}

	return 0;
}

LRESULT MainWindow::OnContextMenu(WPARAM wParam, LPARAM lParam) {
	if (reinterpret_cast<HWND>(wParam) == m_hProcessListView) {
		ShowProcessContextMenu(LOWORD(lParam), HIWORD(lParam));
		return 0;
	}
	return DefWindowProc(m_hWnd, WM_CONTEXTMENU, wParam, lParam);
}

LRESULT MainWindow::OnTimer(WPARAM wParam) {
	if (wParam == IDT_REFRESH_TIMER) {
		RefreshProcessList();
		return 0;
	}
	return DefWindowProc(m_hWnd, WM_TIMER, wParam, 0);
}

void MainWindow::RefreshProcessList() {
	if (m_IsRefreshing) {
		return;
	}

	ULONGLONG currentTime = GetTickCount64();
	if (m_LastRefreshTime > 0 && (currentTime - m_LastRefreshTime) < 500) {
		return;
	}

	m_IsRefreshing = true;
	m_LastRefreshTime = currentTime;

	std::thread refreshThread([this]() {
		std::vector<ProcessInfo> processes = m_ProcessManager.EnumerateAllProcesses();
		
		PostMessage(m_hWnd, WM_USER + 1, 0, reinterpret_cast<LPARAM>(new std::vector<ProcessInfo>(std::move(processes))));
	});
	refreshThread.detach();
}

LRESULT MainWindow::HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
		case WM_CREATE:
			return OnCreate();
		case WM_DESTROY:
			return OnDestroy();
		case WM_SIZE:
			return OnSize();
		case WM_COMMAND:
			return OnCommand(wParam, lParam);
		case WM_NOTIFY:
			return OnNotify(wParam, lParam);
		case WM_CONTEXTMENU:
			return OnContextMenu(wParam, lParam);
		case WM_TIMER:
			return OnTimer(wParam);
		case WM_KEYDOWN:
			if (wParam == VK_ESCAPE && GetFocus() == m_hSearchFilter) {
				SetWindowTextW(m_hSearchFilter, L"");
				m_FilterText.clear();
				UpdateProcessList();
				return 0;
			}
			return DefWindowProc(m_hWnd, uMsg, wParam, lParam);
		case WM_USER + 1:
			{
				std::vector<ProcessInfo>* processes = reinterpret_cast<std::vector<ProcessInfo>*>(lParam);
				if (processes) {
					std::unordered_set<DWORD> oldPids;
					for (const auto& p : m_Processes) {
						oldPids.insert(p.ProcessId);
					}
					
					std::unordered_set<DWORD> newPids;
					for (const auto& p : *processes) {
						newPids.insert(p.ProcessId);
					}
					
					for (DWORD pid : oldPids) {
						if (newPids.find(pid) == newPids.end()) {
							m_SystemProcessCache.erase(pid);
							m_ProcessCpuTime.erase(pid);
							m_ProcessCpuPercent.erase(pid);
							m_ProcessMemory.erase(pid);
						}
					}
					
					m_Processes = std::move(*processes);
					delete processes;
					
					CalculateCpuUsage();
					UpdateMemoryUsage();
					UpdateProcessList();
					
					std::wostringstream oss;
					if (m_FilterText.empty()) {
						oss << L"Processes: " << m_Processes.size();
					} else {
						oss << L"Processes: " << m_FilteredProcesses.size() << L" (filtered from " << m_Processes.size() << L")";
					}
					if (m_hStatusBar) {
						std::wstring statusText = oss.str();
						SendMessage(m_hStatusBar, SB_SETTEXT, SBT_NOBORDERS, reinterpret_cast<LPARAM>(statusText.c_str()));
					}
					m_IsRefreshing = false;
				}
			}
			return 0;
		default:
			return DefWindowProc(m_hWnd, uMsg, wParam, lParam);
	}
}

std::wstring MainWindow::GetProcessImagePath(DWORD processId) {
	HandleWrapper hProcess = m_ProcessManager.OpenProcess(processId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
	if (!hProcess.IsValid()) {
		return L"";
	}

	WCHAR imagePath[MAX_PATH] = {};
	DWORD pathLen = MAX_PATH;
	if (QueryFullProcessImageNameW(hProcess.Get(), 0, imagePath, &pathLen)) {
		return std::wstring(imagePath);
	}
	return L"";
}

int MainWindow::GetProcessIconIndex(const std::wstring& imagePath) {
	if (imagePath.empty() || !m_hProcessIconList) {
		return m_DefaultIconIndex;
	}

	auto it = m_IconCache.find(imagePath);
	if (it != m_IconCache.end()) {
		return it->second;
	}

	SHFILEINFOW sfi = {};
	DWORD_PTR result = SHGetFileInfoW(
		imagePath.c_str(),
		FILE_ATTRIBUTE_NORMAL,
		&sfi,
		sizeof(sfi),
		SHGFI_ICON | SHGFI_SMALLICON
	);

	int iconIndex = m_DefaultIconIndex;
	if (result && sfi.hIcon) {
		iconIndex = ImageList_AddIcon(m_hProcessIconList, sfi.hIcon);
		if (iconIndex >= 0) {
			m_IconCache[imagePath] = iconIndex;
		} else {
			iconIndex = m_DefaultIconIndex;
		}
		DestroyIcon(sfi.hIcon);
	}

	return iconIndex;
}

void MainWindow::BuildProcessHierarchy() {
	m_ProcessChildren.clear();
	m_ProcessDepth.clear();
	std::unordered_map<DWORD, const ProcessInfo*> processMap;
	std::unordered_set<DWORD> rootProcessSet;
	std::vector<const ProcessInfo*> rootProcesses;
	
	for (const auto& proc : m_Processes) {
		processMap[proc.ProcessId] = &proc;
	}
	
	for (const auto& proc : m_Processes) {
		if (proc.ParentProcessId == 0 || proc.ParentProcessId == proc.ProcessId) {
			if (rootProcessSet.find(proc.ProcessId) == rootProcessSet.end()) {
				rootProcessSet.insert(proc.ProcessId);
				rootProcesses.push_back(&proc);
			}
		} else {
			auto parentIt = processMap.find(proc.ParentProcessId);
			if (parentIt != processMap.end()) {
				m_ProcessChildren[proc.ParentProcessId].push_back(proc.ProcessId);
			} else {
				if (rootProcessSet.find(proc.ProcessId) == rootProcessSet.end()) {
					rootProcessSet.insert(proc.ProcessId);
					rootProcesses.push_back(&proc);
				}
			}
		}
	}
	
	std::unordered_set<DWORD> visibleProcesses;
	std::unordered_set<DWORD> processedProcesses;
	
	auto markVisible = [&](DWORD pid) {
		DWORD currentPid = pid;
		while (currentPid != 0 && processedProcesses.find(currentPid) == processedProcesses.end()) {
			if (processMap.find(currentPid) != processMap.end()) {
				visibleProcesses.insert(currentPid);
				processedProcesses.insert(currentPid);
				const ProcessInfo* proc = processMap[currentPid];
				currentPid = proc->ParentProcessId;
				if (currentPid == proc->ProcessId) break;
			} else {
				break;
			}
		}
	};
	
	auto markDescendants = [&](DWORD pid) {
		std::function<void(DWORD)> markChildren = [&](DWORD parentPid) {
			auto it = m_ProcessChildren.find(parentPid);
			if (it != m_ProcessChildren.end()) {
				for (DWORD childPid : it->second) {
					if (visibleProcesses.find(childPid) == visibleProcesses.end()) {
						visibleProcesses.insert(childPid);
						markChildren(childPid);
					}
				}
			}
		};
		markChildren(pid);
	};
	
	if (!m_FilterText.empty()) {
		std::wstring filterLower = m_FilterText;
		std::transform(filterLower.begin(), filterLower.end(), filterLower.begin(), ::towlower);
		
		for (const auto& proc : m_Processes) {
			std::wstring nameW(proc.ProcessName.begin(), proc.ProcessName.end());
			std::transform(nameW.begin(), nameW.end(), nameW.begin(), ::towlower);
			
			bool matches = false;
			if (nameW.find(filterLower) != std::wstring::npos) {
				matches = true;
			} else {
				std::wostringstream pidStr;
				pidStr << proc.ProcessId;
				if (pidStr.str().find(filterLower) != std::wstring::npos) {
					matches = true;
				} else {
					std::wstring imagePath = GetProcessImagePath(proc.ProcessId);
					if (!imagePath.empty()) {
						std::transform(imagePath.begin(), imagePath.end(), imagePath.begin(), ::towlower);
						if (imagePath.find(filterLower) != std::wstring::npos) {
							matches = true;
						}
					}
				}
			}
			
			if (matches) {
				markVisible(proc.ProcessId);
				markDescendants(proc.ProcessId);
			}
		}
	} else {
		for (const auto& proc : m_Processes) {
			visibleProcesses.insert(proc.ProcessId);
		}
	}
	
	m_FilteredProcesses.clear();
	std::unordered_set<DWORD> addedProcesses;
	
	std::function<void(const ProcessInfo*, int)> addProcess = [&](const ProcessInfo* proc, int depth) {
		if (!proc) return;
		
		if (addedProcesses.find(proc->ProcessId) != addedProcesses.end()) {
			return;
		}
		
		if (visibleProcesses.find(proc->ProcessId) == visibleProcesses.end()) {
			return;
		}
		
		addedProcesses.insert(proc->ProcessId);
		ProcessInfo procCopy = *proc;
		m_FilteredProcesses.push_back(procCopy);
		m_ProcessDepth[proc->ProcessId] = depth;
		
		bool isExpanded = (depth == 0) || m_ExpandedProcesses[proc->ProcessId];
		if (isExpanded) {
			auto it = m_ProcessChildren.find(proc->ProcessId);
			if (it != m_ProcessChildren.end()) {
				std::vector<DWORD> sortedChildren = it->second;
				std::sort(sortedChildren.begin(), sortedChildren.end());
				
				for (DWORD childPid : sortedChildren) {
					auto childIt = processMap.find(childPid);
					if (childIt != processMap.end() && childIt->second != nullptr) {
						addProcess(childIt->second, depth + 1);
					}
				}
			}
		}
	};
	
	std::sort(rootProcesses.begin(), rootProcesses.end(), 
		[](const ProcessInfo* a, const ProcessInfo* b) { return a->ProcessId < b->ProcessId; });
	
	for (const auto* root : rootProcesses) {
		addProcess(root, 0);
	}
}

void MainWindow::UpdateProcessList() {
	if (!m_hProcessListView) return;

	ListView_DeleteAllItems(m_hProcessListView);

	if (m_TreeViewEnabled) {
		BuildProcessHierarchy();
	} else {
		m_FilteredProcesses.clear();
		if (m_FilterText.empty()) {
			m_FilteredProcesses = m_Processes;
		} else {
			std::wstring filterLower = m_FilterText;
			std::transform(filterLower.begin(), filterLower.end(), filterLower.begin(), ::towlower);
			
			for (const auto& proc : m_Processes) {
				std::wstring nameW(proc.ProcessName.begin(), proc.ProcessName.end());
				std::transform(nameW.begin(), nameW.end(), nameW.begin(), ::towlower);
				
				std::wstring pidStr = std::to_wstring(proc.ProcessId);
				std::transform(pidStr.begin(), pidStr.end(), pidStr.begin(), ::towlower);
				
				std::wstring imagePath = GetProcessImagePath(proc.ProcessId);
				std::wstring desc = imagePath.empty() ? L"" : GetFileDescription(imagePath);
				std::transform(desc.begin(), desc.end(), desc.begin(), ::towlower);
				
				std::wstring company = imagePath.empty() ? L"" : GetFileCompany(imagePath);
				std::transform(company.begin(), company.end(), company.begin(), ::towlower);
				
				std::wstring user = proc.UserName;
				std::transform(user.begin(), user.end(), user.begin(), ::towlower);
				
				if (nameW.find(filterLower) != std::wstring::npos ||
					pidStr.find(filterLower) != std::wstring::npos ||
					desc.find(filterLower) != std::wstring::npos ||
					company.find(filterLower) != std::wstring::npos ||
					user.find(filterLower) != std::wstring::npos) {
					m_FilteredProcesses.push_back(proc);
				}
			}
		}
	}

	for (size_t i = 0; i < m_FilteredProcesses.size(); ++i) {
		const auto& proc = m_FilteredProcesses[i];

		std::wstring imagePath = GetProcessImagePath(proc.ProcessId);
		int iconIndex = GetProcessIconIndex(imagePath);

		std::wstring nameWStr(proc.ProcessName.begin(), proc.ProcessName.end());
		std::wstring displayName;
		
		if (m_TreeViewEnabled) {
			int depth = 0;
			auto depthIt = m_ProcessDepth.find(proc.ProcessId);
			if (depthIt != m_ProcessDepth.end()) {
				depth = depthIt->second;
			}
			
			bool hasChildren = m_ProcessChildren.find(proc.ProcessId) != m_ProcessChildren.end() && 
			                  !m_ProcessChildren[proc.ProcessId].empty();
			
			for (int d = 0; d < depth; ++d) {
				displayName += L"    ";
			}
			
			if (hasChildren) {
				displayName += m_ExpandedProcesses[proc.ProcessId] ? L"[-] " : L"[+] ";
			} else {
				displayName += L"    ";
			}
		}
		displayName += nameWStr;

		LVITEMW lvi = {};
		lvi.mask = LVIF_TEXT | LVIF_PARAM | LVIF_IMAGE;
		lvi.iItem = static_cast<int>(i);
		lvi.lParam = proc.ProcessId;
		lvi.iImage = iconIndex;
		lvi.pszText = const_cast<LPWSTR>(displayName.c_str());
		lvi.iSubItem = COL_NAME;
		ListView_InsertItem(m_hProcessListView, &lvi);

		std::wostringstream pidStr;
		pidStr << proc.ProcessId;
		std::wstring pidWStr = pidStr.str();
		ListView_SetItemText(m_hProcessListView, i, COL_PID, const_cast<LPWSTR>(pidWStr.c_str()));

		std::wostringstream ppidStr;
		ppidStr << proc.ParentProcessId;
		std::wstring ppidWStr = ppidStr.str();
		ListView_SetItemText(m_hProcessListView, i, COL_PPID, const_cast<LPWSTR>(ppidWStr.c_str()));

		std::wostringstream sessionStr;
		sessionStr << proc.SessionId;
		std::wstring sessionWStr = sessionStr.str();
		ListView_SetItemText(m_hProcessListView, i, COL_SESSION, const_cast<LPWSTR>(sessionWStr.c_str()));

		std::wstring integrityStr = FormatIntegrityLevel(proc.IntegrityLevel);
		ListView_SetItemText(m_hProcessListView, i, COL_INTEGRITY, const_cast<LPWSTR>(integrityStr.c_str()));

		std::wstring userStr = proc.UserName.empty() ? L"N/A" : proc.UserName;
		ListView_SetItemText(m_hProcessListView, i, COL_USER, const_cast<LPWSTR>(userStr.c_str()));

		std::wstring archWStr(proc.Architecture.begin(), proc.Architecture.end());
		ListView_SetItemText(m_hProcessListView, i, COL_ARCHITECTURE, const_cast<LPWSTR>(archWStr.c_str()));

		double cpuPercent = GetCpuUsage(proc.ProcessId);
		std::wostringstream cpuStream;
		cpuStream << std::fixed << std::setprecision(1) << cpuPercent << L"%";
		std::wstring cpuStr = cpuStream.str();
		ListView_SetItemText(m_hProcessListView, i, COL_CPU, const_cast<LPWSTR>(cpuStr.c_str()));

		std::wstring memoryStr = L"N/A";
		auto memIt = m_ProcessMemory.find(proc.ProcessId);
		if (memIt != m_ProcessMemory.end() && memIt->second > 0) {
			memoryStr = FormatMemorySize(memIt->second);
		}
		ListView_SetItemText(m_hProcessListView, i, COL_MEMORY, const_cast<LPWSTR>(memoryStr.c_str()));

		std::wstring descriptionStr = L"";
		std::wstring companyStr = L"";
		if (!imagePath.empty()) {
			descriptionStr = GetFileDescription(imagePath);
			companyStr = GetFileCompany(imagePath);
		}
		if (descriptionStr.empty()) descriptionStr = L"N/A";
		if (companyStr.empty()) companyStr = L"N/A";
		
		ListView_SetItemText(m_hProcessListView, i, COL_DESCRIPTION, const_cast<LPWSTR>(descriptionStr.c_str()));

		std::wstring imagePathStr = imagePath.empty() ? L"N/A" : imagePath;
		ListView_SetItemText(m_hProcessListView, i, COL_IMAGEPATH, const_cast<LPWSTR>(imagePathStr.c_str()));

		ListView_SetItemText(m_hProcessListView, i, COL_COMMANDLINE, const_cast<LPWSTR>(L"N/A"));

		ListView_SetItemText(m_hProcessListView, i, COL_COMPANY, const_cast<LPWSTR>(companyStr.c_str()));
	}
}

void MainWindow::SortProcessList(int column, bool ascending) {
	m_SortColumn = column;
	m_SortAscending = ascending;

	auto& listToSort = m_FilterText.empty() ? m_Processes : m_FilteredProcesses;
	std::sort(listToSort.begin(), listToSort.end(), [this, column, ascending](const ProcessInfo& a, const ProcessInfo& b) {
		bool result = false;
		switch (column) {
			case COL_NAME:
				result = a.ProcessName < b.ProcessName;
				break;
			case COL_PID:
				result = a.ProcessId < b.ProcessId;
				break;
			case COL_PPID:
				result = a.ParentProcessId < b.ParentProcessId;
				break;
			case COL_CPU:
				{
					ULONGLONG cpuA = m_ProcessCpuTime.find(a.ProcessId) != m_ProcessCpuTime.end() ? m_ProcessCpuTime[a.ProcessId] : 0;
					ULONGLONG cpuB = m_ProcessCpuTime.find(b.ProcessId) != m_ProcessCpuTime.end() ? m_ProcessCpuTime[b.ProcessId] : 0;
					result = cpuA < cpuB;
				}
				break;
			case COL_MEMORY:
				{
					SIZE_T memA = m_ProcessMemory.find(a.ProcessId) != m_ProcessMemory.end() ? m_ProcessMemory[a.ProcessId] : 0;
					SIZE_T memB = m_ProcessMemory.find(b.ProcessId) != m_ProcessMemory.end() ? m_ProcessMemory[b.ProcessId] : 0;
					result = memA < memB;
				}
				break;
			case COL_SESSION:
				result = a.SessionId < b.SessionId;
				break;
			case COL_INTEGRITY:
				result = static_cast<DWORD>(a.IntegrityLevel) < static_cast<DWORD>(b.IntegrityLevel);
				break;
			case COL_USER:
				result = a.UserName < b.UserName;
				break;
			case COL_ARCHITECTURE:
				result = a.Architecture < b.Architecture;
				break;
			case COL_DESCRIPTION:
			case COL_IMAGEPATH:
				result = a.ProcessName < b.ProcessName;
				break;
			default:
				result = a.ProcessName < b.ProcessName;
				break;
		}
		return ascending ? result : !result;
	});

	UpdateProcessList();
}

void MainWindow::OnProcessListDoubleClick() {
	int sel = ListView_GetNextItem(m_hProcessListView, -1, LVNI_SELECTED);
	if (sel >= 0) {
		LVITEMW lvi = {};
		lvi.iItem = sel;
		lvi.mask = LVIF_PARAM;
		ListView_GetItem(m_hProcessListView, &lvi);
		ShowProcessProperties(static_cast<DWORD>(lvi.lParam));
	}
}

void MainWindow::OnProcessListSelectionChanged() {
	int sel = ListView_GetNextItem(m_hProcessListView, -1, LVNI_SELECTED);
	if (sel >= 0) {
		LVITEMW lvi = {};
		lvi.iItem = sel;
		lvi.mask = LVIF_PARAM;
		ListView_GetItem(m_hProcessListView, &lvi);
		m_SelectedProcessId = static_cast<DWORD>(lvi.lParam);
		
		auto it = std::find_if(m_FilteredProcesses.begin(), m_FilteredProcesses.end(),
			[this](const ProcessInfo& p) { return p.ProcessId == m_SelectedProcessId; });
		
		if (it != m_FilteredProcesses.end() && m_hStatusBar) {
			std::wostringstream statusText;
			statusText << L"PID: " << it->ProcessId
				<< L" | Threads: " << it->ThreadCount
				<< L" | Handles: " << it->HandleCount
				<< L" | GDI: " << it->GdiObjectCount
				<< L" | USER: " << it->UserObjectCount;
			
			if (it->DEPEnabled || it->ASLREnabled || it->CFGEnabled) {
				statusText << L" | Mitigations: ";
				if (it->DEPEnabled) statusText << L"DEP ";
				if (it->ASLREnabled) statusText << L"ASLR ";
				if (it->CFGEnabled) statusText << L"CFG";
			}
			
			SendMessageW(m_hStatusBar, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(statusText.str().c_str()));
		}
	} else {
		m_SelectedProcessId = 0;
	}
	UpdateProcessMenuState();
}

void MainWindow::ShowProcessContextMenu(int x, int y) {
	if (m_SelectedProcessId == 0) return;

	POINT pt = { x, y };
	if (pt.x == -1 && pt.y == -1) {
		int sel = ListView_GetNextItem(m_hProcessListView, -1, LVNI_SELECTED);
		if (sel >= 0) {
			RECT rc;
			ListView_GetItemRect(m_hProcessListView, sel, &rc, LVIR_BOUNDS);
			pt.x = rc.left;
			pt.y = rc.bottom;
			ClientToScreen(m_hProcessListView, &pt);
		}
	}

	TrackPopupMenu(m_hContextMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, m_hWnd, nullptr);
}

void MainWindow::OnFileRefresh() {
	RefreshProcessList();
}

void MainWindow::OnFileExit() {
	PostMessage(m_hWnd, WM_CLOSE, 0, 0);
}

void MainWindow::OnFileExport() {
	if (m_Processes.empty()) {
		MessageBoxW(m_hWnd, L"No process data available. Please refresh the process list first.", L"Export Failed", MB_OK | MB_ICONWARNING);
		return;
	}
	
	BuildProcessHierarchy();
	
	const auto& processesToExport = m_FilteredProcesses.empty() ? m_Processes : m_FilteredProcesses;
	
	OPENFILENAMEW ofn = {};
	wchar_t szFile[260] = {};
	wcscpy_s(szFile, L"processes.csv");
	
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = m_hWnd;
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = sizeof(szFile) / sizeof(szFile[0]);
	ofn.lpstrFilter = L"CSV Files\0*.csv\0JSON Files\0*.json\0Text Files\0*.txt\0All Files\0*.*\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = nullptr;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = nullptr;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY;

	if (!GetSaveFileNameW(&ofn)) {
		return;
	}

	std::wstring filePath(szFile);
	std::wstring extension;
	size_t dotPos = filePath.find_last_of(L".");
	if (dotPos != std::wstring::npos && dotPos + 1 < filePath.length()) {
		extension = filePath.substr(dotPos + 1);
		std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);
	}

	bool success = false;
	if (extension == L"csv") {
		success = ExportToCSV(filePath, processesToExport);
	} else if (extension == L"json") {
		success = ExportToJSON(filePath, processesToExport);
	} else {
		success = ExportToText(filePath, processesToExport);
	}

	if (success) {
		std::wostringstream oss;
		oss << L"Process list exported successfully to:\n" << filePath;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Export Successful", MB_OK | MB_ICONINFORMATION);
		int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1, nullptr, 0, nullptr, nullptr);
		if (sizeNeeded > 0) {
			std::string filePathA(sizeNeeded, 0);
			WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1, &filePathA[0], sizeNeeded, nullptr, nullptr);
			filePathA.pop_back();
			Logger::GetInstance().LogInfo("Exported process list to: " + filePathA);
		}
	} else {
		MessageBoxW(m_hWnd, L"Failed to export process list.", L"Export Failed", MB_OK | MB_ICONERROR);
		int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1, nullptr, 0, nullptr, nullptr);
		if (sizeNeeded > 0) {
			std::string filePathA(sizeNeeded, 0);
			WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1, &filePathA[0], sizeNeeded, nullptr, nullptr);
			filePathA.pop_back();
			Logger::GetInstance().LogError("Failed to export process list to: " + filePathA);
		}
	}
}

static std::wstring Utf8ToWide(const std::string& utf8) {
	if (utf8.empty()) return L"";
	int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
	if (sizeNeeded <= 0) return L"";
	std::wstring result(sizeNeeded, 0);
	MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &result[0], sizeNeeded);
	result.pop_back();
	return result;
}

static std::string WideToUtf8(const std::wstring& wide) {
	if (wide.empty()) return "";
	int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (sizeNeeded <= 0) return "";
	std::string result(sizeNeeded, 0);
	WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &result[0], sizeNeeded, nullptr, nullptr);
	result.pop_back();
	return result;
}

bool MainWindow::ExportToCSV(const std::wstring& filePath, const std::vector<WinProcessInspector::Core::ProcessInfo>& processes) {
	if (processes.empty()) {
		return false;
	}

	FILE* file = nullptr;
	if (_wfopen_s(&file, filePath.c_str(), L"w,ccs=UTF-8") != 0 || !file) {
		return false;
	}

	fprintf(file, "\xEF\xBB\xBF");
	fprintf(file, "Name,PID,Parent PID,CPU%%,Memory,Session,Integrity,User,Architecture,Description,Image Path\n");
	auto escapeCSV = [](const std::string& str) -> std::string {
		if (str.find(",") != std::string::npos || str.find("\"") != std::string::npos || str.find("\n") != std::string::npos) {
			std::string escaped = "\"";
			for (char c : str) {
				if (c == '"') escaped += "\"\"";
				else escaped += c;
			}
			escaped += "\"";
			return escaped;
		}
		return str;
	};

	for (const auto& proc : processes) {
		try {
			std::string name = proc.ProcessName;
			std::string user = WideToUtf8(proc.UserName.empty() ? L"N/A" : proc.UserName);
			std::string integrity = WideToUtf8(FormatIntegrityLevel(proc.IntegrityLevel));
			std::string arch = proc.Architecture;
			
			std::wstring imagePathW = GetProcessImagePath(proc.ProcessId);
			std::string imagePath = WideToUtf8(imagePathW.empty() ? L"N/A" : imagePathW);
			std::string description = "N/A";
			
			double cpuUsage = 0.0;
			try {
				cpuUsage = GetCpuUsage(proc.ProcessId);
			} catch (...) {
				cpuUsage = 0.0;
			}
			
			SIZE_T memory = 0;
			auto memIt = m_ProcessMemory.find(proc.ProcessId);
			if (memIt != m_ProcessMemory.end()) {
				memory = memIt->second;
			}

			fprintf(file, "%s,%u,%u,%.2f,%llu,%u,%s,%s,%s,%s,%s\n",
				escapeCSV(name).c_str(),
				proc.ProcessId,
				proc.ParentProcessId,
				cpuUsage,
				static_cast<unsigned long long>(memory),
				proc.SessionId,
				escapeCSV(integrity).c_str(),
				escapeCSV(user).c_str(),
				escapeCSV(arch).c_str(),
				escapeCSV(description).c_str(),
				escapeCSV(imagePath).c_str()
			);
		} catch (...) {
			continue;
		}
	}

	fclose(file);
	return true;
}

bool MainWindow::ExportToJSON(const std::wstring& filePath, const std::vector<WinProcessInspector::Core::ProcessInfo>& processes) {
	if (processes.empty()) {
		return false;
	}

	FILE* file = nullptr;
	if (_wfopen_s(&file, filePath.c_str(), L"w,ccs=UTF-8") != 0 || !file) {
		return false;
	}

	fprintf(file, "{\n  \"processes\": [\n");

	auto escapeJSON = [](const std::string& str) -> std::string {
		std::string escaped;
		for (char c : str) {
			if (c == '"') escaped += "\\\"";
			else if (c == '\\') escaped += "\\\\";
			else if (c == '\n') escaped += "\\n";
			else if (c == '\r') escaped += "\\r";
			else if (c == '\t') escaped += "\\t";
			else escaped += c;
		}
		return escaped;
	};

	for (size_t i = 0; i < processes.size(); ++i) {
		const auto& proc = processes[i];
		try {
			std::string name = proc.ProcessName;
			std::string user = WideToUtf8(proc.UserName.empty() ? L"N/A" : proc.UserName);
			std::string integrity = WideToUtf8(FormatIntegrityLevel(proc.IntegrityLevel));
			std::string arch = proc.Architecture;
			
			std::wstring imagePathW = GetProcessImagePath(proc.ProcessId);
			std::string imagePath = WideToUtf8(imagePathW.empty() ? L"N/A" : imagePathW);
			std::string description = "N/A";
			
			double cpuUsage = 0.0;
			try {
				cpuUsage = GetCpuUsage(proc.ProcessId);
			} catch (...) {
				cpuUsage = 0.0;
			}
			
			SIZE_T memory = 0;
			auto memIt = m_ProcessMemory.find(proc.ProcessId);
			if (memIt != m_ProcessMemory.end()) {
				memory = memIt->second;
			}

			fprintf(file, "    {\n");
			fprintf(file, "      \"name\": \"%s\",\n", escapeJSON(name).c_str());
			fprintf(file, "      \"pid\": %u,\n", proc.ProcessId);
			fprintf(file, "      \"parentPid\": %u,\n", proc.ParentProcessId);
			fprintf(file, "      \"cpuUsage\": %.2f,\n", cpuUsage);
			fprintf(file, "      \"memory\": %llu,\n", static_cast<unsigned long long>(memory));
			fprintf(file, "      \"sessionId\": %u,\n", proc.SessionId);
			fprintf(file, "      \"integrity\": \"%s\",\n", escapeJSON(integrity).c_str());
			fprintf(file, "      \"user\": \"%s\",\n", escapeJSON(user).c_str());
			fprintf(file, "      \"architecture\": \"%s\",\n", escapeJSON(arch).c_str());
			fprintf(file, "      \"description\": \"%s\",\n", escapeJSON(description).c_str());
			fprintf(file, "      \"imagePath\": \"%s\"\n", escapeJSON(imagePath).c_str());
			fprintf(file, "    }%s\n", (i < processes.size() - 1) ? "," : "");
		} catch (...) {
			continue;
		}
	}

	fprintf(file, "  ]\n}\n");
	fclose(file);
	return true;
}

bool MainWindow::ExportToText(const std::wstring& filePath, const std::vector<WinProcessInspector::Core::ProcessInfo>& processes) {
	FILE* file = nullptr;
	if (_wfopen_s(&file, filePath.c_str(), L"w,ccs=UTF-8") != 0 || !file) {
		return false;
	}

	fwprintf(file, L"WinProcessInspector - Process List Export\n");
	SYSTEMTIME st;
	GetLocalTime(&st);
	FILETIME ft;
	SystemTimeToFileTime(&st, &ft);
	fwprintf(file, L"Generated: %ls\n", FormatTime(ft).c_str());
	fwprintf(file, L"Total Processes: %zu\n\n", processes.size());
	fwprintf(file, L"%-30s %8s %8s %8s %12s %8s %15s %-20s %12s %-30s %s\n",
		L"Name", L"PID", L"PPID", L"CPU%", L"Memory", L"Session", L"Integrity", L"User", L"Architecture", L"Description", L"Image Path");
	fwprintf(file, L"%s\n", std::wstring(150, L'-').c_str());

	for (const auto& proc : processes) {
		std::wstring name = Utf8ToWide(proc.ProcessName);
		std::wstring user = proc.UserName.empty() ? L"N/A" : proc.UserName;
		std::wstring integrity = FormatIntegrityLevel(proc.IntegrityLevel);
		std::wstring arch = Utf8ToWide(proc.Architecture);
		
		std::wstring imagePath = GetProcessImagePath(proc.ProcessId);
		std::wstring description = L"N/A";
		
		double cpuUsage = GetCpuUsage(proc.ProcessId);
		SIZE_T memory = 0;
		auto memIt = m_ProcessMemory.find(proc.ProcessId);
		if (memIt != m_ProcessMemory.end()) {
			memory = memIt->second;
		}

		fwprintf(file, L"%-30s %8u %8u %7.2f%% %12llu %8u %15s %-20s %12s %-30s %s\n",
			name.c_str(),
			proc.ProcessId,
			proc.ParentProcessId,
			cpuUsage,
			static_cast<unsigned long long>(memory),
			proc.SessionId,
			integrity.c_str(),
			user.c_str(),
			arch.c_str(),
			description.c_str(),
			imagePath.c_str()
		);
	}

	fclose(file);
	return true;
}

void MainWindow::OnViewAutoRefresh() {
	m_AutoRefresh = !m_AutoRefresh;
	
	HMENU hViewMenu = GetSubMenu(m_hMenu, 2);
	if (hViewMenu) {
		CheckMenuItem(hViewMenu, IDM_VIEW_AUTOREFRESH, m_AutoRefresh ? MF_CHECKED : MF_UNCHECKED);
	}

	if (m_AutoRefresh) {
		m_RefreshTimerId = SetTimer(m_hWnd, IDT_REFRESH_TIMER, 2000, nullptr);
	} else {
		if (m_RefreshTimerId) {
			KillTimer(m_hWnd, m_RefreshTimerId);
			m_RefreshTimerId = 0;
		}
	}
}

void MainWindow::OnViewTreeView() {
	m_TreeViewEnabled = !m_TreeViewEnabled;
	
	HMENU hViewMenu = GetSubMenu(m_hMenu, 2);
	if (hViewMenu) {
		CheckMenuItem(hViewMenu, IDM_VIEW_TREEVIEW, m_TreeViewEnabled ? MF_CHECKED : MF_UNCHECKED);
	}
	
	if (!m_TreeViewEnabled) {
		m_ExpandedProcesses.clear();
		m_ProcessChildren.clear();
		m_ProcessDepth.clear();
	}
	
	UpdateProcessList();
}

void MainWindow::OnViewToolbar() {
	m_ToolbarVisible = !m_ToolbarVisible;

	HMENU hViewMenu = GetSubMenu(m_hMenu, 2);
	if (hViewMenu) {
		CheckMenuItem(hViewMenu, IDM_VIEW_TOOLBAR, m_ToolbarVisible ? MF_CHECKED : MF_UNCHECKED);
	}

	if (m_hToolbar && IsWindow(m_hToolbar)) {
		ShowWindow(m_hToolbar, m_ToolbarVisible ? SW_SHOW : SW_HIDE);
		SendMessage(m_hWnd, WM_SIZE, 0, 0);
	}
}

void MainWindow::OnViewSearchBar() {
	m_SearchBarVisible = !m_SearchBarVisible;
	
	HMENU hViewMenu = GetSubMenu(m_hMenu, 2);
	if (hViewMenu) {
		CheckMenuItem(hViewMenu, IDM_VIEW_SEARCHBAR, m_SearchBarVisible ? MF_CHECKED : MF_UNCHECKED);
	}
	
	if (m_hSearchFilter && IsWindow(m_hSearchFilter)) {
		ShowWindow(m_hSearchFilter, m_SearchBarVisible ? SW_SHOW : SW_HIDE);
		SendMessage(m_hWnd, WM_SIZE, 0, 0);
	}
}

void MainWindow::OnViewColumns() {
	ShowColumnChooserDialog();
}

INT_PTR CALLBACK ColumnChooserDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	if (uMsg == WM_INITDIALOG) {
		MainWindow* pMainWindow = reinterpret_cast<MainWindow*>(lParam);
		SetWindowLongPtr(hDlg, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pMainWindow));
		
		HFONT hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
		
		struct ColumnCheckbox {
			int controlId;
			int columnIndex;
		};
		
		ColumnCheckbox checkboxes[] = {
			{ IDC_COLUMN_NAME, COL_NAME },
			{ IDC_COLUMN_PID, COL_PID },
			{ IDC_COLUMN_PPID, COL_PPID },
			{ IDC_COLUMN_CPU, COL_CPU },
			{ IDC_COLUMN_MEMORY, COL_MEMORY },
			{ IDC_COLUMN_SESSION, COL_SESSION },
			{ IDC_COLUMN_INTEGRITY, COL_INTEGRITY },
			{ IDC_COLUMN_USER, COL_USER },
			{ IDC_COLUMN_ARCHITECTURE, COL_ARCHITECTURE },
			{ IDC_COLUMN_DESCRIPTION, COL_DESCRIPTION },
			{ IDC_COLUMN_IMAGEPATH, COL_IMAGEPATH },
			{ IDC_COLUMN_COMMANDLINE, COL_COMMANDLINE },
			{ IDC_COLUMN_COMPANY, COL_COMPANY }
		};
		
		std::vector<bool>& columnVisible = pMainWindow->GetColumnVisible();
		for (size_t i = 0; i < sizeof(checkboxes) / sizeof(checkboxes[0]); ++i) {
			HWND hCheckbox = GetDlgItem(hDlg, checkboxes[i].controlId);
			if (hCheckbox) {
				SendMessage(hCheckbox, BM_SETCHECK, columnVisible[checkboxes[i].columnIndex] ? BST_CHECKED : BST_UNCHECKED, 0);
				if (hFont) {
					SendMessageW(hCheckbox, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);
				}
			}
		}
		
		HWND hOkButton = GetDlgItem(hDlg, IDOK);
		HWND hCancelButton = GetDlgItem(hDlg, IDCANCEL);
		if (hFont) {
			if (hOkButton) SendMessageW(hOkButton, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);
			if (hCancelButton) SendMessageW(hCancelButton, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);
		}
		
		return TRUE;
	}
	
	if (uMsg == WM_COMMAND) {
		if (LOWORD(wParam) == 1) {
			MainWindow* pMainWindow = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hDlg, GWLP_USERDATA));
			if (pMainWindow) {
				struct ColumnCheckbox {
					int controlId;
					int columnIndex;
				};
				
				ColumnCheckbox checkboxes[] = {
					{ IDC_COLUMN_NAME, COL_NAME },
					{ IDC_COLUMN_PID, COL_PID },
					{ IDC_COLUMN_PPID, COL_PPID },
					{ IDC_COLUMN_CPU, COL_CPU },
					{ IDC_COLUMN_MEMORY, COL_MEMORY },
					{ IDC_COLUMN_SESSION, COL_SESSION },
					{ IDC_COLUMN_INTEGRITY, COL_INTEGRITY },
					{ IDC_COLUMN_USER, COL_USER },
					{ IDC_COLUMN_ARCHITECTURE, COL_ARCHITECTURE },
					{ IDC_COLUMN_DESCRIPTION, COL_DESCRIPTION },
					{ IDC_COLUMN_IMAGEPATH, COL_IMAGEPATH },
					{ IDC_COLUMN_COMMANDLINE, COL_COMMANDLINE },
					{ IDC_COLUMN_COMPANY, COL_COMPANY }
				};
				
				std::vector<bool>& columnVisible = pMainWindow->GetColumnVisible();
				for (size_t i = 0; i < sizeof(checkboxes) / sizeof(checkboxes[0]); ++i) {
					HWND hCheckbox = GetDlgItem(hDlg, checkboxes[i].controlId);
					if (hCheckbox) {
						LRESULT checked = SendMessage(hCheckbox, BM_GETCHECK, 0, 0);
						columnVisible[checkboxes[i].columnIndex] = (checked == BST_CHECKED);
					}
				}
				pMainWindow->UpdateColumnVisibility();
			}
			EndDialog(hDlg, 1);
			return TRUE;
		} else if (LOWORD(wParam) == 2) {
			EndDialog(hDlg, 2);
			return TRUE;
		}
	}
	
	return FALSE;
}

void MainWindow::ShowColumnChooserDialog() {
	INT_PTR result = DialogBoxParamW(m_hInstance, MAKEINTRESOURCE(IDD_COLUMN_CHOOSER), m_hWnd, ColumnChooserDialogProc, reinterpret_cast<LPARAM>(this));
	if (result == -1) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to show column chooser dialog. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Error", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Failed to show column chooser dialog. Error: " + std::to_string(error));
	}
}

void MainWindow::UpdateColumnVisibility() {
	for (int i = 0; i < COL_COUNT; ++i) {
		if (m_ColumnVisible[i]) {
			if (ListView_GetColumnWidth(m_hProcessListView, i) == 0) {
				SendMessage(m_hProcessListView, LVM_SETCOLUMNWIDTH, i, LVSCW_AUTOSIZE_USEHEADER);
			}
		} else {
			ListView_SetColumnWidth(m_hProcessListView, i, 0);
		}
	}
}

void MainWindow::OnHelpAbout() {
	MessageBoxW(m_hWnd, L"WinProcessInspector\n\nA professional Windows system inspection tool.", L"About WinProcessInspector", MB_OK | MB_ICONINFORMATION);
}

void MainWindow::OnHelpGitHub() {
	HINSTANCE result = ShellExecuteW(m_hWnd, L"open", L"https://github.com/PhilipPanda/WinProcessInspector", nullptr, nullptr, SW_SHOWNORMAL);
	if (reinterpret_cast<INT_PTR>(result) <= 32) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to open GitHub repository.\n\nError code: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Error", MB_OK | MB_ICONERROR);
	}
}

void MainWindow::UpdateProcessMenuState() {
	HMENU hProcessMenu = GetSubMenu(m_hMenu, 1);
	if (!hProcessMenu) return;
	
	bool hasSelection = (m_SelectedProcessId != 0);
	
	EnableMenuItem(hProcessMenu, IDM_PROCESS_PROPERTIES, hasSelection ? MF_ENABLED : MF_GRAYED);
	EnableMenuItem(hProcessMenu, IDM_PROCESS_FILE_LOCATION, hasSelection ? MF_ENABLED : MF_GRAYED);
	EnableMenuItem(hProcessMenu, IDM_PROCESS_SEARCH_ONLINE, hasSelection ? MF_ENABLED : MF_GRAYED);
	EnableMenuItem(hProcessMenu, IDM_PROCESS_INJECT_DLL, hasSelection ? MF_ENABLED : MF_GRAYED);
	EnableMenuItem(hProcessMenu, IDM_PROCESS_SUSPEND, hasSelection ? MF_ENABLED : MF_GRAYED);
	EnableMenuItem(hProcessMenu, IDM_PROCESS_RESUME, hasSelection ? MF_ENABLED : MF_GRAYED);
	EnableMenuItem(hProcessMenu, IDM_PROCESS_TERMINATE, hasSelection ? MF_ENABLED : MF_GRAYED);
}

void MainWindow::ShowProcessProperties(DWORD processId) {
	if (!m_PropertiesDialog) {
		m_PropertiesDialog = std::make_unique<ProcessPropertiesDialog>(m_hInstance, m_hWnd);
	}
	m_PropertiesDialog->Show(processId);
}

bool MainWindow::ValidateProcess(DWORD processId, std::wstring& errorMsg) {
	ProcessInfo info = m_ProcessManager.GetProcessDetails(processId);
	if (info.ProcessId == 0) {
		errorMsg = L"The process no longer exists.";
		return false;
	}
	return true;
}

bool MainWindow::ValidateProcessAccess(DWORD processId, DWORD desiredAccess, std::wstring& errorMsg) {
	HandleWrapper hProcess = m_ProcessManager.OpenProcess(processId, desiredAccess);
	if (!hProcess.IsValid()) {
		DWORD error = GetLastError();
		if (error == ERROR_ACCESS_DENIED) {
			errorMsg = L"Access denied. The process may be protected or running with higher privileges.";
		} else if (error == ERROR_INVALID_PARAMETER) {
			errorMsg = L"Invalid process ID.";
		} else {
			std::wostringstream oss;
			oss << L"Failed to open process. Error: " << error;
			errorMsg = oss.str();
		}
		return false;
	}
	return true;
}

bool MainWindow::ValidateArchitectureCompatibility(DWORD processId, std::wstring& errorMsg) {
	std::string targetArch = m_ProcessManager.GetProcessArchitecture(processId);
	SystemInfo sysInfo;
	std::string systemArch = sysInfo.GetSystemArchitecture();
	
	if (targetArch != systemArch && targetArch != "?" && systemArch != "?") {
		std::wostringstream oss;
		oss << L"Architecture mismatch. Target process is " << std::wstring(targetArch.begin(), targetArch.end())
			<< L" but system is " << std::wstring(systemArch.begin(), systemArch.end())
			<< L". Some operations may fail.";
		errorMsg = oss.str();
		return false;
	}
	return true;
}

bool MainWindow::ValidateIntegrityLevel(DWORD processId, std::wstring& errorMsg) {
	SecurityManager secMgr;
	IntegrityLevel targetLevel = secMgr.GetProcessIntegrityLevel(processId);
	IntegrityLevel currentLevel = secMgr.GetProcessIntegrityLevel(0);
	
	if (static_cast<DWORD>(targetLevel) > static_cast<DWORD>(currentLevel)) {
		errorMsg = L"The target process has higher integrity level. This operation may fail.";
		return false;
	}
	return true;
}

void MainWindow::TerminateProcess(DWORD processId) {
	std::wstring errorMsg;
	if (!ValidateProcess(processId, errorMsg)) {
		MessageBoxW(m_hWnd, errorMsg.c_str(), L"Terminate Process", MB_OK | MB_ICONERROR);
		return;
	}

	if (!ValidateProcessAccess(processId, PROCESS_TERMINATE, errorMsg)) {
		MessageBoxW(m_hWnd, errorMsg.c_str(), L"Terminate Process", MB_OK | MB_ICONERROR);
		return;
	}

	int result = MessageBoxW(m_hWnd, L"Are you sure you want to terminate this process?\n\nThis action cannot be undone.", L"Terminate Process", MB_YESNO | MB_ICONWARNING);
	if (result == IDYES) {
		HandleWrapper hProcess = m_ProcessManager.OpenProcess(processId, PROCESS_TERMINATE);
		if (hProcess.IsValid()) {
			if (::TerminateProcess(hProcess.Get(), 1)) {
				RefreshProcessList();
				Logger::GetInstance().LogInfo("Terminated process PID " + std::to_string(processId));
				MessageBoxW(m_hWnd, L"Process terminated successfully.", L"Terminate Process", MB_OK | MB_ICONINFORMATION);
			} else {
				DWORD error = GetLastError();
				std::wostringstream oss;
				oss << L"Failed to terminate process. Error: " << error;
				MessageBoxW(m_hWnd, oss.str().c_str(), L"Terminate Process", MB_OK | MB_ICONERROR);
				Logger::GetInstance().LogError("Failed to terminate process PID " + std::to_string(processId) + ". Error: " + std::to_string(error));
			}
		}
	}
}

void MainWindow::SuspendProcess(DWORD processId) {
	std::wstring errorMsg;
	if (!ValidateProcess(processId, errorMsg)) {
		MessageBoxW(m_hWnd, errorMsg.c_str(), L"Suspend Process", MB_OK | MB_ICONERROR);
		return;
	}

	if (!ValidateProcessAccess(processId, PROCESS_SUSPEND_RESUME, errorMsg)) {
		MessageBoxW(m_hWnd, errorMsg.c_str(), L"Suspend Process", MB_OK | MB_ICONERROR);
		return;
	}

	std::vector<ThreadInfo> threads = m_ProcessManager.EnumerateThreads(processId);
	int suspendedCount = 0;
	int failedCount = 0;

	for (const auto& thread : threads) {
		HandleWrapper hThread(OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread.ThreadId));
		if (hThread.IsValid()) {
			if (SuspendThread(hThread.Get()) != (DWORD)-1) {
				suspendedCount++;
			} else {
				failedCount++;
			}
		} else {
			failedCount++;
		}
	}

	if (suspendedCount > 0) {
		std::wostringstream oss;
		oss << L"Process suspended successfully.\n\nSuspended " << suspendedCount << L" thread(s)";
		if (failedCount > 0) {
			oss << L"\nFailed to suspend " << failedCount << L" thread(s)";
		}
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Suspend Process", MB_OK | MB_ICONINFORMATION);
		Logger::GetInstance().LogInfo("Suspended process PID " + std::to_string(processId));
		RefreshProcessList();
	} else {
		MessageBoxW(m_hWnd, L"Failed to suspend any threads in the process.", L"Suspend Process", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Failed to suspend process PID " + std::to_string(processId));
	}
}

void MainWindow::ResumeProcess(DWORD processId) {
	std::wstring errorMsg;
	if (!ValidateProcess(processId, errorMsg)) {
		MessageBoxW(m_hWnd, errorMsg.c_str(), L"Resume Process", MB_OK | MB_ICONERROR);
		return;
	}

	if (!ValidateProcessAccess(processId, PROCESS_SUSPEND_RESUME, errorMsg)) {
		MessageBoxW(m_hWnd, errorMsg.c_str(), L"Resume Process", MB_OK | MB_ICONERROR);
		return;
	}

	std::vector<ThreadInfo> threads = m_ProcessManager.EnumerateThreads(processId);
	int resumedCount = 0;
	int failedCount = 0;

	for (const auto& thread : threads) {
		HandleWrapper hThread(OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread.ThreadId));
		if (hThread.IsValid()) {
			DWORD suspendCount = ResumeThread(hThread.Get());
			if (suspendCount != (DWORD)-1) {
				resumedCount++;
			} else {
				failedCount++;
			}
		} else {
			failedCount++;
		}
	}

	if (resumedCount > 0) {
		std::wostringstream oss;
		oss << L"Process resumed successfully.\n\nResumed " << resumedCount << L" thread(s)";
		if (failedCount > 0) {
			oss << L"\nFailed to resume " << failedCount << L" thread(s)";
		}
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Resume Process", MB_OK | MB_ICONINFORMATION);
		Logger::GetInstance().LogInfo("Resumed process PID " + std::to_string(processId));
		RefreshProcessList();
	} else {
		MessageBoxW(m_hWnd, L"Failed to resume any threads in the process.", L"Resume Process", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Failed to resume process PID " + std::to_string(processId));
	}
}

void MainWindow::InjectDll(DWORD processId) {
	std::wstring errorMsg;
	if (!ValidateProcess(processId, errorMsg)) {
		MessageBoxW(m_hWnd, errorMsg.c_str(), L"Inject DLL", MB_OK | MB_ICONERROR);
		return;
	}

	if (!ValidateProcessAccess(processId, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, errorMsg)) {
		MessageBoxW(m_hWnd, errorMsg.c_str(), L"Inject DLL", MB_OK | MB_ICONERROR);
		return;
	}

	ValidateArchitectureCompatibility(processId, errorMsg);

	OPENFILENAMEW ofn = {};
	wchar_t szFile[260] = {};
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = m_hWnd;
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = sizeof(szFile) / sizeof(szFile[0]);
	ofn.lpstrFilter = L"DLL Files\0*.dll\0All Files\0*.*\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = nullptr;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = nullptr;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (!GetOpenFileNameW(&ofn)) {
		return;
	}

	int ansiLen = WideCharToMultiByte(CP_ACP, 0, szFile, -1, nullptr, 0, nullptr, nullptr);
	if (ansiLen <= 0) {
		MessageBoxW(m_hWnd, L"Failed to convert DLL path.", L"Inject DLL", MB_OK | MB_ICONERROR);
		return;
	}

	std::vector<char> ansiPath(ansiLen);
	WideCharToMultiByte(CP_ACP, 0, szFile, -1, &ansiPath[0], ansiLen, nullptr, nullptr);

	HandleWrapper hProcess = m_ProcessManager.OpenProcess(processId, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ);
	if (!hProcess.IsValid()) {
		MessageBoxW(m_hWnd, L"Failed to open process for injection.", L"Inject DLL", MB_OK | MB_ICONERROR);
		return;
	}

	int selectedMethod = SelectInjectionMethod(processId);
	if (selectedMethod == -1) {
		return;
	}

	using namespace WinProcessInspector::Injection;
	bool success = false;
	std::wstring methodUsed;

	switch (selectedMethod) {
		case 0:
			if (InjectViaNtCreateThreadEx(&ansiPath[0], hProcess.Get())) {
				success = true;
				methodUsed = L"NtCreateThreadEx";
			}
			break;
		case 1:
			if (InjectViaQueueUserAPC(&ansiPath[0], hProcess.Get(), processId)) {
				success = true;
				methodUsed = L"QueueUserAPC";
			}
			break;
		case 2:
			if (InjectViaSetWindowsHookEx(processId, &ansiPath[0])) {
				success = true;
				methodUsed = L"SetWindowsHookEx";
			}
			break;
		default:
			MessageBoxW(m_hWnd, L"Invalid injection method selected.", L"Inject DLL", MB_OK | MB_ICONERROR);
			return;
		}

	if (success) {
		std::wostringstream oss;
		oss << L"DLL injected successfully using " << methodUsed << L" method.";
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Inject DLL", MB_OK | MB_ICONINFORMATION);
		int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, methodUsed.c_str(), -1, nullptr, 0, nullptr, nullptr);
		if (sizeNeeded > 0) {
			std::string methodUsedA(sizeNeeded, 0);
			WideCharToMultiByte(CP_UTF8, 0, methodUsed.c_str(), -1, &methodUsedA[0], sizeNeeded, nullptr, nullptr);
			methodUsedA.pop_back();
			Logger::GetInstance().LogInfo("Injected DLL into process PID " + std::to_string(processId) + " using " + methodUsedA);
		}
		RefreshProcessList();
	} else {
		MessageBoxW(m_hWnd, L"Failed to inject DLL. All injection methods failed.\n\nThe process may be protected or incompatible.", L"Inject DLL", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Failed to inject DLL into process PID " + std::to_string(processId));
	}
}

void MainWindow::OpenProcessFileLocation(DWORD processId) {
	ProcessInfo info = m_ProcessManager.GetProcessDetails(processId);
	if (info.ProcessId == 0) {
		MessageBoxW(m_hWnd, L"The process no longer exists.", L"Open File Location", MB_OK | MB_ICONERROR);
		return;
	}

	HandleWrapper hProcess = m_ProcessManager.OpenProcess(processId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
	if (!hProcess.IsValid()) {
		MessageBoxW(m_hWnd, L"Failed to open process.", L"Open File Location", MB_OK | MB_ICONERROR);
		return;
	}

	WCHAR processPath[MAX_PATH] = {};
	DWORD pathLen = MAX_PATH;
	if (QueryFullProcessImageNameW(hProcess.Get(), 0, processPath, &pathLen)) {
		std::wstring dirPath(processPath);
		size_t lastSlash = dirPath.find_last_of(L"\\/");
		if (lastSlash != std::wstring::npos) {
			dirPath = dirPath.substr(0, lastSlash + 1);
		}

		ShellExecuteW(m_hWnd, L"open", L"explorer.exe", (L"/select,\"" + std::wstring(processPath) + L"\"").c_str(), nullptr, SW_SHOWNORMAL);
	} else {
		MessageBoxW(m_hWnd, L"Failed to get process file path.", L"Open File Location", MB_OK | MB_ICONERROR);
	}
}

void MainWindow::CopyProcessId(DWORD processId) {
	std::wostringstream oss;
	oss << processId;
	std::wstring pidStr = oss.str();
	
	if (OpenClipboard(m_hWnd)) {
		EmptyClipboard();
		HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (pidStr.length() + 1) * sizeof(WCHAR));
		if (hMem) {
			LPWSTR pMem = static_cast<LPWSTR>(GlobalLock(hMem));
			if (pMem) {
				wcscpy_s(pMem, pidStr.length() + 1, pidStr.c_str());
				GlobalUnlock(hMem);
				SetClipboardData(CF_UNICODETEXT, hMem);
			} else {
				GlobalFree(hMem);
			}
		}
		CloseClipboard();
	}
}

void MainWindow::CopyProcessName(DWORD processId) {
	auto it = std::find_if(m_Processes.begin(), m_Processes.end(), [processId](const ProcessInfo& p) {
		return p.ProcessId == processId;
	});
	
	if (it != m_Processes.end()) {
		std::wstring nameWStr(it->ProcessName.begin(), it->ProcessName.end());
		
		if (OpenClipboard(m_hWnd)) {
			EmptyClipboard();
			HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (nameWStr.length() + 1) * sizeof(WCHAR));
			if (hMem) {
			LPWSTR pMem = static_cast<LPWSTR>(GlobalLock(hMem));
			if (pMem) {
				wcscpy_s(pMem, nameWStr.length() + 1, nameWStr.c_str());
				GlobalUnlock(hMem);
				SetClipboardData(CF_UNICODETEXT, hMem);
			} else {
				GlobalFree(hMem);
			}
				SetClipboardData(CF_UNICODETEXT, hMem);
			}
			CloseClipboard();
		}
	}
}

std::wstring MainWindow::FormatIntegrityLevel(WinProcessInspector::Security::IntegrityLevel level) {
	return WinProcessInspector::Security::IntegrityLevelToString(level);
}

std::wstring MainWindow::FormatMemorySize(SIZE_T bytes) {
	std::wostringstream oss;
	if (bytes < 1024) {
		oss << bytes << L" B";
	} else if (bytes < 1024 * 1024) {
		oss << std::fixed << std::setprecision(2) << (bytes / 1024.0) << L" KB";
	} else if (bytes < 1024ULL * 1024 * 1024) {
		oss << std::fixed << std::setprecision(2) << (bytes / (1024.0 * 1024.0)) << L" MB";
	} else {
		oss << std::fixed << std::setprecision(2) << (bytes / (1024.0 * 1024.0 * 1024.0)) << L" GB";
	}
	return oss.str();
}

std::wstring MainWindow::FormatTime(const FILETIME& ft) {
	SYSTEMTIME st;
	if (FileTimeToSystemTime(&ft, &st)) {
		std::wostringstream oss;
		oss << std::setfill(L'0') << std::setw(2) << st.wMonth << L"/"
			<< std::setw(2) << st.wDay << L"/" << st.wYear << L" "
			<< std::setw(2) << st.wHour << L":"
			<< std::setw(2) << st.wMinute << L":"
			<< std::setw(2) << st.wSecond;
		return oss.str();
	}
	return L"N/A";
}

void MainWindow::CalculateCpuUsage() {
	ULONGLONG currentTime = GetTickCount64();
	ULONGLONG timeDelta = 0;
	
	if (m_LastCpuUpdateTime > 0) {
		timeDelta = currentTime - m_LastCpuUpdateTime;
		if (timeDelta < 500) {
			return;
		}
	}
	
	FILETIME idleTime, kernelTime, userTime;
	if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
		return;
	}
	
	for (const auto& proc : m_Processes) {
		HandleWrapper hProcess = m_ProcessManager.OpenProcess(proc.ProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
		if (!hProcess.IsValid()) {
			m_ProcessCpuPercent[proc.ProcessId] = 0.0;
			continue;
		}
		
		FILETIME creationTime, exitTime, kernelTimeProc, userTimeProc;
		if (!GetProcessTimes(hProcess.Get(), &creationTime, &exitTime, &kernelTimeProc, &userTimeProc)) {
			m_ProcessCpuPercent[proc.ProcessId] = 0.0;
			continue;
		}
		
		ULONGLONG processTime = ((ULONGLONG)kernelTimeProc.dwHighDateTime << 32) | kernelTimeProc.dwLowDateTime;
		processTime += ((ULONGLONG)userTimeProc.dwHighDateTime << 32) | userTimeProc.dwLowDateTime;
		
		if (m_ProcessCpuTimePrev.find(proc.ProcessId) != m_ProcessCpuTimePrev.end()) {
			ULONGLONG prevTime = m_ProcessCpuTimePrev[proc.ProcessId];
			ULONGLONG deltaTime = processTime - prevTime;
			
			if (timeDelta > 0) {
				double cpuPercent = (static_cast<double>(deltaTime) / static_cast<double>(timeDelta * 10000)) * 100.0;
				if (cpuPercent > 100.0) cpuPercent = 100.0;
				m_ProcessCpuPercent[proc.ProcessId] = cpuPercent;
			} else {
				m_ProcessCpuPercent[proc.ProcessId] = 0.0;
			}
		} else {
			m_ProcessCpuPercent[proc.ProcessId] = 0.0;
		}
		
		m_ProcessCpuTimePrev[proc.ProcessId] = static_cast<DWORD>(processTime & 0xFFFFFFFF);
	}
	
	m_LastCpuUpdateTime = currentTime;
}

void MainWindow::UpdateMemoryUsage() {
	for (const auto& proc : m_Processes) {
		HandleWrapper hProcess = m_ProcessManager.OpenProcess(proc.ProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
		if (!hProcess.IsValid()) {
			m_ProcessMemory[proc.ProcessId] = 0;
			continue;
		}
		
		PROCESS_MEMORY_COUNTERS_EX pmc = {};
		if (GetProcessMemoryInfo(hProcess.Get(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
			m_ProcessMemory[proc.ProcessId] = pmc.PrivateUsage;
		} else {
			m_ProcessMemory[proc.ProcessId] = 0;
		}
	}
}

double MainWindow::GetCpuUsage(DWORD processId) const {
	auto it = m_ProcessCpuPercent.find(processId);
	if (it != m_ProcessCpuPercent.end()) {
		return it->second;
	}
	return 0.0;
}

static struct InjectionDialogData {
	int* pSelectedMethod;
	bool* pDone;
	HWND hDesc;
} g_InjectionDialogData;

static LRESULT CALLBACK InjectionMethodDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	if (uMsg == WM_COMMAND) {
		if (LOWORD(wParam) == IDC_INJECTION_METHOD_LIST && HIWORD(wParam) == LBN_SELCHANGE) {
			HWND hList = GetDlgItem(hDlg, IDC_INJECTION_METHOD_LIST);
			int sel = static_cast<int>(SendMessage(hList, LB_GETCURSEL, 0, 0));
			const wchar_t* descs[] = {
				L"Native API method. More stealthy than CreateRemoteThread, bypasses some hooks. Most reliable option.",
				L"Uses Asynchronous Procedure Calls. Targets first alertable thread. Stealthy but requires alertable state.",
				L"Hook-based injection. Requires DLL to export 'HookProcedure'. May be detected by anti-cheat."
			};
			if (sel >= 0 && sel < 3 && g_InjectionDialogData.hDesc) {
				SetWindowTextW(g_InjectionDialogData.hDesc, descs[sel]);
			}
		}
		if (LOWORD(wParam) == IDC_INJECTION_METHOD_LIST && HIWORD(wParam) == LBN_DBLCLK) {
			HWND hList = GetDlgItem(hDlg, IDC_INJECTION_METHOD_LIST);
			if (g_InjectionDialogData.pSelectedMethod) {
				*g_InjectionDialogData.pSelectedMethod = static_cast<int>(SendMessage(hList, LB_GETCURSEL, 0, 0));
			}
			if (g_InjectionDialogData.pDone) *g_InjectionDialogData.pDone = true;
			DestroyWindow(hDlg);
			return TRUE;
		}
		if (LOWORD(wParam) == IDC_INJECTION_METHOD_OK) {
			HWND hList = GetDlgItem(hDlg, IDC_INJECTION_METHOD_LIST);
			if (g_InjectionDialogData.pSelectedMethod) {
				*g_InjectionDialogData.pSelectedMethod = static_cast<int>(SendMessage(hList, LB_GETCURSEL, 0, 0));
			}
			if (g_InjectionDialogData.pDone) *g_InjectionDialogData.pDone = true;
			DestroyWindow(hDlg);
			return TRUE;
		}
		if (LOWORD(wParam) == IDC_INJECTION_METHOD_CANCEL || LOWORD(wParam) == IDCANCEL) {
			if (g_InjectionDialogData.pDone) *g_InjectionDialogData.pDone = true;
			DestroyWindow(hDlg);
			return TRUE;
		}
	}
	if (uMsg == WM_CLOSE) {
		if (g_InjectionDialogData.pDone) *g_InjectionDialogData.pDone = true;
		DestroyWindow(hDlg);
		return TRUE;
	}
	return DefWindowProc(hDlg, uMsg, wParam, lParam);
}

int MainWindow::SelectInjectionMethod(DWORD processId) {
	const wchar_t* methods[] = {
		L"NtCreateThreadEx (Native API)",
		L"QueueUserAPC (APC-based)",
		L"SetWindowsHookEx (Hook-based)"
	};

	WNDCLASSW wc = {};
	wc.lpfnWndProc = InjectionMethodDialogProc;
	wc.hInstance = m_hInstance;
	wc.lpszClassName = L"InjectionMethodDialog";
	wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
	wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
	RegisterClassW(&wc);

	HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME,
		L"InjectionMethodDialog",
		L"Select Injection Method",
		WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME,
		CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,
		m_hWnd, nullptr, m_hInstance, nullptr);

	if (!hDlg) {
		return 0;
	}

	HWND hList = CreateWindowExW(WS_EX_CLIENTEDGE,
		L"LISTBOX",
		L"",
		WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY,
		10, 10, 360, 200,
		hDlg, reinterpret_cast<HMENU>(IDC_INJECTION_METHOD_LIST), m_hInstance, nullptr);

	HWND hDesc = CreateWindowExW(WS_EX_CLIENTEDGE,
		L"EDIT",
		L"",
		WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
		10, 220, 360, 30,
		hDlg, reinterpret_cast<HMENU>(IDC_INJECTION_METHOD_DESCRIPTION), m_hInstance, nullptr);

	HWND hOk = CreateWindowW(L"BUTTON", L"OK",
		WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
		200, 260, 75, 25,
		hDlg, reinterpret_cast<HMENU>(IDC_INJECTION_METHOD_OK), m_hInstance, nullptr);

	HWND hCancel = CreateWindowW(L"BUTTON", L"Cancel",
		WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
		285, 260, 75, 25,
		hDlg, reinterpret_cast<HMENU>(IDC_INJECTION_METHOD_CANCEL), m_hInstance, nullptr);

	HFONT hFont = reinterpret_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
	if (hFont) {
		SendMessage(hList, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);
		SendMessage(hDesc, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);
		SendMessage(hOk, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);
		SendMessage(hCancel, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);
	}

	for (int i = 0; i < 3; ++i) {
		SendMessage(hList, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(methods[i]));
	}
	SendMessage(hList, LB_SETCURSEL, 0, 0);

	const wchar_t* descs[] = {
		L"Native API method. More stealthy than CreateRemoteThread, bypasses some hooks. Most reliable option.",
		L"Uses Asynchronous Procedure Calls. Targets first alertable thread. Stealthy but requires alertable state.",
		L"Hook-based injection. Requires DLL to export 'HookProcedure'. May be detected by anti-cheat."
	};
	SetWindowTextW(hDesc, descs[0]);

	int selectedMethod = -1;
	bool done = false;
	g_InjectionDialogData.pSelectedMethod = &selectedMethod;
	g_InjectionDialogData.pDone = &done;
	g_InjectionDialogData.hDesc = hDesc;

	ShowWindow(hDlg, SW_SHOW);
	UpdateWindow(hDlg);
	SetFocus(hList);

	MSG msg = {};
	while (!done && GetMessage(&msg, nullptr, 0, 0)) {
		if (!IsDialogMessage(hDlg, &msg)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return selectedMethod >= 0 ? selectedMethod : 0;
}

void MainWindow::SearchProcessOnline(DWORD processId) {
	ProcessInfo info = m_ProcessManager.GetProcessDetails(processId);
	if (info.ProcessId == 0) {
		MessageBoxW(m_hWnd, L"The process no longer exists.", L"Search Online", MB_OK | MB_ICONERROR);
		return;
	}

	std::wstring processName(info.ProcessName.begin(), info.ProcessName.end());
	
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
	
	std::wstring query = L"https://duckduckgo.com//search?q=" + encoded;
	ShellExecuteW(nullptr, L"open", query.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void MainWindow::ShowCommandLineDialog(DWORD processId) {
	ProcessInfo info = m_ProcessManager.GetProcessDetails(processId);
	if (info.ProcessId == 0) {
		MessageBoxW(m_hWnd, L"The process no longer exists.", L"Command Line", MB_OK | MB_ICONERROR);
		return;
	}

	std::wstring message;
	message += L"Process: ";
	message += std::wstring(info.ProcessName.begin(), info.ProcessName.end());
	message += L"\nPID: ";
	message += std::to_wstring(info.ProcessId);
	message += L"\n\nCommand Line:\n";
	
	if (info.CommandLine.empty()) {
		message += L"(Not available)";
	} else {
		message += info.CommandLine;
	}
	
	MessageBoxW(m_hWnd, message.c_str(), L"Process Command Line", MB_OK | MB_ICONINFORMATION);
}

void MainWindow::ShowNetworkConnectionsWindow() {
	NetworkManager netMgr;
	auto allConnections = netMgr.EnumerateConnections();
	
	if (allConnections.empty()) {
		MessageBoxW(m_hWnd, L"No active network connections found.", L"Network Connections", MB_OK | MB_ICONINFORMATION);
		return;
	}
	
	std::wstring message = L"System Network Connections\n\n";
	message += L"Total: " + std::to_wstring(allConnections.size()) + L" active connections\n\n";
	message += L"Top 30 connections:\n";
	message += L"─────────────────────────────────────────────────\n\n";
	
	int count = 0;
	for (const auto& conn : allConnections) {
		if (count >= 30) {
			message += L"\n... and " + std::to_wstring(allConnections.size() - 30) + L" more.\n\n";
			message += L"Tip: For per-process connections:\n";
			message += L"Right-click process → Properties → Network tab";
			break;
		}
		
		message += NetworkManager::GetProtocolString(conn.Protocol) + L" | ";
		message += conn.LocalAddress + L":" + std::to_wstring(conn.LocalPort) + L" → ";
		message += conn.RemoteAddress + L":" + std::to_wstring(conn.RemotePort) + L"\n";
		message += L"    State: " + NetworkManager::GetStateString(conn.State);
		message += L" | PID: " + std::to_wstring(conn.ProcessId) + L"\n\n";
		count++;
	}
	
	MessageBoxW(m_hWnd, message.c_str(), L"Network Connections", MB_OK | MB_ICONINFORMATION);
}

void MainWindow::ShowSystemInformationWindow() {
	std::wstring message = L"System Information\n";
	message += L"================================\n\n";
	
	MEMORYSTATUSEX memStatus = {};
	memStatus.dwLength = sizeof(memStatus);
	if (GlobalMemoryStatusEx(&memStatus)) {
		message += L"Physical Memory:\n";
		message += L"  Total: " + std::to_wstring(memStatus.ullTotalPhys / 1024 / 1024) + L" MB\n";
		message += L"  Available: " + std::to_wstring(memStatus.ullAvailPhys / 1024 / 1024) + L" MB\n";
		message += L"  Used: " + std::to_wstring((memStatus.ullTotalPhys - memStatus.ullAvailPhys) / 1024 / 1024) + L" MB\n";
		message += L"  Load: " + std::to_wstring(memStatus.dwMemoryLoad) + L"%\n\n";
	}
	
	SYSTEM_INFO sysInfo = {};
	GetSystemInfo(&sysInfo);
	message += L"Processor:\n";
	message += L"  Count: " + std::to_wstring(sysInfo.dwNumberOfProcessors) + L" logical processors\n";
	message += L"  Architecture: ";
	switch (sysInfo.wProcessorArchitecture) {
		case PROCESSOR_ARCHITECTURE_AMD64: message += L"x64 (AMD64)\n"; break;
		case PROCESSOR_ARCHITECTURE_ARM: message += L"ARM\n"; break;
		case PROCESSOR_ARCHITECTURE_ARM64: message += L"ARM64\n"; break;
		case PROCESSOR_ARCHITECTURE_INTEL: message += L"x86 (Intel)\n"; break;
		default: message += L"Unknown\n"; break;
	}
	message += L"\n";
	
	auto processes = m_ProcessManager.EnumerateAllProcesses();
	DWORD totalThreads = 0;
	DWORD totalHandles = 0;
	SIZE_T totalMemory = 0;
	
	for (const auto& proc : processes) {
		totalThreads += proc.ThreadCount;
		totalHandles += proc.HandleCount;
		auto memIt = m_ProcessMemory.find(proc.ProcessId);
		if (memIt != m_ProcessMemory.end()) {
			totalMemory += memIt->second;
		}
	}
	
	message += L"Process Summary:\n";
	message += L"  Total Processes: " + std::to_wstring(processes.size()) + L"\n";
	message += L"  Total Threads: " + std::to_wstring(totalThreads) + L"\n";
	message += L"  Total Handles: " + std::to_wstring(totalHandles) + L"\n";
	message += L"  Total Memory: " + std::to_wstring(totalMemory / 1024 / 1024) + L" MB\n";
	
	MessageBoxW(m_hWnd, message.c_str(), L"System Information", MB_OK | MB_ICONINFORMATION);
}

void MainWindow::GroupSvchostServices(std::unordered_map<DWORD, std::vector<DWORD>>& processChildren) {
	SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
	if (!hSCManager) {
		return;
	}
	
	DWORD bytesNeeded = 0;
	DWORD servicesReturned = 0;
	DWORD resumeHandle = 0;
	
	if (EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr) || GetLastError() == ERROR_MORE_DATA) {
		if (bytesNeeded > 0 && bytesNeeded < 100 * 1024 * 1024) {
			std::vector<BYTE> buffer(bytesNeeded);
			ENUM_SERVICE_STATUS_PROCESSW* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
			
			if (EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, reinterpret_cast<LPBYTE>(services), bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr)) {
				for (DWORD i = 0; i < servicesReturned; ++i) {
					if (services[i].ServiceStatusProcess.dwProcessId != 0) {
						for (const auto& proc : m_Processes) {
							std::wstring procName(proc.ProcessName.begin(), proc.ProcessName.end());
							std::transform(procName.begin(), procName.end(), procName.begin(), ::towlower);
							
							if (procName == L"svchost.exe" && proc.ProcessId == services[i].ServiceStatusProcess.dwProcessId) {
								processChildren[proc.ProcessId].push_back(proc.ProcessId);
								break;
							}
						}
					}
				}
			}
		}
	}
	
	CloseServiceHandle(hSCManager);
}

void MainWindow::GroupAppContainerProcesses(std::unordered_map<DWORD, std::vector<DWORD>>& processChildren) {
	for (const auto& proc : m_Processes) {
		if (proc.ProcessId == 0) continue;
		
		HandleWrapper hProcess = m_ProcessManager.OpenProcess(proc.ProcessId, PROCESS_QUERY_INFORMATION);
		if (!hProcess.IsValid()) continue;
		
		HANDLE hToken = nullptr;
		if (!OpenProcessToken(hProcess.Get(), TOKEN_QUERY, &hToken)) continue;
		
		DWORD length = 0;
		GetTokenInformation(hToken, TokenAppContainerSid, nullptr, 0, &length);
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && length > 0 && length < 1024) {
			std::vector<BYTE> buffer(length);
			PTOKEN_APPCONTAINER_INFORMATION pAppContainer = reinterpret_cast<PTOKEN_APPCONTAINER_INFORMATION>(buffer.data());
			
			if (GetTokenInformation(hToken, TokenAppContainerSid, pAppContainer, length, &length)) {
				if (pAppContainer->TokenAppContainer != nullptr) {
					LPWSTR sidString = nullptr;
					if (ConvertSidToStringSidW(pAppContainer->TokenAppContainer, &sidString)) {
						std::wstring appContainerSid(sidString);
						LocalFree(sidString);
						
						for (const auto& otherProc : m_Processes) {
							if (otherProc.ProcessId == proc.ProcessId) continue;
							
							HandleWrapper hOtherProcess = m_ProcessManager.OpenProcess(otherProc.ProcessId, PROCESS_QUERY_INFORMATION);
							if (!hOtherProcess.IsValid()) continue;
							
							HANDLE hOtherToken = nullptr;
							if (OpenProcessToken(hOtherProcess.Get(), TOKEN_QUERY, &hOtherToken)) {
								DWORD otherLength = 0;
								GetTokenInformation(hOtherToken, TokenAppContainerSid, nullptr, 0, &otherLength);
								if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && otherLength > 0 && otherLength < 1024) {
									std::vector<BYTE> otherBuffer(otherLength);
									PTOKEN_APPCONTAINER_INFORMATION pOtherAppContainer = reinterpret_cast<PTOKEN_APPCONTAINER_INFORMATION>(otherBuffer.data());
									
									if (GetTokenInformation(hOtherToken, TokenAppContainerSid, pOtherAppContainer, otherLength, &otherLength)) {
										if (pOtherAppContainer->TokenAppContainer != nullptr) {
											LPWSTR otherSidString = nullptr;
											if (ConvertSidToStringSidW(pOtherAppContainer->TokenAppContainer, &otherSidString)) {
												std::wstring otherAppContainerSid(otherSidString);
												LocalFree(otherSidString);
												
												if (appContainerSid == otherAppContainerSid && proc.ProcessId < otherProc.ProcessId) {
													processChildren[proc.ProcessId].push_back(otherProc.ProcessId);
												}
											}
										}
									}
								}
								CloseHandle(hOtherToken);
							}
						}
					}
				}
			}
		}
		
		CloseHandle(hToken);
	}
}

LRESULT MainWindow::OnCustomDraw(LPNMLVCUSTOMDRAW lplvcd) {
	switch (lplvcd->nmcd.dwDrawStage) {
		case CDDS_PREPAINT:
			return CDRF_NOTIFYITEMDRAW;
		
		case CDDS_ITEMPREPAINT:
		{
			LVITEMW lvi = {};
			lvi.iItem = static_cast<int>(lplvcd->nmcd.dwItemSpec);
			lvi.mask = LVIF_PARAM;
			ListView_GetItem(m_hProcessListView, &lvi);
			DWORD processId = static_cast<DWORD>(lvi.lParam);
			
			auto it = std::find_if(m_FilteredProcesses.begin(), m_FilteredProcesses.end(),
				[processId](const ProcessInfo& p) { return p.ProcessId == processId; });
			
			if (it == m_FilteredProcesses.end()) {
				return CDRF_DODEFAULT;
			}
			
			lplvcd->clrText = RGB(0, 0, 0);
			lplvcd->clrTextBk = (lplvcd->nmcd.dwItemSpec % 2) ? RGB(255, 255, 255) : RGB(248, 248, 248);
			
			COLORREF processColor = GetProcessColor(processId, *it);
			if (processColor != RGB(0, 0, 0)) {
				lplvcd->clrText = processColor;
			}
			
			if (processId == m_CurrentProcessId) {
				lplvcd->clrTextBk = RGB(220, 230, 255);
			}
			
			return CDRF_NOTIFYSUBITEMDRAW | CDRF_NEWFONT;
		}
		
		case CDDS_SUBITEM | CDDS_ITEMPREPAINT:
		{
			return CDRF_DODEFAULT;
		}
	}
	
	return CDRF_DODEFAULT;
}

COLORREF MainWindow::GetProcessColor(DWORD processId, const ProcessInfo& info) {
	if (IsSystemProcess(processId)) {
		return RGB(0, 100, 200);
	}
	
	switch (info.IntegrityLevel) {
		case IntegrityLevel::System:
		case IntegrityLevel::High:
			return RGB(200, 0, 0);
		case IntegrityLevel::Low:
			return RGB(0, 128, 0);
		case IntegrityLevel::Untrusted:
			return RGB(160, 100, 0);
		default:
			return RGB(0, 0, 0);
	}
}

void MainWindow::DrawCpuBar(HDC hdc, RECT rect, double cpuPercent) {
	rect.left += 2;
	rect.right -= 2;
	rect.top += 2;
	rect.bottom -= 2;
	
	HBRUSH bgBrush = CreateSolidBrush(RGB(240, 240, 240));
	FillRect(hdc, &rect, bgBrush);
	DeleteObject(bgBrush);
	
	int barWidth = static_cast<int>((rect.right - rect.left) * (cpuPercent / 100.0));
	if (barWidth > 0) {
		RECT barRect = rect;
		barRect.right = barRect.left + barWidth;
		
		COLORREF barColor;
		if (cpuPercent >= 75.0) {
			barColor = RGB(255, 100, 100);
		} else if (cpuPercent >= 50.0) {
			barColor = RGB(255, 200, 80);
		} else if (cpuPercent >= 25.0) {
			barColor = RGB(255, 230, 100);
		} else {
			barColor = RGB(100, 200, 120);
		}
		
		HBRUSH barBrush = CreateSolidBrush(barColor);
		FillRect(hdc, &barRect, barBrush);
		DeleteObject(barBrush);
	}
	
	std::wostringstream oss;
	oss << std::fixed << std::setprecision(1) << cpuPercent << L"%";
	std::wstring text = oss.str();
	
	SetBkMode(hdc, TRANSPARENT);
	SetTextColor(hdc, RGB(0, 0, 0));
	DrawTextW(hdc, text.c_str(), -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

void MainWindow::DrawMemoryBar(HDC hdc, RECT rect, SIZE_T memory, SIZE_T totalMemory) {
	rect.left += 2;
	rect.right -= 2;
	rect.top += 2;
	rect.bottom -= 2;
	
	HBRUSH bgBrush = CreateSolidBrush(RGB(240, 240, 240));
	FillRect(hdc, &rect, bgBrush);
	DeleteObject(bgBrush);
	
	double percent = (double)memory / (double)totalMemory * 100.0;
	int barWidth = static_cast<int>((rect.right - rect.left) * (percent / 100.0));
	
	if (barWidth > 0 && barWidth < (rect.right - rect.left)) {
		RECT barRect = rect;
		barRect.right = barRect.left + barWidth;
		
		COLORREF barColor = RGB(80, 150, 255);
		HBRUSH barBrush = CreateSolidBrush(barColor);
		FillRect(hdc, &barRect, barBrush);
		DeleteObject(barBrush);
	}
	
	std::wstring text = FormatMemorySize(memory);
	
	SetBkMode(hdc, TRANSPARENT);
	SetTextColor(hdc, RGB(0, 0, 0));
	DrawTextW(hdc, text.c_str(), -1, &rect, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
}

bool MainWindow::IsSystemProcess(DWORD processId) {
	auto it = m_SystemProcessCache.find(processId);
	if (it != m_SystemProcessCache.end()) {
		return it->second;
	}
	
	bool isSystem = false;
	if (processId == 0 || processId == 4) {
		isSystem = true;
	} else {
		HandleWrapper hProcess = m_ProcessManager.OpenProcess(processId, PROCESS_QUERY_INFORMATION);
		if (hProcess.IsValid()) {
			WCHAR path[MAX_PATH];
			if (GetProcessImageFileNameW(hProcess.Get(), path, MAX_PATH)) {
				std::wstring pathStr(path);
				std::transform(pathStr.begin(), pathStr.end(), pathStr.begin(), ::towlower);
				if (pathStr.find(L"\\windows\\system32\\") != std::wstring::npos ||
					pathStr.find(L"\\windows\\syswow64\\") != std::wstring::npos) {
					isSystem = true;
				}
			}
		}
	}
	
	m_SystemProcessCache[processId] = isSystem;
	return isSystem;
}

bool MainWindow::IsVerifiedProcess(const std::wstring& imagePath) {
	auto it = m_VerifiedCache.find(imagePath);
	if (it != m_VerifiedCache.end()) {
		return it->second;
	}
	
	bool verified = false;
	
	WINTRUST_FILE_INFO fileInfo = {};
	fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	fileInfo.pcwszFilePath = imagePath.c_str();
	fileInfo.hFile = nullptr;
	fileInfo.pgKnownSubject = nullptr;
	
	GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA trustData = {};
	trustData.cbStruct = sizeof(WINTRUST_DATA);
	trustData.dwUIChoice = WTD_UI_NONE;
	trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	trustData.dwUnionChoice = WTD_CHOICE_FILE;
	trustData.pFile = &fileInfo;
	trustData.dwStateAction = WTD_STATEACTION_VERIFY;
	trustData.dwProvFlags = WTD_SAFER_FLAG;
	
	LONG status = WinVerifyTrust(nullptr, &policyGUID, &trustData);
	verified = (status == ERROR_SUCCESS);
	
	trustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(nullptr, &policyGUID, &trustData);
	
	m_VerifiedCache[imagePath] = verified;
	return verified;
}

std::wstring MainWindow::GetFileDescription(const std::wstring& filePath) {
	auto it = m_DescriptionCache.find(filePath);
	if (it != m_DescriptionCache.end()) {
		return it->second;
	}
	
	std::wstring description;
	
	DWORD handle = 0;
	DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &handle);
	if (size > 0 && size < 10 * 1024 * 1024) {
		std::vector<BYTE> buffer(size);
		if (GetFileVersionInfoW(filePath.c_str(), 0, size, buffer.data())) {
			struct LANGANDCODEPAGE {
				WORD wLanguage;
				WORD wCodePage;
			} *lpTranslate;
			
			UINT cbTranslate;
			if (VerQueryValueW(buffer.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate)) {
				for (UINT i = 0; i < (cbTranslate / sizeof(struct LANGANDCODEPAGE)); i++) {
					wchar_t subBlock[256];
					swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\FileDescription",
						lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);
					
					LPVOID lpBuffer;
					UINT dwBytes;
					if (VerQueryValueW(buffer.data(), subBlock, &lpBuffer, &dwBytes) && dwBytes > 0) {
						description = static_cast<LPCWSTR>(lpBuffer);
						break;
					}
				}
			}
		}
	}
	
	m_DescriptionCache[filePath] = description;
	return description;
}

std::wstring MainWindow::GetFileCompany(const std::wstring& filePath) {
	auto it = m_CompanyCache.find(filePath);
	if (it != m_CompanyCache.end()) {
		return it->second;
	}
	
	std::wstring company;
	
	DWORD handle = 0;
	DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &handle);
	if (size > 0 && size < 10 * 1024 * 1024) {
		std::vector<BYTE> buffer(size);
		if (GetFileVersionInfoW(filePath.c_str(), 0, size, buffer.data())) {
			struct LANGANDCODEPAGE {
				WORD wLanguage;
				WORD wCodePage;
			} *lpTranslate;
			
			UINT cbTranslate;
			if (VerQueryValueW(buffer.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate)) {
				for (UINT i = 0; i < (cbTranslate / sizeof(struct LANGANDCODEPAGE)); i++) {
					wchar_t subBlock[256];
					swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\CompanyName",
						lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);
					
					LPVOID lpBuffer;
					UINT dwBytes;
					if (VerQueryValueW(buffer.data(), subBlock, &lpBuffer, &dwBytes) && dwBytes > 0) {
						company = static_cast<LPCWSTR>(lpBuffer);
						break;
					}
				}
			}
		}
	}
	
	m_CompanyCache[filePath] = company;
	return company;
}
