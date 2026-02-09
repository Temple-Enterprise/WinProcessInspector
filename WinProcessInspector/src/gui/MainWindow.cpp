#include "MainWindow.h"
#include "ProcessPropertiesDialog.h"
#include "../core/ProcessManager.h"
#include "../core/SystemInfo.h"
#include "../utils/Logger.h"
#include "../security/SecurityManager.h"
#include "../injection/InjectionEngine.h"
#include "../../resource.h"
#include <commctrl.h>
#include <shellapi.h>
#include <commdlg.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <chrono>
#include <functional>
#include <unordered_set>
#include <psapi.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")

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
	COL_COUNT
};


MainWindow::MainWindow(HINSTANCE hInstance)
	: m_hWnd(nullptr)
	, m_hInstance(hInstance)
	, m_hProcessListView(nullptr)
	, m_hStatusBar(nullptr)
	, m_hToolbar(nullptr)
	, m_hSearchFilter(nullptr)
	, m_hMenu(nullptr)
	, m_hContextMenu(nullptr)
	, m_hAccel(nullptr)
	, m_SelectedProcessId(0)
	, m_SortColumn(COL_NAME)
	, m_SortAscending(true)
	, m_AutoRefresh(false)
	, m_ToolbarVisible(true)
	, m_RefreshTimerId(0)
	, m_IsRefreshing(false)
	, m_LastRefreshTime(0)
	, m_hProcessIconList(nullptr)
	, m_DefaultIconIndex(-1)
{
}

MainWindow::~MainWindow() {
	Cleanup();
}

bool MainWindow::Initialize() {
	// Step A: Initialize Common Controls
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

	// Step B-D: Create Main Window (includes window class registration and resource loading)
	if (!CreateMainWindow()) {
		// Error already reported in CreateMainWindow
		return false;
	}

	// Step E: Create Menu Bar
	if (!CreateMenuBar()) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create menu bar. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
		Logger::GetInstance().LogWarning("Failed to create menu bar. Error: " + std::to_string(error));
		// Non-critical, continue
	}

	// Step E: Create Toolbar (optional, can be hidden)
	if (!CreateToolbar()) {
		Logger::GetInstance().LogWarning("Failed to create toolbar. Continuing without toolbar.");
		// Non-critical, continue
	}

	// Step E: Create Search/Filter Bar
	if (!CreateSearchFilter()) {
		Logger::GetInstance().LogWarning("Failed to create search filter. Continuing without filter.");
		// Non-critical, continue
	}

	// Step E: Create Process ListView
	if (!CreateProcessListView()) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create process list view. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Error", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Failed to create process list view. Error: " + std::to_string(error));
		return false;
	}

	// Step E: Create Status Bar
	if (!CreateStatusBar()) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create status bar. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
		Logger::GetInstance().LogWarning("Failed to create status bar. Error: " + std::to_string(error));
		// Non-critical, continue
	}

	// Step F: Create keyboard accelerators
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

	// Step G: Trigger initial layout now that all controls are created
	// This ensures ListView accounts for StatusBar height
	RECT rc;
	GetClientRect(m_hWnd, &rc);
	SendMessage(m_hWnd, WM_SIZE, SIZE_RESTORED, MAKELPARAM(rc.right, rc.bottom));

	// Initialize filtered processes
	m_FilteredProcesses = m_Processes;

	RefreshProcessList();
	Logger::GetInstance().LogInfo("Application initialized successfully");
	return true;
}

int MainWindow::Run() {
	MSG msg = {};
	while (GetMessage(&msg, nullptr, 0, 0) > 0) {
		// Handle keyboard accelerators
		if (m_hAccel && TranslateAccelerator(m_hWnd, m_hAccel, &msg)) {
			continue;
		}
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return static_cast<int>(msg.wParam);
}

bool MainWindow::CreateMainWindow() {
	// Validate hInstance
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
	
	// Load cursor (non-critical, use default if fails)
	wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
	if (!wc.hCursor) {
		DWORD error = GetLastError();
		Logger::GetInstance().LogWarning("Failed to load cursor. Error: " + std::to_string(error) + ". Using default.");
		wc.hCursor = LoadCursor(nullptr, IDC_ARROW); // Try again or use system default
	}
	
	// Load icons (non-critical, use defaults if fails)
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

	// Unregister class if it exists (from previous run)
	UnregisterClassW(L"WinProcessInspectorMainWindow", m_hInstance);
	SetLastError(0); // Clear error from UnregisterClass (it's OK if class didn't exist)

	// Register window class
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

	// Verify class exists before creating window
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

	// Create main window
	SetLastError(0); // Clear any previous errors
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
	
	// Ensure title is set (in case CreateWindowExW didn't set it properly)
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

	// Verify window was created successfully
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
	
	// Trigger initial layout
	SendMessage(m_hWnd, WM_SIZE, SIZE_RESTORED, MAKELPARAM(1200, 800));
	
	return true;
}

bool MainWindow::CreateMenuBar() {
	// Verify window is valid before using it
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
	AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_EXPORT, L"&Export...");
	AppendMenuW(hFileMenu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_EXIT, L"E&xit");

	HMENU hViewMenu = CreatePopupMenu();
	if (!hViewMenu) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create View menu. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
		Logger::GetInstance().LogWarning("Failed to create View menu. Error: " + std::to_string(error));
		return false;
	}
	AppendMenuW(hViewMenu, MF_STRING | MF_CHECKED, IDM_VIEW_AUTOREFRESH, L"&Auto Refresh");

	HMENU hHelpMenu = CreatePopupMenu();
	if (!hHelpMenu) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create Help menu. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
		Logger::GetInstance().LogWarning("Failed to create Help menu. Error: " + std::to_string(error));
		return false;
	}
	AppendMenuW(hHelpMenu, MF_STRING, IDM_HELP_ABOUT, L"&About...");

	AppendMenuW(m_hMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(hFileMenu), L"&File");
	AppendMenuW(m_hMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(hViewMenu), L"&View");
	AppendMenuW(m_hMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(hHelpMenu), L"&Help");

	// Set menu on window - verify window is valid first
	if (m_hWnd && IsWindow(m_hWnd)) {
		if (!SetMenu(m_hWnd, m_hMenu)) {
			DWORD error = GetLastError();
			std::wostringstream oss;
			oss << L"Failed to set menu on window. Error: " << error << L" (0x" << std::hex << error << L")";
			MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
			Logger::GetInstance().LogWarning("Failed to set menu on window. Error: " + std::to_string(error));
			// Non-critical, continue
		}
	} else {
		MessageBoxW(nullptr, L"Window handle is invalid when setting menu", L"Initialization Error", MB_OK | MB_ICONERROR);
		Logger::GetInstance().LogError("Window handle is invalid when setting menu");
		return false;
	}

	// Create context menu
	m_hContextMenu = CreatePopupMenu();
	if (!m_hContextMenu) {
		DWORD error = GetLastError();
		std::wostringstream oss;
		oss << L"Failed to create context menu. Error: " << error;
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Initialization Warning", MB_OK | MB_ICONWARNING);
		Logger::GetInstance().LogWarning("Failed to create context menu. Error: " + std::to_string(error));
		// Non-critical, continue
	} else {
		AppendMenuW(m_hContextMenu, MF_STRING, IDM_CONTEXT_PROPERTIES, L"&Properties");
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
	}

	return true;
}

bool MainWindow::CreateProcessListView() {
	// Common controls are already initialized in Initialize()
	// Get client area for initial sizing
	RECT rc;
	GetClientRect(m_hWnd, &rc);
	
	// Create ListView control with proper initial size
	// Note: StatusBar will be created after this, so OnSize will handle final layout
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

	// Set extended styles
	ListView_SetExtendedListViewStyle(m_hProcessListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

	// Create icon image list for process icons (DPI-aware)
	int iconSize = GetSystemMetrics(SM_CXSMICON);
	m_hProcessIconList = ImageList_Create(iconSize, iconSize, ILC_COLOR32 | ILC_MASK, 1, 100);
	if (m_hProcessIconList) {
		// Load default executable icon
		SHFILEINFOW sfi = {};
		SHGetFileInfoW(L".exe", FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES);
		if (sfi.hIcon) {
			m_DefaultIconIndex = ImageList_AddIcon(m_hProcessIconList, sfi.hIcon);
			DestroyIcon(sfi.hIcon);
		}
		// Attach image list to ListView
		ListView_SetImageList(m_hProcessListView, m_hProcessIconList, LVSIL_SMALL);
	}

	// Add columns
	LVCOLUMNW lvc = {};
	lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvc.fmt = LVCFMT_LEFT;

	// Name (with icon) - first column
	lvc.iSubItem = COL_NAME;
	lvc.pszText = const_cast<LPWSTR>(L"Name");
	lvc.cx = 250;
	ListView_InsertColumn(m_hProcessListView, COL_NAME, &lvc);

	// PID
	lvc.iSubItem = COL_PID;
	lvc.pszText = const_cast<LPWSTR>(L"PID");
	lvc.cx = 80;
	ListView_InsertColumn(m_hProcessListView, COL_PID, &lvc);

	// Parent PID
	lvc.iSubItem = COL_PPID;
	lvc.pszText = const_cast<LPWSTR>(L"PPID");
	lvc.cx = 80;
	ListView_InsertColumn(m_hProcessListView, COL_PPID, &lvc);

	// Session
	lvc.iSubItem = COL_SESSION;
	lvc.pszText = const_cast<LPWSTR>(L"Session");
	lvc.cx = 80;
	ListView_InsertColumn(m_hProcessListView, COL_SESSION, &lvc);

	// Integrity
	lvc.iSubItem = COL_INTEGRITY;
	lvc.pszText = const_cast<LPWSTR>(L"Integrity");
	lvc.cx = 100;
	ListView_InsertColumn(m_hProcessListView, COL_INTEGRITY, &lvc);

	// User
	lvc.iSubItem = COL_USER;
	lvc.pszText = const_cast<LPWSTR>(L"User");
	lvc.cx = 150;
	ListView_InsertColumn(m_hProcessListView, COL_USER, &lvc);

	// Architecture
	lvc.iSubItem = COL_ARCHITECTURE;
	lvc.pszText = const_cast<LPWSTR>(L"Architecture");
	lvc.cx = 100;
	ListView_InsertColumn(m_hProcessListView, COL_ARCHITECTURE, &lvc);

	// CPU Usage
	lvc.iSubItem = COL_CPU;
	lvc.pszText = const_cast<LPWSTR>(L"CPU");
	lvc.cx = 80;
	lvc.fmt = LVCFMT_RIGHT;
	ListView_InsertColumn(m_hProcessListView, COL_CPU, &lvc);
	lvc.fmt = LVCFMT_LEFT; // Reset for other columns

	// Private Memory
	lvc.iSubItem = COL_MEMORY;
	lvc.pszText = const_cast<LPWSTR>(L"Memory");
	lvc.cx = 100;
	lvc.fmt = LVCFMT_RIGHT;
	ListView_InsertColumn(m_hProcessListView, COL_MEMORY, &lvc);
	lvc.fmt = LVCFMT_LEFT; // Reset for other columns

	// Description
	lvc.iSubItem = COL_DESCRIPTION;
	lvc.pszText = const_cast<LPWSTR>(L"Description");
	lvc.cx = 200;
	ListView_InsertColumn(m_hProcessListView, COL_DESCRIPTION, &lvc);

	// Image Path
	lvc.iSubItem = COL_IMAGEPATH;
	lvc.pszText = const_cast<LPWSTR>(L"Image Path");
	lvc.cx = 300;
	ListView_InsertColumn(m_hProcessListView, COL_IMAGEPATH, &lvc);

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
	// Create toolbar control
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

	// Send TB_BUTTONSTRUCTSIZE message
	SendMessage(m_hToolbar, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);

	// Set toolbar image list (using icon resources per directive)
	HIMAGELIST hImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 3, 0);
	if (hImageList) {
		// Load icon resources (Windows selects appropriate size automatically)
		HICON hIconRefresh = static_cast<HICON>(LoadImage(m_hInstance, MAKEINTRESOURCE(IDI_REFRESH), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
		HICON hIconProperties = static_cast<HICON>(LoadImage(m_hInstance, MAKEINTRESOURCE(IDI_PROPERTIES), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
		HICON hIconSearch = static_cast<HICON>(LoadImage(m_hInstance, MAKEINTRESOURCE(IDI_SEARCH), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
		
		// Use actual icons if loaded, otherwise fallback to system icons
		if (!hIconRefresh) hIconRefresh = LoadIcon(nullptr, IDI_APPLICATION);
		if (!hIconProperties) hIconProperties = LoadIcon(nullptr, IDI_APPLICATION);
		if (!hIconSearch) hIconSearch = LoadIcon(nullptr, IDI_APPLICATION);
		
		ImageList_AddIcon(hImageList, hIconRefresh);
		ImageList_AddIcon(hImageList, hIconProperties);
		ImageList_AddIcon(hImageList, hIconSearch);
		
		SendMessage(m_hToolbar, TB_SETIMAGELIST, 0, reinterpret_cast<LPARAM>(hImageList));
	}

	// Add buttons
	TBBUTTON buttons[3] = {};
	
	// Refresh button (IDI_REFRESH)
	buttons[0].iBitmap = 0;
	buttons[0].idCommand = IDM_FILE_REFRESH;
	buttons[0].fsState = TBSTATE_ENABLED;
	buttons[0].fsStyle = BTNS_BUTTON;
	buttons[0].dwData = 0;
	buttons[0].iString = 0;

	// Properties button (IDI_PROPERTIES) - opens properties for selected process
	buttons[1].iBitmap = 1;
	buttons[1].idCommand = IDM_CONTEXT_PROPERTIES;
	buttons[1].fsState = TBSTATE_ENABLED;
	buttons[1].fsStyle = BTNS_BUTTON;
	buttons[1].dwData = 0;
	buttons[1].iString = 0;

	// Search/Filter button (IDI_SEARCH) - focuses search field
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
	// Create search icon (static control with icon)
	HWND hSearchIcon = CreateWindowExW(
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
	
	if (hSearchIcon) {
		// Load search icon
		HICON hIcon = static_cast<HICON>(LoadImage(m_hInstance, MAKEINTRESOURCE(IDI_SEARCH), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
		if (hIcon) {
			SendMessage(hSearchIcon, STM_SETICON, reinterpret_cast<WPARAM>(hIcon), 0);
		}
	}

	// Create label
	HWND hLabel = CreateWindowExW(
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

	// Create edit control for search/filter
	m_hSearchFilter = CreateWindowExW(
		WS_EX_CLIENTEDGE,
		L"EDIT",
		L"",
		WS_VISIBLE | WS_CHILD | ES_LEFT | ES_AUTOHSCROLL,
		70, 0, 300, 22,
		m_hWnd,
		reinterpret_cast<HMENU>(IDC_SEARCH_FILTER),
		m_hInstance,
		nullptr
	);

	if (!m_hSearchFilter) {
		return false;
	}

	// Set placeholder text hint (via EM_SETCUEBANNER if available)
	SendMessage(m_hSearchFilter, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"Search by name or PID..."));

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
			// Return TRUE to allow window creation to continue
			return TRUE;
		}
		// If lpCreateParams is NULL or invalid, window creation should fail
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
	// Trigger initial layout after all controls are created
	// This ensures ListView and StatusBar are properly sized
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

	// Resize toolbar if visible
	int toolbarHeight = 0;
	if (m_hToolbar && IsWindow(m_hToolbar) && m_ToolbarVisible) {
		SendMessage(m_hToolbar, WM_SIZE, 0, 0);
		RECT rcToolbar;
		if (GetWindowRect(m_hToolbar, &rcToolbar)) {
			toolbarHeight = rcToolbar.bottom - rcToolbar.top;
			yPos += toolbarHeight;
		}
	}

	// Resize search filter (always visible, below toolbar)
	int searchHeight = 22; // Default height
	if (m_hSearchFilter && IsWindow(m_hSearchFilter)) {
		RECT rcSearch;
		if (GetWindowRect(m_hSearchFilter, &rcSearch)) {
			searchHeight = rcSearch.bottom - rcSearch.top;
		}
		SetWindowPos(m_hSearchFilter, nullptr, 0, yPos, rc.right - rc.left, searchHeight, SWP_NOZORDER | SWP_NOACTIVATE);
		ShowWindow(m_hSearchFilter, SW_SHOW);
		yPos += searchHeight;
	}

	// Resize status bar first (it needs to know its size)
	int statusBarHeight = 0;
	if (m_hStatusBar && IsWindow(m_hStatusBar)) {
		// Status bar handles its own sizing via WM_SIZE
		SendMessage(m_hStatusBar, WM_SIZE, 0, 0);
		
		// Get status bar height using client rect (more reliable)
		RECT rcStatus;
		if (GetClientRect(m_hStatusBar, &rcStatus)) {
			statusBarHeight = rcStatus.bottom - rcStatus.top;
		} else {
			// Fallback: use GetWindowRect and convert
			RECT rcStatusWindow;
			if (GetWindowRect(m_hStatusBar, &rcStatusWindow)) {
				statusBarHeight = rcStatusWindow.bottom - rcStatusWindow.top;
			}
		}
		rc.bottom -= statusBarHeight;
	}

	// Resize process list to fill remaining client area
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
			// Ensure ListView is visible and redrawn
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
			PostMessage(m_hWnd, WM_CLOSE, 0, 0);
			break;
		case IDM_VIEW_AUTOREFRESH:
			OnViewAutoRefresh();
			break;
		case IDM_VIEW_TOOLBAR:
			OnViewToolbar();
			break;
		case IDM_HELP_ABOUT:
			OnHelpAbout();
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
		default:
			break;
	}
	return 0;
}

LRESULT MainWindow::OnNotify(WPARAM wParam, LPARAM lParam) {
	NMHDR* pnmh = reinterpret_cast<NMHDR*>(lParam);
	
	if (pnmh->idFrom == IDC_PROCESS_LIST) {
		if (pnmh->code == NM_DBLCLK) {
			OnProcessListDoubleClick();
		} else if (pnmh->code == LVN_ITEMCHANGED) {
			OnProcessListSelectionChanged();
		} else if (pnmh->code == LVN_COLUMNCLICK) {
			NMLISTVIEW* pnmv = reinterpret_cast<NMLISTVIEW*>(lParam);
			SortProcessList(pnmv->iSubItem, m_SortColumn == pnmv->iSubItem ? !m_SortAscending : true);
		} else if (pnmh->code == NM_CLICK) {
			// Handle expand/collapse on name column click
			NMLISTVIEW* pnmv = reinterpret_cast<NMLISTVIEW*>(lParam);
			if (pnmv->iSubItem == COL_NAME) {
				LVITEMW lvi = {};
				lvi.iItem = pnmv->iItem;
				lvi.mask = LVIF_PARAM;
				ListView_GetItem(m_hProcessListView, &lvi);
				DWORD processId = static_cast<DWORD>(lvi.lParam);
				
				// Toggle expansion state
				m_ExpandedProcesses[processId] = !m_ExpandedProcesses[processId];
				UpdateProcessList();
			}
		}
	} else if (pnmh->idFrom == IDC_TOOLBAR && pnmh->code == TTN_GETDISPINFO) {
		// Toolbar tooltip notification
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
	// Prevent concurrent refreshes
	if (m_IsRefreshing) {
		return;
	}

	// Throttle refresh rate (minimum 1 second between refreshes)
	DWORD currentTime = GetTickCount();
	if (m_LastRefreshTime > 0 && (currentTime - m_LastRefreshTime) < 1000) {
		return;
	}

	m_IsRefreshing = true;
	m_LastRefreshTime = currentTime;

	// Run refresh in background thread to keep UI responsive
	std::thread refreshThread([this]() {
		std::vector<ProcessInfo> processes = m_ProcessManager.EnumerateAllProcesses();
		
		// Post result back to UI thread
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
			// Handle keyboard shortcuts
			if (wParam == VK_F5) {
				RefreshProcessList();
				return 0;
			}
			if (wParam == VK_ESCAPE && GetFocus() == m_hSearchFilter) {
				SetWindowTextW(m_hSearchFilter, L"");
				m_FilterText.clear();
				UpdateProcessList();
				return 0;
			}
			if (wParam == VK_RETURN && GetFocus() == m_hProcessListView && m_SelectedProcessId) {
				ShowProcessProperties(m_SelectedProcessId);
				return 0;
			}
			break;
		case WM_USER + 1:
			// Refresh completed
			{
				std::vector<ProcessInfo>* processes = reinterpret_cast<std::vector<ProcessInfo>*>(lParam);
				if (processes) {
					m_Processes = std::move(*processes);
					delete processes;
					
					UpdateProcessList();
					
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

	// Check cache first
	auto it = m_IconCache.find(imagePath);
	if (it != m_IconCache.end()) {
		return it->second;
	}

	// Extract icon using Shell API (non-blocking, uses cached file info)
	SHFILEINFOW sfi = {};
	DWORD_PTR result = SHGetFileInfoW(
		imagePath.c_str(),
		FILE_ATTRIBUTE_NORMAL,
		&sfi,
		sizeof(sfi),
		SHGFI_ICON | SHGFI_SMALLICON | SHGFI_SYSICONINDEX
	);

	int iconIndex = m_DefaultIconIndex;
	if (result && sfi.hIcon) {
		// Add icon to image list
		iconIndex = ImageList_AddIcon(m_hProcessIconList, sfi.hIcon);
		if (iconIndex >= 0) {
			// Cache the index
			m_IconCache[imagePath] = iconIndex;
		} else {
			iconIndex = m_DefaultIconIndex;
		}
		DestroyIcon(sfi.hIcon);
	}

	return iconIndex;
}

void MainWindow::BuildProcessHierarchy() {
	// Build parent-child map from ALL processes (not filtered)
	m_ProcessChildren.clear();
	m_ProcessDepth.clear();
	std::unordered_map<DWORD, const ProcessInfo*> processMap; // PID -> ProcessInfo*
	std::vector<const ProcessInfo*> rootProcesses;
	
	// First pass: build process map and identify roots
	for (const auto& proc : m_Processes) {
		processMap[proc.ProcessId] = &proc;
		
		if (proc.ParentProcessId == 0 || proc.ParentProcessId == proc.ProcessId) {
			rootProcesses.push_back(&proc);
		} else {
			// Add to parent's children list
			m_ProcessChildren[proc.ParentProcessId].push_back(proc.ProcessId);
		}
	}
	
	// Handle orphaned processes (parent doesn't exist)
	for (const auto& proc : m_Processes) {
		if (proc.ParentProcessId != 0 && proc.ParentProcessId != proc.ProcessId) {
			if (processMap.find(proc.ParentProcessId) == processMap.end()) {
				// Parent doesn't exist - treat as root
				rootProcesses.push_back(&proc);
			}
		}
	}
	
	// Build filtered set that respects hierarchy
	std::unordered_set<DWORD> visibleProcesses; // Processes that should be visible
	
	// Helper to mark process and all ancestors as visible
	auto markVisible = [&](DWORD pid) {
		DWORD currentPid = pid;
		while (currentPid != 0) {
			if (processMap.find(currentPid) != processMap.end()) {
				visibleProcesses.insert(currentPid);
				const ProcessInfo* proc = processMap[currentPid];
				currentPid = proc->ParentProcessId;
				if (currentPid == proc->ProcessId) break; // Self-parent
			} else {
				break;
			}
		}
	};
	
	// If filtering, mark matching processes and their ancestors
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
					// Check image path (safely, don't crash if process is gone)
					// Only check if we have access - use a lightweight check
					HandleWrapper hProcess = m_ProcessManager.OpenProcess(proc.ProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
					if (hProcess.IsValid()) {
						WCHAR imagePath[MAX_PATH] = {};
						DWORD pathLen = MAX_PATH;
						if (QueryFullProcessImageNameW(hProcess.Get(), 0, imagePath, &pathLen)) {
							std::wstring imagePathStr(imagePath);
							std::transform(imagePathStr.begin(), imagePathStr.end(), imagePathStr.begin(), ::towlower);
							if (imagePathStr.find(filterLower) != std::wstring::npos) {
								matches = true;
							}
						}
					}
					// If process access fails, just skip image path check (process may have terminated)
				}
			}
			
			if (matches) {
				markVisible(proc.ProcessId);
			}
		}
	} else {
		// No filter - all processes visible
		for (const auto& proc : m_Processes) {
			visibleProcesses.insert(proc.ProcessId);
		}
	}
	
	// Build display list with proper hierarchy
	m_FilteredProcesses.clear();
	std::function<void(const ProcessInfo*, int)> addProcess = [&](const ProcessInfo* proc, int depth) {
		// Only add if visible
		if (visibleProcesses.find(proc->ProcessId) == visibleProcesses.end()) {
			return;
		}
		
		ProcessInfo procCopy = *proc;
		m_FilteredProcesses.push_back(procCopy);
		m_ProcessDepth[proc->ProcessId] = depth;
		
		// Add children if expanded (roots are always expanded)
		bool isExpanded = (depth == 0) || m_ExpandedProcesses[proc->ProcessId];
		if (isExpanded) {
			auto it = m_ProcessChildren.find(proc->ProcessId);
			if (it != m_ProcessChildren.end()) {
				// Sort children by PID for consistent display
				std::vector<DWORD> sortedChildren = it->second;
				std::sort(sortedChildren.begin(), sortedChildren.end());
				
				for (DWORD childPid : sortedChildren) {
					auto childIt = processMap.find(childPid);
					if (childIt != processMap.end()) {
						addProcess(childIt->second, depth + 1);
					}
				}
			}
		}
	};
	
	// Sort roots by PID for consistent display
	std::sort(rootProcesses.begin(), rootProcesses.end(), 
		[](const ProcessInfo* a, const ProcessInfo* b) { return a->ProcessId < b->ProcessId; });
	
	// Add all root processes
	for (const auto* root : rootProcesses) {
		addProcess(root, 0);
	}
}

void MainWindow::UpdateProcessList() {
	if (!m_hProcessListView) return;

	ListView_DeleteAllItems(m_hProcessListView);

	// Build hierarchical structure (which handles filtering internally)
	BuildProcessHierarchy();

	// Use filtered processes for display (already in hierarchical order)
	for (size_t i = 0; i < m_FilteredProcesses.size(); ++i) {
		const auto& proc = m_FilteredProcesses[i];

		// Get process image path and icon
		std::wstring imagePath = GetProcessImagePath(proc.ProcessId);
		int iconIndex = GetProcessIconIndex(imagePath);

		// Get tree depth for this process (default to 0 if not found)
		int depth = 0;
		auto depthIt = m_ProcessDepth.find(proc.ProcessId);
		if (depthIt != m_ProcessDepth.end()) {
			depth = depthIt->second;
		}
		
		// Check if process has children (from full process list)
		bool hasChildren = m_ProcessChildren.find(proc.ProcessId) != m_ProcessChildren.end() && 
		                  !m_ProcessChildren[proc.ProcessId].empty();
		
		// Build display name with proper indentation and expand/collapse indicator
		std::wstring nameWStr(proc.ProcessName.begin(), proc.ProcessName.end());
		std::wstring displayName;
		
		// Add indentation based on depth (4 spaces per level)
		for (int d = 0; d < depth; ++d) {
			displayName += L"    ";
		}
		
		// Add expand/collapse indicator
		if (hasChildren) {
			displayName += m_ExpandedProcesses[proc.ProcessId] ? L"[-] " : L"[+] ";
		} else {
			displayName += L"    "; // Indent for visual alignment
		}
		displayName += nameWStr;

		// Name (with icon) - first column
		LVITEMW lvi = {};
		lvi.mask = LVIF_TEXT | LVIF_PARAM | LVIF_IMAGE;
		lvi.iItem = static_cast<int>(i);
		lvi.lParam = proc.ProcessId;
		lvi.iImage = iconIndex;
		lvi.pszText = const_cast<LPWSTR>(displayName.c_str());
		lvi.iSubItem = COL_NAME;
		ListView_InsertItem(m_hProcessListView, &lvi);

		// PID
		std::wostringstream pidStr;
		pidStr << proc.ProcessId;
		std::wstring pidWStr = pidStr.str();
		ListView_SetItemText(m_hProcessListView, i, COL_PID, const_cast<LPWSTR>(pidWStr.c_str()));

		// Parent PID
		std::wostringstream ppidStr;
		ppidStr << proc.ParentProcessId;
		std::wstring ppidWStr = ppidStr.str();
		ListView_SetItemText(m_hProcessListView, i, COL_PPID, const_cast<LPWSTR>(ppidWStr.c_str()));

		// Session
		std::wostringstream sessionStr;
		sessionStr << proc.SessionId;
		std::wstring sessionWStr = sessionStr.str();
		ListView_SetItemText(m_hProcessListView, i, COL_SESSION, const_cast<LPWSTR>(sessionWStr.c_str()));

		// Integrity
		std::wstring integrityStr = FormatIntegrityLevel(proc.IntegrityLevel);
		ListView_SetItemText(m_hProcessListView, i, COL_INTEGRITY, const_cast<LPWSTR>(integrityStr.c_str()));

		// User
		std::wstring userStr = proc.UserName.empty() ? L"N/A" : proc.UserName;
		ListView_SetItemText(m_hProcessListView, i, COL_USER, const_cast<LPWSTR>(userStr.c_str()));

		// Architecture
		std::wstring archWStr(proc.Architecture.begin(), proc.Architecture.end());
		ListView_SetItemText(m_hProcessListView, i, COL_ARCHITECTURE, const_cast<LPWSTR>(archWStr.c_str()));

		// CPU Usage
		std::wstring cpuStr = L"0%"; // TODO: Calculate actual CPU usage
		ListView_SetItemText(m_hProcessListView, i, COL_CPU, const_cast<LPWSTR>(cpuStr.c_str()));

		// Private Memory
		std::wstring memoryStr = L"N/A";
		auto memIt = m_ProcessMemory.find(proc.ProcessId);
		if (memIt != m_ProcessMemory.end() && memIt->second > 0) {
			memoryStr = FormatMemorySize(memIt->second);
		}
		ListView_SetItemText(m_hProcessListView, i, COL_MEMORY, const_cast<LPWSTR>(memoryStr.c_str()));

		ListView_SetItemText(m_hProcessListView, i, COL_DESCRIPTION, const_cast<LPWSTR>(L"N/A"));

		// Image Path
		std::wstring imagePathStr = imagePath.empty() ? L"N/A" : imagePath;
		ListView_SetItemText(m_hProcessListView, i, COL_IMAGEPATH, const_cast<LPWSTR>(imagePathStr.c_str()));
	}
}

void MainWindow::SortProcessList(int column, bool ascending) {
	m_SortColumn = column;
	m_SortAscending = ascending;

	// Simple sort implementation
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
				// Sort by name for these columns (would need ProcessManager enhancement for actual values)
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
	} else {
		m_SelectedProcessId = 0;
	}
}

void MainWindow::ShowProcessContextMenu(int x, int y) {
	if (m_SelectedProcessId == 0) return;

	POINT pt = { x, y };
	if (pt.x == -1 && pt.y == -1) {
		// Keyboard context menu
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

void MainWindow::OnFileExport() {
	MessageBoxW(m_hWnd, L"Export functionality not yet implemented", L"WinProcessInspector", MB_OK | MB_ICONINFORMATION);
}

void MainWindow::OnViewAutoRefresh() {
	m_AutoRefresh = !m_AutoRefresh;
	
	// Get View menu (index 1: File=0, View=1, Help=2)
	HMENU hViewMenu = GetSubMenu(m_hMenu, 1);
	if (hViewMenu) {
		CheckMenuItem(hViewMenu, IDM_VIEW_AUTOREFRESH, m_AutoRefresh ? MF_CHECKED : MF_UNCHECKED);
	}

	if (m_AutoRefresh) {
		m_RefreshTimerId = SetTimer(m_hWnd, IDT_REFRESH_TIMER, 2000, nullptr); // Refresh every 2 seconds
	} else {
		if (m_RefreshTimerId) {
			KillTimer(m_hWnd, m_RefreshTimerId);
			m_RefreshTimerId = 0;
		}
	}
}

void MainWindow::OnViewToolbar() {
	m_ToolbarVisible = !m_ToolbarVisible;

	HMENU hViewMenu = GetSubMenu(m_hMenu, 1);
	if (hViewMenu) {
		CheckMenuItem(hViewMenu, IDM_VIEW_TOOLBAR, m_ToolbarVisible ? MF_CHECKED : MF_UNCHECKED);
	}

	if (m_hToolbar && IsWindow(m_hToolbar)) {
		ShowWindow(m_hToolbar, m_ToolbarVisible ? SW_SHOW : SW_HIDE);
		SendMessage(m_hWnd, WM_SIZE, 0, 0); // Trigger layout update
	}
}

void MainWindow::OnHelpAbout() {
	MessageBoxW(m_hWnd, L"WinProcessInspector\n\nA professional Windows system inspection tool.", L"About WinProcessInspector", MB_OK | MB_ICONINFORMATION);
}

void MainWindow::ShowProcessProperties(DWORD processId) {
	if (!m_PropertiesDialog) {
		m_PropertiesDialog = std::make_unique<ProcessPropertiesDialog>(m_hInstance, m_hWnd);
	}
	m_PropertiesDialog->Show(processId);
}

bool MainWindow::ValidateProcess(DWORD processId, std::wstring& errorMsg) {
	// Check if process still exists
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
	
	// Check if architectures match
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
	IntegrityLevel currentLevel = secMgr.GetProcessIntegrityLevel(0); // 0 = current process
	
	// Check if target process has higher integrity
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

	// Suspend all threads in the process
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

	// Resume all threads in the process
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

	ValidateArchitectureCompatibility(processId, errorMsg); // Warning only

	// Open file dialog to select DLL
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
		return; // User cancelled
	}

	// Convert DLL path to ANSI (injection layer uses ANSI)
	int ansiLen = WideCharToMultiByte(CP_ACP, 0, szFile, -1, nullptr, 0, nullptr, nullptr);
	if (ansiLen <= 0) {
		MessageBoxW(m_hWnd, L"Failed to convert DLL path.", L"Inject DLL", MB_OK | MB_ICONERROR);
		return;
	}

	std::vector<char> ansiPath(ansiLen);
	WideCharToMultiByte(CP_ACP, 0, szFile, -1, &ansiPath[0], ansiLen, nullptr, nullptr);

	// Open process handle for injection
	HandleWrapper hProcess = m_ProcessManager.OpenProcess(processId, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ);
	if (!hProcess.IsValid()) {
		MessageBoxW(m_hWnd, L"Failed to open process for injection.", L"Inject DLL", MB_OK | MB_ICONERROR);
		return;
	}

	// Try injection methods in order of reliability
	using namespace WinProcessInspector::Injection;
	bool success = false;
	std::wstring methodUsed;

	if (InjectViaCreateRemoteThread(&ansiPath[0], hProcess.Get())) {
		success = true;
		methodUsed = L"CreateRemoteThread";
	} else if (InjectViaNtCreateThreadEx(&ansiPath[0], hProcess.Get())) {
		success = true;
		methodUsed = L"NtCreateThreadEx";
	} else if (InjectViaRtlCreateUserThread(hProcess.Get(), &ansiPath[0])) {
		success = true;
		methodUsed = L"RtlCreateUserThread";
	} else if (InjectViaQueueUserAPC(&ansiPath[0], hProcess.Get(), processId)) {
		success = true;
		methodUsed = L"QueueUserAPC";
	}

	if (success) {
		std::wostringstream oss;
		oss << L"DLL injected successfully using " << methodUsed << L" method.";
		MessageBoxW(m_hWnd, oss.str().c_str(), L"Inject DLL", MB_OK | MB_ICONINFORMATION);
		Logger::GetInstance().LogInfo("Injected DLL into process PID " + std::to_string(processId) + " using " + std::string(methodUsed.begin(), methodUsed.end()));
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
		// Extract directory path
		std::wstring dirPath(processPath);
		size_t lastSlash = dirPath.find_last_of(L"\\/");
		if (lastSlash != std::wstring::npos) {
			dirPath = dirPath.substr(0, lastSlash + 1);
		}

		// Open folder in Explorer
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
			wcscpy_s(pMem, pidStr.length() + 1, pidStr.c_str());
			GlobalUnlock(hMem);
			SetClipboardData(CF_UNICODETEXT, hMem);
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
				wcscpy_s(pMem, nameWStr.length() + 1, nameWStr.c_str());
				GlobalUnlock(hMem);
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
