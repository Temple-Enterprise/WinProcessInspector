#include "MainWindow.h"
#include "../core/ProcessManager.h"
#include "../injection/InjectionEngine.h"

#include "external/imgui/imgui.h"
#include "external/imgui/backends/imgui_impl_win32.h"
#include "external/imgui/backends/imgui_impl_dx11.h"
#include <shellapi.h>
#include <psapi.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include "../../resource.h"

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "psapi.lib")

using namespace RuntimeInspector::GUI;
using namespace RuntimeInspector::Core;
using namespace RuntimeInspector::Injection;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

MainWindow::MainWindow(HINSTANCE hInstance)
	: m_hWnd(nullptr)
	, m_hInstance(hInstance)
	, m_bRunning(true)
	, m_pImGuiContext(nullptr)
	, m_Renderer(std::make_unique<DirectXRenderer>())
	, m_SelectedProcessIndex(-1)
	, m_SelectedInjectionMethod(0)
	, m_AutoRefresh(false)
	, m_ShowProcessDetails(false)
	, m_ShowThreadManager(false)
	, m_ShowModuleInspector(false)
	, m_ShowMemoryAnalyzer(false)
	, m_ShowProcessProperties(false)
{
	m_DllPathBuffer[0] = '\0';
	m_ProcessFilter[0] = '\0';
	m_MemoryAddressBuffer[0] = '\0';
	m_MemorySizeBuffer[0] = '\0';
	m_SearchStringBuffer[0] = '\0';
	m_StatusMessage = "Ready";
	memset(&m_CurrentProcessDetails, 0, sizeof(m_CurrentProcessDetails));
	
	Logger::GetInstance().LogInfo("Runtime Inspector initialized");
}

MainWindow::~MainWindow() {
	Cleanup();
}

bool MainWindow::Initialize() {
	if (!CreateMainWindow()) {
		Logger::GetInstance().LogError("Failed to create main window");
		return false;
	}

	if (!m_Renderer->Initialize(m_hWnd)) {
		Logger::GetInstance().LogError("Failed to initialize DirectX renderer");
		return false;
	}

	if (!InitializeImGui()) {
		Logger::GetInstance().LogError("Failed to initialize ImGui");
		return false;
	}

	RefreshProcessList();
	Logger::GetInstance().LogInfo("Application initialized successfully");
	return true;
}

bool MainWindow::CreateMainWindow() {
	WNDCLASSEXW wc = {};
	wc.cbSize = sizeof(WNDCLASSEXW);
	wc.style = CS_HREDRAW | CS_VREDRAW;
	wc.lpfnWndProc = WindowProc;
	wc.hInstance = m_hInstance;
	wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wc.lpszClassName = L"RuntimeInspectorMainWindow";
	HICON hIcon = (HICON)LoadImage(m_hInstance, MAKEINTRESOURCE(IDI_MAIN_ICON), IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), 0);
	HICON hIconSm = (HICON)LoadImage(m_hInstance, MAKEINTRESOURCE(IDI_MAIN_ICON), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
	if (!hIcon) {
		hIcon = LoadIcon(nullptr, IDI_APPLICATION);
	}
	if (!hIconSm) {
		hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
	}
	wc.hIcon = hIcon;
	wc.hIconSm = hIconSm;

	RegisterClassExW(&wc);

	m_hWnd = ::CreateWindowExW(
		WS_EX_APPWINDOW,
		L"RuntimeInspectorMainWindow",
		L"Runtime Inspector",
		WS_POPUP | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX,
		100, 100, 1000, 700,
		nullptr,
		nullptr,
		m_hInstance,
		this
	);
	
	if (!m_hWnd) {
		return false;
	}

	SetWindowTextW(m_hWnd, L"Runtime Inspector");
	if (hIcon) {
		SendMessageW(m_hWnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
	}
	if (hIconSm) {
		SendMessageW(m_hWnd, WM_SETICON, ICON_SMALL, (LPARAM)hIconSm);
	}
	
	ShowWindow(m_hWnd, SW_SHOWNORMAL);
	UpdateWindow(m_hWnd);
	
	SetForegroundWindow(m_hWnd);
	SetActiveWindow(m_hWnd);
	SetFocus(m_hWnd);
	
	InvalidateRect(m_hWnd, nullptr, TRUE);
	UpdateWindow(m_hWnd);
	
	return true;
}


bool MainWindow::InitializeImGui() {
	IMGUI_CHECKVERSION();
	m_pImGuiContext = ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO();
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

	char windowsPath[MAX_PATH];
	if (GetWindowsDirectoryA(windowsPath, MAX_PATH) > 0) {
		char fontPath[MAX_PATH];
		sprintf_s(fontPath, "%s\\Fonts\\segoeui.ttf", windowsPath);
		if (GetFileAttributesA(fontPath) != INVALID_FILE_ATTRIBUTES) {
			io.Fonts->AddFontFromFileTTF(fontPath, Config::UI_FONT_SIZE);
		}
		sprintf_s(fontPath, "%s\\Fonts\\segoeuib.ttf", windowsPath);
		if (GetFileAttributesA(fontPath) != INVALID_FILE_ATTRIBUTES) {
			io.Fonts->AddFontFromFileTTF(fontPath, Config::UI_TITLE_FONT_SIZE);
		}
	}

	ImGuiStyle& style = ImGui::GetStyle();
	style.WindowPadding = ImVec2(Config::UI_WINDOW_PADDING_X, Config::UI_WINDOW_PADDING_Y);
	style.FramePadding = ImVec2(Config::UI_FRAME_PADDING_X, Config::UI_FRAME_PADDING_Y);
	style.ItemSpacing = ImVec2(Config::UI_ITEM_SPACING_X, Config::UI_ITEM_SPACING_Y);
	style.ItemInnerSpacing = ImVec2(6, 4);
	style.WindowRounding = 0.0f;
	style.FrameRounding = 0.0f;
	style.ScrollbarSize = 14.0f;
	style.ScrollbarRounding = 0.0f;
	style.GrabMinSize = 12.0f;
	style.GrabRounding = 0.0f;
	style.ChildRounding = 0.0f;
	style.PopupRounding = 0.0f;
	style.TabRounding = 0.0f;
	style.WindowBorderSize = 0.0f;
	style.FrameBorderSize = 0.0f;
	style.PopupBorderSize = 1.0f;
	style.ChildBorderSize = 1.0f;

	ImVec4* colors = style.Colors;
	colors[ImGuiCol_Text] = ImVec4(Config::UI_COLOR_TEXT_R, Config::UI_COLOR_TEXT_G, Config::UI_COLOR_TEXT_B, 1.00f);
	colors[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
	colors[ImGuiCol_WindowBg] = ImVec4(Config::UI_COLOR_WINDOW_BG_R, Config::UI_COLOR_WINDOW_BG_G, Config::UI_COLOR_WINDOW_BG_B, 1.00f);
	colors[ImGuiCol_ChildBg] = ImVec4(0.09f, 0.09f, 0.11f, 1.00f);
	colors[ImGuiCol_PopupBg] = ImVec4(0.15f, 0.15f, 0.18f, 0.95f);
	colors[ImGuiCol_Border] = ImVec4(0.25f, 0.25f, 0.30f, 1.00f);
	colors[ImGuiCol_FrameBg] = ImVec4(0.16f, 0.16f, 0.19f, 1.00f);
	colors[ImGuiCol_FrameBgHovered] = ImVec4(0.22f, 0.22f, 0.27f, 1.00f);
	colors[ImGuiCol_FrameBgActive] = ImVec4(0.28f, 0.28f, 0.33f, 1.00f);
	colors[ImGuiCol_TitleBg] = ImVec4(0.13f, 0.13f, 0.15f, 1.00f);
	colors[ImGuiCol_TitleBgActive] = ImVec4(0.16f, 0.16f, 0.19f, 1.00f);
	colors[ImGuiCol_MenuBarBg] = ImVec4(0.13f, 0.13f, 0.15f, 1.00f);
	colors[ImGuiCol_ScrollbarBg] = ImVec4(0.09f, 0.09f, 0.11f, 1.00f);
	colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.35f, 0.35f, 0.40f, 1.00f);
	colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.45f, 0.45f, 0.50f, 1.00f);
	colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.55f, 0.55f, 0.60f, 1.00f);
	colors[ImGuiCol_CheckMark] = ImVec4(Config::UI_COLOR_ACCENT_R, Config::UI_COLOR_ACCENT_G, Config::UI_COLOR_ACCENT_B, 1.00f);
	colors[ImGuiCol_SliderGrab] = ImVec4(Config::UI_COLOR_ACCENT_R, Config::UI_COLOR_ACCENT_G, Config::UI_COLOR_ACCENT_B, 1.00f);
	colors[ImGuiCol_SliderGrabActive] = ImVec4(0.50f, 0.75f, 1.00f, 1.00f);
	colors[ImGuiCol_Button] = ImVec4(0.22f, 0.22f, 0.27f, 1.00f);
	colors[ImGuiCol_ButtonHovered] = ImVec4(0.32f, 0.32f, 0.38f, 1.00f);
	colors[ImGuiCol_ButtonActive] = ImVec4(Config::UI_COLOR_ACCENT_R, Config::UI_COLOR_ACCENT_G, Config::UI_COLOR_ACCENT_B, 1.00f);
	colors[ImGuiCol_Header] = ImVec4(0.22f, 0.22f, 0.27f, 1.00f);
	colors[ImGuiCol_HeaderHovered] = ImVec4(0.32f, 0.32f, 0.38f, 1.00f);
	colors[ImGuiCol_HeaderActive] = ImVec4(Config::UI_COLOR_ACCENT_R, Config::UI_COLOR_ACCENT_G, Config::UI_COLOR_ACCENT_B, 1.00f);
	colors[ImGuiCol_Separator] = ImVec4(0.25f, 0.25f, 0.30f, 1.00f);
	colors[ImGuiCol_ResizeGrip] = ImVec4(0.22f, 0.22f, 0.27f, 1.00f);
	colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.32f, 0.32f, 0.38f, 1.00f);
	colors[ImGuiCol_ResizeGripActive] = ImVec4(Config::UI_COLOR_ACCENT_R, Config::UI_COLOR_ACCENT_G, Config::UI_COLOR_ACCENT_B, 1.00f);
	colors[ImGuiCol_Tab] = ImVec4(0.16f, 0.16f, 0.19f, 1.00f);
	colors[ImGuiCol_TabHovered] = ImVec4(0.26f, 0.26f, 0.31f, 1.00f);
	colors[ImGuiCol_TabActive] = ImVec4(0.22f, 0.22f, 0.27f, 1.00f);
	colors[ImGuiCol_TableHeaderBg] = ImVec4(0.13f, 0.13f, 0.15f, 1.00f);
	colors[ImGuiCol_TableBorderStrong] = ImVec4(0.25f, 0.25f, 0.30f, 1.00f);
	colors[ImGuiCol_TableBorderLight] = ImVec4(0.18f, 0.18f, 0.21f, 1.00f);
	colors[ImGuiCol_TableRowBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
	colors[ImGuiCol_TableRowBgAlt] = ImVec4(0.09f, 0.09f, 0.11f, 0.50f);
	colors[ImGuiCol_TextSelectedBg] = ImVec4(Config::UI_COLOR_ACCENT_R, Config::UI_COLOR_ACCENT_G, Config::UI_COLOR_ACCENT_B, 0.35f);
	colors[ImGuiCol_NavHighlight] = ImVec4(Config::UI_COLOR_ACCENT_R, Config::UI_COLOR_ACCENT_G, Config::UI_COLOR_ACCENT_B, 1.00f);

	ImGui_ImplWin32_Init(m_hWnd);
	ImGui_ImplDX11_Init(m_Renderer->GetDevice(), m_Renderer->GetContext());
	return true;
}

void MainWindow::ShutdownImGui() {
	ImGui_ImplDX11_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();
}

int MainWindow::Run() {
	MSG msg;
	ZeroMemory(&msg, sizeof(msg));

	while (m_bRunning) {
		while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
			if (msg.message == WM_QUIT) {
				m_bRunning = false;
			}
		}

		if (!m_bRunning) {
			break;
		}

		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();

		RenderUI();

		ImGui::Render();
		ImVec4 bgColor = ImGui::GetStyle().Colors[ImGuiCol_WindowBg];
		const float clear_color[4] = { bgColor.x, bgColor.y, bgColor.z, bgColor.w };
		
		m_Renderer->BeginFrame();
		m_Renderer->ClearRenderTarget(clear_color);
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
		m_Renderer->EndFrame();
	}

	Cleanup();
	return 0;
}

void MainWindow::RenderUI() {
	ImGui::SetNextWindowPos(ImVec2(0, 0));
	ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
	ImGui::Begin("Runtime Inspector", nullptr, 
		ImGuiWindowFlags_MenuBar | 
		ImGuiWindowFlags_NoTitleBar |
		ImGuiWindowFlags_NoBringToFrontOnFocus);

	if (ImGui::BeginMenuBar()) {
		ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(12, 4));
		ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size > 1 ? ImGui::GetIO().Fonts->Fonts[1] : nullptr);
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.9f, 0.9f, 0.95f, 1.0f));
		ImGui::Text("Runtime Inspector");
		ImGui::PopStyleColor();
		ImGui::PopFont();
		ImGui::PopStyleVar();
		ImGui::EndMenuBar();
	}

	float leftPanelWidth = ImGui::GetContentRegionAvail().x * Config::UI_PANEL_SPLIT_RATIO;
	ImGui::BeginChild("ProcessList", ImVec2(leftPanelWidth, 0), true);
	RenderProcessList();
	ImGui::EndChild();

	ImGui::SameLine();

	ImGui::BeginChild("Controls", ImVec2(0, 0), true);
	
	if (ImGui::BeginTabBar("MainTabs")) {
		if (ImGui::BeginTabItem("Injection")) {
			RenderDllSelection();
			ImGui::Spacing();
			RenderInjectionMethod();
			ImGui::Spacing();
			
			ImGui::Spacing();
			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.20f, 0.60f, 0.90f, 1.00f));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.25f, 0.65f, 0.95f, 1.00f));
			ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.15f, 0.55f, 0.85f, 1.00f));
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 12));
			if (ImGui::Button("Inject DLL", ImVec2(-1, 42))) {
				PerformInjection();
			}
			ImGui::PopStyleVar();
			ImGui::PopStyleColor(3);
			ImGui::EndTabItem();
		}
		
		if (ImGui::BeginTabItem("Process Details")) {
			RenderProcessDetails();
			ImGui::EndTabItem();
		}
		
		if (ImGui::BeginTabItem("Threads")) {
			RenderThreadManager();
			ImGui::EndTabItem();
		}
		
		if (ImGui::BeginTabItem("Modules")) {
			RenderModuleInspector();
			ImGui::EndTabItem();
		}
		
		if (ImGui::BeginTabItem("Memory")) {
			RenderMemoryAnalyzer();
			ImGui::EndTabItem();
		}
		
		ImGui::EndTabBar();
	}

	ImGui::Spacing();
	RenderStatusBar();
	ImGui::EndChild();

	ImGui::End();

	if (m_ShowProcessProperties) {
		RenderProcessPropertiesWindow();
	}
}

void MainWindow::RenderProcessList() {
	ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size > 1 ? ImGui::GetIO().Fonts->Fonts[1] : nullptr);
	ImGui::Text("Processes");
	ImGui::PopFont();
	
	float buttonWidth = Config::UI_BUTTON_WIDTH;
	float spacing = ImGui::GetStyle().ItemSpacing.x;
	float availableWidth = ImGui::GetContentRegionAvail().x;
	ImGui::SameLine(availableWidth - (buttonWidth * 2 + spacing));
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10, 6));
	if (ImGui::Button("Refresh", ImVec2(buttonWidth, 0))) {
		RefreshProcessList();
	}
	ImGui::SameLine();
	if (ImGui::Button("Export", ImVec2(buttonWidth, 0))) {
		ExportProcessList();
	}
	ImGui::PopStyleVar();
	
	ImGui::Spacing();
	ImGui::PushItemWidth(-1);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 8));
	if (ImGui::InputText("##Filter", m_ProcessFilter, sizeof(m_ProcessFilter))) {
	}
	ImGui::PopStyleVar();
	ImGui::PopItemWidth();
	if (m_ProcessFilter[0] == '\0') {
		ImVec2 pos = ImGui::GetItemRectMin();
		pos.x += ImGui::GetStyle().FramePadding.x;
		pos.y += ImGui::GetStyle().FramePadding.y;
		ImGui::SetCursorPos(pos);
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 0.5f, 0.5f, 0.8f));
		ImGui::Text("Search processes...");
		ImGui::PopStyleColor();
	}

	ImGui::Spacing();
	ImGui::Separator();
	ImGui::Spacing();
	ImGui::BeginChild("ProcessScroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

	if (ImGui::BeginTable("Processes", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp)) {
		ImGui::TableSetupColumn("Icon", ImGuiTableColumnFlags_WidthFixed, 20);
		ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 60);
		ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("Arch", ImGuiTableColumnFlags_WidthFixed, 50);
		ImGui::TableHeadersRow();

		for (size_t i = 0; i < m_Processes.size(); i++) {
			const auto& proc = m_Processes[i];
			
			if (m_ProcessFilter[0] != '\0' && 
				proc.ProcessName.find(m_ProcessFilter) == std::string::npos) {
				continue;
			}

			ImGui::TableNextRow();
			
			ImGui::TableSetColumnIndex(0);
			void* texId = nullptr;
			
			auto it = m_IconCache.find(proc.ProcessId);
			if (it != m_IconCache.end()) {
				texId = it->second;
			}
			else {
				texId = GetProcessIconTexture(proc.ProcessId);
				if (texId) {
					m_IconCache[proc.ProcessId] = texId;
				}
			}
			
			if (texId) {
				ImGui::Image((ImTextureID)texId, ImVec2(Config::PROCESS_ICON_SIZE, Config::PROCESS_ICON_SIZE));
			}
			else {
				ImGui::Text(" ");
			}
			
			ImGui::TableSetColumnIndex(1);
			bool selected = (m_SelectedProcessIndex == (int)i);
			ImGui::PushID((int)i);
			char pidLabel[32];
			sprintf_s(pidLabel, "%lu", proc.ProcessId);
			if (ImGui::Selectable(pidLabel, selected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_DontClosePopups)) {
				m_SelectedProcessIndex = (int)i;
				if (m_SelectedProcessIndex >= 0) {
					RefreshProcessDetails();
				}
			}
			
			if (ImGui::BeginPopupContextItem("ProcessContextMenu")) {
				if (ImGui::MenuItem("Properties")) {
					ShowProcessProperties(proc.ProcessId);
					ImGui::CloseCurrentPopup();
				}
				ImGui::Separator();
				if (ImGui::MenuItem("Open File Location")) {
					OpenProcessFileLocation(proc.ProcessId);
					ImGui::CloseCurrentPopup();
				}
				if (ImGui::MenuItem("Copy PID")) {
					CopyProcessId(proc.ProcessId);
					ImGui::CloseCurrentPopup();
				}
				if (ImGui::MenuItem("Copy Name")) {
					CopyProcessName(proc.ProcessName);
					ImGui::CloseCurrentPopup();
				}
				ImGui::Separator();
				if (ImGui::MenuItem("Terminate")) {
					TerminateProcess(proc.ProcessId);
					ImGui::CloseCurrentPopup();
				}
				if (ImGui::MenuItem("Search Online")) {
					SearchProcessOnline(proc.ProcessName);
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}
			ImGui::PopID();

			ImGui::TableSetColumnIndex(2);
			ImGui::Text("%s", proc.ProcessName.c_str());
			
			ImGui::TableSetColumnIndex(3);
			ImGui::Text("%s", proc.Architecture.c_str());
		}
		ImGui::EndTable();
	}

	ImGui::EndChild();
}

void MainWindow::RenderDllSelection() {
	ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size > 1 ? ImGui::GetIO().Fonts->Fonts[1] : nullptr);
	ImGui::Text("DLL Path");
	ImGui::PopFont();
	ImGui::Spacing();
	
	ImGui::PushItemWidth(-90);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 8));
	ImGui::InputTextWithHint("##DllPath", "Select DLL file to inject...", m_DllPathBuffer, sizeof(m_DllPathBuffer));
	ImGui::PopStyleVar();
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 8));
	if (ImGui::Button("Browse", ImVec2(80, 0))) {
		BrowseForDll();
	}
	ImGui::PopStyleVar();
}

void MainWindow::RenderInjectionMethod() {
	ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size > 1 ? ImGui::GetIO().Fonts->Fonts[1] : nullptr);
	ImGui::Text("Injection Method");
	ImGui::PopFont();
	ImGui::Spacing();
	
	const char* methods[] = {
		"CreateRemoteThread",
		"NtCreateThreadEx",
		"QueueUserAPC",
		"SetWindowsHookEx",
		"RtlCreateUserThread"
	};
	ImGui::PushItemWidth(-1);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 8));
	ImGui::Combo("##Method", &m_SelectedInjectionMethod, methods, IM_ARRAYSIZE(methods));
	ImGui::PopStyleVar();
	ImGui::PopItemWidth();
	
	ImGui::Spacing();
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.7f, 0.7f, 1.0f));
	ImGui::TextWrapped("Note: Some methods may require elevated privileges or specific process architectures.");
	ImGui::PopStyleColor();
}

void MainWindow::RenderStatusBar() {
	ImGui::Separator();
	ImGui::Spacing();
	
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.8f, 1.0f, 1.0f));
	ImGui::Text("Status:");
	ImGui::PopStyleColor();
	ImGui::SameLine();
	ImGui::Text("%s", m_StatusMessage.c_str());
	
	const auto& logMessages = Logger::GetInstance().GetMessages();
	if (!logMessages.empty()) {
		ImGui::Spacing();
		ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size > 1 ? ImGui::GetIO().Fonts->Fonts[1] : nullptr);
		ImGui::Text("Activity Log");
		ImGui::PopFont();
		ImGui::BeginChild("Log", ImVec2(0, 160), true, ImGuiWindowFlags_AlwaysVerticalScrollbar);
		ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 3));
		for (const auto& msg : logMessages) {
			ImGui::TextWrapped("%s", msg.c_str());
		}
		ImGui::PopStyleVar();
		if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 1.0f) {
			ImGui::SetScrollHereY(1.0f);
		}
		ImGui::EndChild();
	}
}

void MainWindow::RenderProcessDetails() {
	if (m_SelectedProcessIndex < 0 || m_SelectedProcessIndex >= (int)m_Processes.size()) {
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.7f, 0.7f, 1.0f));
		ImGui::Text("Select a process to view details");
		ImGui::PopStyleColor();
		return;
	}

	DWORD pid = m_Processes[m_SelectedProcessIndex].ProcessId;
	
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10, 6));
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8, 0));
	if (ImGui::Button("Refresh Details", ImVec2(0, 0))) {
		RefreshProcessDetails();
	}
	ImGui::SameLine();
	if (ImGui::Button("Refresh Threads", ImVec2(0, 0))) {
		RefreshThreads(pid);
	}
	ImGui::SameLine();
	if (ImGui::Button("Refresh Modules", ImVec2(0, 0))) {
		RefreshModules(pid);
	}
	ImGui::PopStyleVar(2);

	ImGui::Spacing();
	ImGui::Separator();
	ImGui::Spacing();

	HandleWrapper hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
	if (!hProcess.IsValid()) {
		ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "Failed to open process (Access Denied)");
		Logger::GetInstance().LogWarning("Failed to open process PID " + std::to_string(pid) + " (Access Denied)");
		return;
	}

	PROCESS_MEMORY_COUNTERS_EX pmc = {};
	if (GetProcessMemoryInfo(hProcess.Get(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
		ImGui::Text("Memory Information:");
		ImGui::BulletText("Working Set: %.2f MB", pmc.WorkingSetSize / (1024.0 * 1024.0));
		ImGui::BulletText("Peak Working Set: %.2f MB", pmc.PeakWorkingSetSize / (1024.0 * 1024.0));
		ImGui::BulletText("Page File Usage: %.2f MB", pmc.PagefileUsage / (1024.0 * 1024.0));
		ImGui::BulletText("Peak Page File Usage: %.2f MB", pmc.PeakPagefileUsage / (1024.0 * 1024.0));
		ImGui::BulletText("Private Usage: %.2f MB", pmc.PrivateUsage / (1024.0 * 1024.0));
	}

	FILETIME creationTime, exitTime, kernelTime, userTime;
	if (GetProcessTimes(hProcess.Get(), &creationTime, &exitTime, &kernelTime, &userTime)) {
		ImGui::Spacing();
		ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size > 1 ? ImGui::GetIO().Fonts->Fonts[1] : nullptr);
		ImGui::Text("Process Times");
		ImGui::PopFont();
		ImGui::Spacing();
		SYSTEMTIME st;
		FileTimeToSystemTime(&creationTime, &st);
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.85f, 1.0f, 1.0f));
		ImGui::BulletText("Creation Time: %02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
		
		ULARGE_INTEGER kernel, user;
		kernel.LowPart = kernelTime.dwLowDateTime;
		kernel.HighPart = kernelTime.dwHighDateTime;
		user.LowPart = userTime.dwLowDateTime;
		user.HighPart = userTime.dwHighDateTime;
		
		ImGui::BulletText("Kernel Time: %.2f seconds", kernel.QuadPart / 10000000.0);
		ImGui::BulletText("User Time: %.2f seconds", user.QuadPart / 10000000.0);
		ImGui::PopStyleColor();
	}

	char exePath[MAX_PATH] = { 0 };
	if (GetModuleFileNameExA(hProcess.Get(), nullptr, exePath, MAX_PATH)) {
		ImGui::Spacing();
		ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size > 1 ? ImGui::GetIO().Fonts->Fonts[1] : nullptr);
		ImGui::Text("Executable Path");
		ImGui::PopFont();
		ImGui::Spacing();
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8f, 0.8f, 0.9f, 1.0f));
		ImGui::TextWrapped("%s", exePath);
		ImGui::PopStyleColor();
	}

	CloseHandle(hProcess);
}

void MainWindow::RenderThreadManager() {
	if (m_SelectedProcessIndex < 0 || m_SelectedProcessIndex >= (int)m_Processes.size()) {
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.7f, 0.7f, 1.0f));
		ImGui::Text("Select a process to view threads");
		ImGui::PopStyleColor();
		return;
	}

	DWORD pid = m_Processes[m_SelectedProcessIndex].ProcessId;
	
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10, 6));
	if (ImGui::Button("Refresh Threads", ImVec2(150, 0))) {
		RefreshThreads(pid);
	}
	ImGui::PopStyleVar();

	ImGui::Spacing();
	ImGui::Separator();
	ImGui::Spacing();

	if (ImGui::BeginTable("Threads", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
		ImGui::TableSetupColumn("Thread ID", ImGuiTableColumnFlags_WidthFixed, 100);
		ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 100);
		ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableHeadersRow();

		for (const auto& thread : m_CurrentThreads) {
			ImGui::TableNextRow();
			
			ImGui::TableSetColumnIndex(0);
			ImGui::Text("%lu", thread.ThreadId);
			
			ImGui::TableSetColumnIndex(1);
			ImGui::Text("%s", thread.State.c_str());
			
			ImGui::TableSetColumnIndex(2);
			ImGui::PushID(thread.ThreadId);
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 4));
			if (thread.State == "Running") {
				ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.5f, 0.2f, 1.0f));
				ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.6f, 0.3f, 1.0f));
				if (ImGui::Button("Suspend", ImVec2(80, 0))) {
					SuspendThread(thread.ThreadId);
					RefreshThreads(pid);
				}
				ImGui::PopStyleColor(2);
			}
			else if (thread.State == "Suspended") {
				ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.7f, 0.4f, 1.0f));
				ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.8f, 0.5f, 1.0f));
				if (ImGui::Button("Resume", ImVec2(80, 0))) {
					ResumeThread(thread.ThreadId);
					RefreshThreads(pid);
				}
				ImGui::PopStyleColor(2);
			}
			ImGui::PopStyleVar();
			ImGui::PopID();
		}
		ImGui::EndTable();
	}
}

void MainWindow::RenderModuleInspector() {
	if (m_SelectedProcessIndex < 0 || m_SelectedProcessIndex >= (int)m_Processes.size()) {
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.7f, 0.7f, 1.0f));
		ImGui::Text("Select a process to view modules");
		ImGui::PopStyleColor();
		return;
	}

	DWORD pid = m_Processes[m_SelectedProcessIndex].ProcessId;
	
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10, 6));
	if (ImGui::Button("Refresh Modules", ImVec2(150, 0))) {
		RefreshModules(pid);
	}
	ImGui::PopStyleVar();

	ImGui::Spacing();
	ImGui::Separator();
	ImGui::Spacing();

	if (ImGui::BeginTable("Modules", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
		ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("Base Address", ImGuiTableColumnFlags_WidthFixed, 120);
		ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 100);
		ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableHeadersRow();

		for (const auto& module : m_CurrentModules) {
			ImGui::TableNextRow();
			
			ImGui::TableSetColumnIndex(0);
			ImGui::Text("%s", module.Name.c_str());
			
			ImGui::TableSetColumnIndex(1);
			ImGui::Text("0x%p", (void*)module.BaseAddress);
			
			ImGui::TableSetColumnIndex(2);
			ImGui::Text("%.2f KB", module.Size / 1024.0);
			
			ImGui::TableSetColumnIndex(3);
			ImGui::TextWrapped("%s", module.Path.c_str());
		}
		ImGui::EndTable();
	}
}

void MainWindow::RenderMemoryAnalyzer() {
	if (m_SelectedProcessIndex < 0 || m_SelectedProcessIndex >= (int)m_Processes.size()) {
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.7f, 0.7f, 1.0f));
		ImGui::Text("Select a process to analyze memory");
		ImGui::PopStyleColor();
		return;
	}

	DWORD pid = m_Processes[m_SelectedProcessIndex].ProcessId;

	ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size > 1 ? ImGui::GetIO().Fonts->Fonts[1] : nullptr);
	ImGui::Text("Memory Reader");
	ImGui::PopFont();
	ImGui::Spacing();
	
	ImGui::PushItemWidth(220);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 8));
	ImGui::InputTextWithHint("##Address", "Address (hex)", m_MemoryAddressBuffer, sizeof(m_MemoryAddressBuffer));
	ImGui::PopStyleVar();
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(160);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 8));
	ImGui::InputTextWithHint("##Size", "Size (bytes)", m_MemorySizeBuffer, sizeof(m_MemorySizeBuffer));
	ImGui::PopStyleVar();
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 8));
	if (ImGui::Button("Read", ImVec2(80, 0))) {
		ULONG_PTR addr = 0;
		SIZE_T size = 0;
		sscanf_s(m_MemoryAddressBuffer, "%llx", &addr);
		sscanf_s(m_MemorySizeBuffer, "%zu", &size);
		if (addr && size && size < 1024) {
			ReadProcessMemory(pid, (LPCVOID)addr, size);
		}
	}
	ImGui::PopStyleVar();

	ImGui::Spacing();
	ImGui::Separator();
	ImGui::Spacing();

	ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size > 1 ? ImGui::GetIO().Fonts->Fonts[1] : nullptr);
	ImGui::Text("String Search");
	ImGui::PopFont();
	ImGui::Spacing();
	
	ImGui::PushItemWidth(-90);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 8));
	ImGui::InputTextWithHint("##SearchString", "Enter string to search...", m_SearchStringBuffer, sizeof(m_SearchStringBuffer));
	ImGui::PopStyleVar();
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 8));
	if (ImGui::Button("Search", ImVec2(80, 0))) {
		if (strlen(m_SearchStringBuffer) > 0) {
			SearchMemoryStrings(pid);
		}
	}
	ImGui::PopStyleVar();

	if (!m_MemorySearchResults.empty()) {
		ImGui::Spacing();
		ImGui::Text("Search Results:");
		ImGui::BeginChild("SearchResults", ImVec2(0, 200), true);
		for (const auto& result : m_MemorySearchResults) {
			ImGui::TextWrapped("%s", result.c_str());
		}
		ImGui::EndChild();
	}
}

void MainWindow::RefreshProcessList() {
	std::unordered_map<DWORD, void*> newCache;
	for (const auto& proc : m_Processes) {
		auto it = m_IconCache.find(proc.ProcessId);
		if (it != m_IconCache.end()) {
			newCache[proc.ProcessId] = it->second;
		}
	}
	
	for (auto& pair : m_IconCache) {
		if (newCache.find(pair.first) == newCache.end()) {
			if (pair.second && m_Renderer) {
				m_Renderer->ReleaseTexture(pair.second);
			}
		}
	}
	m_IconCache = std::move(newCache);
	
	m_Processes.clear();
	auto processes = EnumerateAllProcesses();
	
	for (const auto& proc : processes) {
		ProcessInfo info = {};
		info.ProcessId = proc.ProcessId;
		info.ProcessName = proc.ProcessName;
		info.Architecture = proc.Architecture;
		m_Processes.push_back(info);
	}

	m_StatusMessage = "Process list refreshed (" + std::to_string(m_Processes.size()) + " processes)";
}

bool MainWindow::BrowseForDll() {
	OPENFILENAMEA ofn = {};
	char szFile[260] = { 0 };

	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = m_hWnd;
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = "DLL Files\0*.dll\0All Files\0*.*\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = nullptr;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = nullptr;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (GetOpenFileNameA(&ofn)) {
		strcpy_s(m_DllPathBuffer, sizeof(m_DllPathBuffer), szFile);
		m_DllPath = szFile;
		return true;
	}
	return false;
}

void MainWindow::PerformInjection() {
	if (m_SelectedProcessIndex < 0 || m_SelectedProcessIndex >= (int)m_Processes.size()) {
		m_StatusMessage = "Error: No process selected";
		return;
	}

	if (m_DllPath.empty()) {
		m_StatusMessage = "Error: No DLL path specified";
		return;
	}

	DWORD pid = m_Processes[m_SelectedProcessIndex].ProcessId;
	HandleWrapper hProcess(OpenTargetProcess(pid));
	if (!hProcess.IsValid()) {
		m_StatusMessage = "Error: Failed to open target process";
		Logger::GetInstance().LogError("Failed to open target process PID " + std::to_string(pid));
		return;
	}

	bool success = false;
	switch (m_SelectedInjectionMethod) {
		case 0:
			success = InjectViaCreateRemoteThread(m_DllPath.c_str(), hProcess.Get());
			break;
		case 1:
			success = InjectViaNtCreateThreadEx(m_DllPath.c_str(), hProcess.Get());
			break;
		case 2:
			success = InjectViaQueueUserAPC(m_DllPath.c_str(), hProcess.Get(), pid);
			break;
		case 3:
			success = InjectViaSetWindowsHookEx(pid, m_DllPath.c_str());
			break;
		case 4:
			success = InjectViaRtlCreateUserThread(hProcess.Get(), m_DllPath.c_str());
			break;
	}

	if (success) {
		m_StatusMessage = "Injection successful!";
		Logger::GetInstance().LogInfo("Successfully injected " + m_DllPath + " into PID " + std::to_string(pid));
	}
	else {
		m_StatusMessage = "Injection failed!";
		Logger::GetInstance().LogError("Failed to inject " + m_DllPath + " into PID " + std::to_string(pid));
	}
}

void MainWindow::Cleanup() {
	for (auto& pair : m_IconCache) {
		if (pair.second && m_Renderer) {
			m_Renderer->ReleaseTexture(pair.second);
		}
	}
	m_IconCache.clear();
	
	if (m_Renderer) {
		m_Renderer->Shutdown();
		m_Renderer.reset();
	}

	ShutdownImGui();

	char imguiIniPath[MAX_PATH];
	if (GetModuleFileNameA(nullptr, imguiIniPath, MAX_PATH)) {
		char* lastSlash = strrchr(imguiIniPath, '\\');
		if (lastSlash) {
			*(lastSlash + 1) = '\0';
			strcat_s(imguiIniPath, MAX_PATH, "imgui.ini");
			DeleteFileA(imguiIniPath);
		}
	}

	if (m_hWnd) {
		DestroyWindow(m_hWnd);
		m_hWnd = nullptr;
	}
}

LRESULT CALLBACK MainWindow::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	if ((uMsg < WM_NCMOUSEMOVE || uMsg > WM_NCMBUTTONDBLCLK) && 
		uMsg != WM_NCHITTEST &&
		ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam))
		return true;

	if (uMsg == WM_NCCREATE) {
		CREATESTRUCTW* pCreate = (CREATESTRUCTW*)lParam;
		MainWindow* pThis = (MainWindow*)pCreate->lpCreateParams;
		SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)pThis);
		return DefWindowProc(hwnd, uMsg, wParam, lParam);
	}

	MainWindow* pThis = (MainWindow*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
	if (pThis) {
		return pThis->HandleMessage(uMsg, wParam, lParam);
	}

	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT MainWindow::HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
		case WM_ACTIVATE:
			if (wParam != WA_INACTIVE) {
				SetForegroundWindow(m_hWnd);
				InvalidateRect(m_hWnd, nullptr, TRUE);
			}
			return DefWindowProc(m_hWnd, uMsg, wParam, lParam);
		case WM_NCACTIVATE:
			return DefWindowProc(m_hWnd, uMsg, wParam, lParam);
		case WM_PAINT:
		{
			PAINTSTRUCT ps;
			BeginPaint(m_hWnd, &ps);
			EndPaint(m_hWnd, &ps);
			return 0;
		}
		case WM_SIZE:
			if (m_Renderer && wParam != SIZE_MINIMIZED) {
				m_Renderer->Resize((UINT)LOWORD(lParam), (UINT)HIWORD(lParam));
			}
			return 0;
		case WM_SYSCOMMAND:
			if ((wParam & 0xfff0) == SC_KEYMENU)
				return 0;
			if ((wParam & 0xfff0) == SC_CLOSE) {
				m_bRunning = false;
				PostQuitMessage(0);
				return 0;
			}
			break;
		case WM_DESTROY:
			PostQuitMessage(0);
			m_bRunning = false;
			return 0;
		case WM_NCHITTEST:
			LRESULT hit = DefWindowProc(m_hWnd, uMsg, wParam, lParam);
			if (hit == HTCLIENT) {
				POINT pt = { LOWORD(lParam), HIWORD(lParam) };
				ScreenToClient(m_hWnd, &pt);
				if (pt.y >= 0 && pt.y < Config::TITLE_BAR_HEIGHT) {
					return HTCAPTION;
				}
			}
			return hit;
	}
	return DefWindowProc(m_hWnd, uMsg, wParam, lParam);
}

RuntimeInspector::Core::IconWrapper MainWindow::GetProcessIcon(DWORD processId) {
	HandleWrapper hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId));
	if (!hProcess.IsValid()) {
		return RuntimeInspector::Core::IconWrapper();
	}

	char exePath[MAX_PATH] = { 0 };
	if (GetModuleFileNameExA(hProcess.Get(), nullptr, exePath, MAX_PATH) == 0) {
		return RuntimeInspector::Core::IconWrapper();
	}

	SHFILEINFOA sfi = { 0 };
	SHGetFileInfoA(exePath, 0, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_SMALLICON);
	return RuntimeInspector::Core::IconWrapper(sfi.hIcon);
}

void* MainWindow::GetProcessIconTexture(DWORD processId) {
	if (!m_Renderer) {
		return nullptr;
	}
	
	RuntimeInspector::Core::IconWrapper icon = GetProcessIcon(processId);
	if (!icon.IsValid()) {
		return nullptr;
	}
	
	return m_Renderer->CreateTextureFromIcon(icon.Get());
}

void MainWindow::OpenProcessFileLocation(DWORD processId) {
	HandleWrapper hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId));
	if (!hProcess.IsValid()) {
		m_StatusMessage = "Failed to open process";
		Logger::GetInstance().LogError("Failed to open process PID " + std::to_string(processId) + " for file location");
		return;
	}

	char exePath[MAX_PATH] = { 0 };
	if (GetModuleFileNameExA(hProcess.Get(), nullptr, exePath, MAX_PATH) == 0) {
		m_StatusMessage = "Failed to get process path";
		Logger::GetInstance().LogError("Failed to get module filename for process PID " + std::to_string(processId));
		return;
	}

	char* lastSlash = strrchr(exePath, '\\');
	if (lastSlash) {
		*lastSlash = '\0';
	}

	std::string folderPath = exePath;
	ShellExecuteA(nullptr, "open", folderPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
	m_StatusMessage = "Opened file location";
}

void MainWindow::CopyProcessId(DWORD processId) {
	std::string pidStr = std::to_string(processId);
	
	if (OpenClipboard(nullptr)) {
		EmptyClipboard();
		HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, pidStr.length() + 1);
		if (hMem) {
			memcpy(GlobalLock(hMem), pidStr.c_str(), pidStr.length() + 1);
			GlobalUnlock(hMem);
			SetClipboardData(CF_TEXT, hMem);
			CloseClipboard();
			m_StatusMessage = "PID copied to clipboard";
		}
		else {
			CloseClipboard();
			m_StatusMessage = "Failed to copy PID";
		}
	}
	else {
		m_StatusMessage = "Failed to open clipboard";
	}
}

void MainWindow::TerminateProcess(DWORD processId) {
	HandleWrapper hProcess(OpenProcess(PROCESS_TERMINATE, FALSE, processId));
	if (!hProcess.IsValid()) {
		m_StatusMessage = "Failed to open process for termination";
		Logger::GetInstance().LogError("Failed to open process PID " + std::to_string(processId) + " for termination");
		return;
	}

	if (::TerminateProcess(hProcess.Get(), 0)) {
		m_StatusMessage = "Process terminated";
		Logger::GetInstance().LogWarning("Terminated process PID " + std::to_string(processId));
		RefreshProcessList();
	}
	else {
		m_StatusMessage = "Failed to terminate process";
		Logger::GetInstance().LogError("Failed to terminate process PID " + std::to_string(processId));
	}
}

void MainWindow::CopyProcessName(const std::string& processName) {
	if (OpenClipboard(nullptr)) {
		EmptyClipboard();
		HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, processName.length() + 1);
		if (hMem) {
			memcpy(GlobalLock(hMem), processName.c_str(), processName.length() + 1);
			GlobalUnlock(hMem);
			SetClipboardData(CF_TEXT, hMem);
			CloseClipboard();
			m_StatusMessage = "Process name copied to clipboard";
		}
		else {
			CloseClipboard();
			m_StatusMessage = "Failed to copy process name";
		}
	}
	else {
		m_StatusMessage = "Failed to open clipboard";
	}
}

void MainWindow::SearchProcessOnline(const std::string& processName) {
	std::string searchUrl = "https://www.google.com/search?q=" + processName;
	ShellExecuteA(nullptr, "open", searchUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
	m_StatusMessage = "Searching online for " + processName;
}

void MainWindow::ShowProcessProperties(DWORD processId) {
	m_ShowProcessProperties = true;
	m_CurrentProcessDetails.ProcessId = processId;
	for (size_t i = 0; i < m_Processes.size(); i++) {
		if (m_Processes[i].ProcessId == processId) {
			m_SelectedProcessIndex = (int)i;
			m_CurrentProcessDetails.ProcessName = m_Processes[i].ProcessName;
			m_CurrentProcessDetails.Architecture = m_Processes[i].Architecture;
			break;
		}
	}
	RefreshProcessDetails();
}

void MainWindow::RenderProcessPropertiesWindow() {
	if (!m_ShowProcessProperties) {
		return;
	}

	ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));
	
	if (ImGui::Begin("Process Properties", &m_ShowProcessProperties, ImGuiWindowFlags_None)) {
		if (m_CurrentProcessDetails.ProcessId == 0) {
			ImGui::Text("No process selected");
			ImGui::End();
			return;
		}

		ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size > 1 ? ImGui::GetIO().Fonts->Fonts[1] : nullptr);
		ImGui::Text("Process Information");
		ImGui::PopFont();
		ImGui::Separator();
		ImGui::Spacing();

		ImGui::Text("Process Name:");
		ImGui::SameLine(150);
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8f, 0.8f, 0.9f, 1.0f));
		ImGui::Text("%s", m_CurrentProcessDetails.ProcessName.c_str());
		ImGui::PopStyleColor();

		ImGui::Text("Process ID:");
		ImGui::SameLine(150);
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8f, 0.8f, 0.9f, 1.0f));
		ImGui::Text("%lu", m_CurrentProcessDetails.ProcessId);
		ImGui::PopStyleColor();

		ImGui::Text("Architecture:");
		ImGui::SameLine(150);
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8f, 0.8f, 0.9f, 1.0f));
		std::string arch = "?";
		HandleWrapper hProcessArch(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, m_CurrentProcessDetails.ProcessId));
		if (hProcessArch.IsValid()) {
			BOOL isWow64 = FALSE;
			if (IsWow64Process(hProcessArch.Get(), &isWow64)) {
				SYSTEM_INFO si = {};
				GetNativeSystemInfo(&si);
				if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
					if (isWow64) {
						arch = "x86";
					} else {
						arch = "x64";
					}
				} else {
					arch = "x86";
				}
			}
		}
		ImGui::Text("%s", arch.c_str());
		ImGui::PopStyleColor();

		HandleWrapper hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, m_CurrentProcessDetails.ProcessId));
		if (hProcess.IsValid()) {
			ImGui::Spacing();
			ImGui::Separator();
			ImGui::Spacing();

			ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size > 1 ? ImGui::GetIO().Fonts->Fonts[1] : nullptr);
			ImGui::Text("Memory Information");
			ImGui::PopFont();
			ImGui::Spacing();

			PROCESS_MEMORY_COUNTERS_EX pmc = {};
			if (GetProcessMemoryInfo(hProcess.Get(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
				ImGui::Text("Working Set:");
				ImGui::SameLine(150);
				ImGui::Text("%.2f MB", pmc.WorkingSetSize / (1024.0 * 1024.0));

				ImGui::Text("Peak Working Set:");
				ImGui::SameLine(150);
				ImGui::Text("%.2f MB", pmc.PeakWorkingSetSize / (1024.0 * 1024.0));

				ImGui::Text("Page File Usage:");
				ImGui::SameLine(150);
				ImGui::Text("%.2f MB", pmc.PagefileUsage / (1024.0 * 1024.0));

				ImGui::Text("Private Usage:");
				ImGui::SameLine(150);
				ImGui::Text("%.2f MB", pmc.PrivateUsage / (1024.0 * 1024.0));
			}

			ImGui::Spacing();
			ImGui::Separator();
			ImGui::Spacing();

			ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size > 1 ? ImGui::GetIO().Fonts->Fonts[1] : nullptr);
			ImGui::Text("Process Times");
			ImGui::PopFont();
			ImGui::Spacing();

			FILETIME creationTime, exitTime, kernelTime, userTime;
			if (GetProcessTimes(hProcess.Get(), &creationTime, &exitTime, &kernelTime, &userTime)) {
				SYSTEMTIME st;
				FileTimeToSystemTime(&creationTime, &st);
				ImGui::Text("Creation Time:");
				ImGui::SameLine(150);
				ImGui::Text("%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

				ULARGE_INTEGER kernel, user;
				kernel.LowPart = kernelTime.dwLowDateTime;
				kernel.HighPart = kernelTime.dwHighDateTime;
				user.LowPart = userTime.dwLowDateTime;
				user.HighPart = userTime.dwHighDateTime;

				ImGui::Text("Kernel Time:");
				ImGui::SameLine(150);
				ImGui::Text("%.2f seconds", kernel.QuadPart / 10000000.0);

				ImGui::Text("User Time:");
				ImGui::SameLine(150);
				ImGui::Text("%.2f seconds", user.QuadPart / 10000000.0);
			}

			char exePath[MAX_PATH] = { 0 };
			if (GetModuleFileNameExA(hProcess.Get(), nullptr, exePath, MAX_PATH)) {
				ImGui::Spacing();
				ImGui::Separator();
				ImGui::Spacing();

				ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size > 1 ? ImGui::GetIO().Fonts->Fonts[1] : nullptr);
				ImGui::Text("Executable Path");
				ImGui::PopFont();
				ImGui::Spacing();
				ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8f, 0.8f, 0.9f, 1.0f));
				ImGui::TextWrapped("%s", exePath);
				ImGui::PopStyleColor();
			}

		}
		else {
			ImGui::Spacing();
			ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "Failed to open process (Access Denied)");
			Logger::GetInstance().LogWarning("Failed to open process PID " + std::to_string(m_CurrentProcessDetails.ProcessId) + " (Access Denied)");
		}

		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();

		if (ImGui::Button("Close", ImVec2(100, 0))) {
			m_ShowProcessProperties = false;
		}
	}
	ImGui::End();
}

void MainWindow::ExportProcessList() {
	OPENFILENAMEA ofn = {};
	char szFile[260] = { 0 };
	strcpy_s(szFile, "processes.txt");

	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = m_hWnd;
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = "Text Files\0*.txt\0All Files\0*.*\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = nullptr;
	ofn.Flags = OFN_OVERWRITEPROMPT;

	if (GetSaveFileNameA(&ofn)) {
		std::ofstream file(szFile);
		if (file.is_open()) {
			file << "PID\tName\tArchitecture\n";
			for (const auto& proc : m_Processes) {
				file << proc.ProcessId << "\t" << proc.ProcessName << "\t" << proc.Architecture << "\n";
			}
			file.close();
			m_StatusMessage = "Process list exported to " + std::string(szFile);
		}
		else {
			m_StatusMessage = "Failed to export process list";
		}
	}
}

void MainWindow::RefreshProcessDetails() {
	if (m_SelectedProcessIndex < 0 || m_SelectedProcessIndex >= (int)m_Processes.size()) {
		return;
	}

	DWORD pid = m_Processes[m_SelectedProcessIndex].ProcessId;
	m_CurrentProcessDetails.ProcessId = pid;
	m_CurrentProcessDetails.ProcessName = m_Processes[m_SelectedProcessIndex].ProcessName;
}

void MainWindow::RefreshThreads(DWORD processId) {
	m_CurrentThreads.clear();
	
	HandleWrapper hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
	if (!hSnapshot.IsValid()) {
		Logger::GetInstance().LogError("Failed to create thread snapshot");
		return;
	}

	THREADENTRY32 te32 = {};
	te32.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(hSnapshot.Get(), &te32)) {
		do {
			if (te32.th32OwnerProcessID == processId) {
				ThreadInfo info = {};
				info.ThreadId = te32.th32ThreadID;
				info.ProcessId = te32.th32OwnerProcessID;
				
				HandleWrapper hThread(OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, info.ThreadId));
				if (hThread.IsValid()) {
					DWORD suspendCount = ::SuspendThread(hThread.Get());
					if (suspendCount != (DWORD)-1) {
						if (suspendCount > 0) {
							::ResumeThread(hThread.Get());
							info.State = "Suspended";
						}
						else {
							info.State = "Running";
						}
					}
					else {
						info.State = "Unknown";
					}
				}
				else {
					info.State = "Unknown";
				}
				
				m_CurrentThreads.push_back(info);
			}
		} while (Thread32Next(hSnapshot.Get(), &te32));
	}
}

void MainWindow::RefreshModules(DWORD processId) {
	m_CurrentModules.clear();
	
	HandleWrapper hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId));
	if (!hProcess.IsValid()) {
		Logger::GetInstance().LogWarning("Failed to open process PID " + std::to_string(processId) + " for module enumeration");
		return;
	}

	HMODULE hMods[1024];
	DWORD cbNeeded;
	if (EnumProcessModules(hProcess.Get(), hMods, sizeof(hMods), &cbNeeded)) {
		for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			char szModName[MAX_PATH];
			if (GetModuleFileNameExA(hProcess.Get(), hMods[i], szModName, sizeof(szModName))) {
				MODULEINFO modInfo = {};
				if (GetModuleInformation(hProcess.Get(), hMods[i], &modInfo, sizeof(modInfo))) {
					ModuleInfo info = {};
					char* fileName = strrchr(szModName, '\\');
					info.Name = fileName ? fileName + 1 : szModName;
					info.Path = szModName;
					info.BaseAddress = (ULONG_PTR)modInfo.lpBaseOfDll;
					info.Size = modInfo.SizeOfImage;
					m_CurrentModules.push_back(info);
				}
			}
		}
	}

}

void MainWindow::SuspendThread(DWORD threadId) {
	HandleWrapper hThread(OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId));
	if (hThread.IsValid()) {
		::SuspendThread(hThread.Get());
		m_StatusMessage = "Thread suspended";
		Logger::GetInstance().LogInfo("Suspended thread " + std::to_string(threadId));
	} else {
		Logger::GetInstance().LogError("Failed to open thread " + std::to_string(threadId) + " for suspension");
	}
}

void MainWindow::ResumeThread(DWORD threadId) {
	HandleWrapper hThread(OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId));
	if (hThread.IsValid()) {
		::ResumeThread(hThread.Get());
		m_StatusMessage = "Thread resumed";
		Logger::GetInstance().LogInfo("Resumed thread " + std::to_string(threadId));
	} else {
		Logger::GetInstance().LogError("Failed to open thread " + std::to_string(threadId) + " for resumption");
	}
}

void MainWindow::ReadProcessMemory(DWORD processId, LPCVOID address, SIZE_T size) {
	HandleWrapper hProcess(OpenProcess(PROCESS_VM_READ, FALSE, processId));
	if (!hProcess.IsValid()) {
		m_StatusMessage = "Failed to open process for memory read";
		Logger::GetInstance().LogError("Failed to open process PID " + std::to_string(processId) + " for memory read");
		return;
	}

	std::vector<BYTE> buffer(size);
	SIZE_T bytesRead = 0;
	if (::ReadProcessMemory(hProcess.Get(), address, buffer.data(), size, &bytesRead)) {
		std::stringstream ss;
		ss << "Memory at 0x" << std::hex << (ULONG_PTR)address << " (" << std::dec << bytesRead << " bytes):\n";
		for (SIZE_T i = 0; i < bytesRead; i++) {
			if (i % 16 == 0) {
				ss << "\n0x" << std::hex << std::setfill('0') << std::setw(8) << (ULONG_PTR)address + i << ": ";
			}
			ss << std::hex << std::setfill('0') << std::setw(2) << (int)buffer[i] << " ";
		}
		Logger::GetInstance().LogInfo(ss.str());
		m_StatusMessage = "Memory read successful";
	}
	else {
		m_StatusMessage = "Failed to read memory";
		Logger::GetInstance().LogError("Failed to read memory from process PID " + std::to_string(processId));
	}
}

void MainWindow::SearchMemoryStrings(DWORD processId) {
	m_MemorySearchResults.clear();
	
	HandleWrapper hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId));
	if (!hProcess.IsValid()) {
		m_StatusMessage = "Failed to open process for memory search";
		Logger::GetInstance().LogError("Failed to open process PID " + std::to_string(processId) + " for memory search");
		return;
	}

	MEMORY_BASIC_INFORMATION mbi = {};
	LPCVOID address = nullptr;
	std::string searchStr = m_SearchStringBuffer;
	
	while (VirtualQueryEx(hProcess.Get(), address, &mbi, sizeof(mbi))) {
		if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
			std::vector<BYTE> buffer(mbi.RegionSize);
			SIZE_T bytesRead = 0;
			if (::ReadProcessMemory(hProcess.Get(), mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
				for (SIZE_T i = 0; i <= bytesRead - searchStr.length(); i++) {
					if (memcmp(buffer.data() + i, searchStr.c_str(), searchStr.length()) == 0) {
						std::stringstream ss;
						ss << "Found at 0x" << std::hex << (ULONG_PTR)mbi.BaseAddress + i;
						m_MemorySearchResults.push_back(ss.str());
						if (m_MemorySearchResults.size() >= 100) {
							break;
						}
					}
				}
			}
		}
		address = (LPCVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
		if (m_MemorySearchResults.size() >= 100) {
			break;
		}
	}

	m_StatusMessage = "Found " + std::to_string(m_MemorySearchResults.size()) + " matches";
	Logger::GetInstance().LogInfo("Memory search found " + std::to_string(m_MemorySearchResults.size()) + " matches in process PID " + std::to_string(processId));
}

void MainWindow::EnumerateHandles(DWORD processId) {
	m_HandleList.clear();
	m_HandleList.push_back("Handle enumeration requires additional privileges");
	m_StatusMessage = "Handle enumeration not fully implemented";
}
