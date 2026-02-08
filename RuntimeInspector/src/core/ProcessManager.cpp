#include "ProcessManager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <string.h>

namespace RuntimeInspector {
namespace Core {

std::vector<ProcessInfo> EnumerateAllProcesses() {
	std::vector<ProcessInfo> processes;

	PROCESSENTRY32W PE32 = {};
	PE32.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		return processes;
	}

		if (Process32FirstW(hSnap, &PE32)) {
		do {
			ProcessInfo info;
			info.ProcessId = PE32.th32ProcessID;
			info.ParentProcessId = PE32.th32ParentProcessID;

			int size_needed = WideCharToMultiByte(CP_UTF8, 0, PE32.szExeFile, -1, nullptr, 0, nullptr, nullptr);
			std::string processName(size_needed, 0);
			WideCharToMultiByte(CP_UTF8, 0, PE32.szExeFile, -1, &processName[0], size_needed, nullptr, nullptr);
			processName.pop_back();
			info.ProcessName = processName;

			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PE32.th32ProcessID);
			if (hProcess) {
				BOOL isWow64 = FALSE;
				if (IsWow64Process(hProcess, &isWow64)) {
					if (isWow64) {
						info.Architecture = "x86";
					}
					else {
						SYSTEM_INFO si;
						GetNativeSystemInfo(&si);
						if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
							si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
							info.Architecture = "x64";
						}
						else {
							info.Architecture = "x86";
						}
					}
				}
				else {
					SYSTEM_INFO si;
					GetNativeSystemInfo(&si);
					if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
						si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
						info.Architecture = "x64";
					}
					else {
						info.Architecture = "x86";
					}
				}
				CloseHandle(hProcess);
			}
			else {
				info.Architecture = "?";
			}

			processes.push_back(info);
		} while (Process32NextW(hSnap, &PE32));
	}

	CloseHandle(hSnap);
	return processes;
}

DWORD SelectProcessFromList() {
	printf("\n=== Process List ===\n");
	printf("%-8s %-40s %-8s\n", "Index", "Process Name", "Arch");
	printf("------------------------------------------------------------\n");

	std::vector<ProcessInfo> processes = EnumerateAllProcesses();

	if (processes.empty()) {
		printf("No processes found!\n");
		return 0;
	}

	for (size_t i = 0; i < processes.size(); i++) {
		printf("%-8zu %-40s %-8s (PID: %lu)\n", 
			i + 1, 
			processes[i].ProcessName.c_str(), 
			processes[i].Architecture.c_str(),
			processes[i].ProcessId);
	}

	printf("\nEnter process index (1-%zu) or 0 to cancel: ", processes.size());
	fflush(stdout);
	char selectionStr[20];
	if (fgets(selectionStr, sizeof(selectionStr), stdin) == nullptr) {
		printf("Failed to read selection\n");
		return 0;
	}
	int selection = atoi(selectionStr);

	if (selection < 1 || selection > (int)processes.size()) {
		printf("Invalid selection\n");
		return 0;
	}

	DWORD selectedPID = processes[selection - 1].ProcessId;
	printf("\nSelected: %s (PID: %lu)\n", processes[selection - 1].ProcessName.c_str(), selectedPID);
	return selectedPID;
}

DWORD FindProcessByName(const char* processName) {
	PROCESSENTRY32W PE32 = {};
	PE32.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot failed!\n");
		printf("LastError : 0x%x\n", GetLastError());
		return 0;
	}

	DWORD PID = 0;
	BOOL bRet = Process32FirstW(hSnap, &PE32);
	char yn[3];

	int wlen = MultiByteToWideChar(CP_UTF8, 0, processName, -1, nullptr, 0);
	std::vector<wchar_t> wprocessName(wlen);
	MultiByteToWideChar(CP_UTF8, 0, processName, -1, &wprocessName[0], wlen);

	while (bRet) {
		if (_wcsicmp(PE32.szExeFile, &wprocessName[0]) == 0) {
			PID = PE32.th32ProcessID;
			
			int size_needed = WideCharToMultiByte(CP_UTF8, 0, PE32.szExeFile, -1, nullptr, 0, nullptr, nullptr);
			std::string procName(size_needed, 0);
			WideCharToMultiByte(CP_UTF8, 0, PE32.szExeFile, -1, &procName[0], size_needed, nullptr, nullptr);
			procName.pop_back();

			printf("Found process: %s (PID: %d)\n", procName.c_str(), PID);
			printf("Continue with this PID? [Y/N]: ");

			scanf_s("%2s", yn, 2);

			if (!strcmp((LPCSTR)yn, "y") || !strcmp((LPCSTR)yn, "Y"))
				break;

			printf("\n\n");
		}

		bRet = Process32NextW(hSnap, &PE32);
	}

	CloseHandle(hSnap);
	return PID;
}

HANDLE OpenTargetProcess(DWORD processId) {
	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION |
		PROCESS_CREATE_THREAD |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE,
		FALSE, processId);

	if (!hProcess) {
		printf("Could not open process for PID %d\n", processId);
		printf("LastError : 0X%x\n", GetLastError());
		return NULL;
	}

	return hProcess;
}

}
}
