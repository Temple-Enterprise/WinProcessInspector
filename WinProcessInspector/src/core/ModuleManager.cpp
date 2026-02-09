#include "ModuleManager.h"
#include "HandleWrapper.h"
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <shlwapi.h>
#include <wincrypt.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")

namespace WinProcessInspector {
namespace Core {

std::vector<ModuleInfo> ModuleManager::EnumerateModules(DWORD processId) const {
	std::vector<ModuleInfo> modules;

	HandleWrapper hProcess(::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId));
	if (!hProcess.IsValid()) {
		return modules; // Access denied or process not found
	}

	HMODULE hMods[1024];
	DWORD cbNeeded = 0;

	if (!EnumProcessModules(hProcess.Get(), hMods, sizeof(hMods), &cbNeeded)) {
		return modules;
	}

	DWORD moduleCount = cbNeeded / sizeof(HMODULE);
	if (moduleCount > 1024) {
		moduleCount = 1024;
	}

	for (DWORD i = 0; i < moduleCount; ++i) {
		ModuleInfo info;

		// Get module file path
		WCHAR modPath[MAX_PATH] = {};
		if (GetModuleFileNameExW(hProcess.Get(), hMods[i], modPath, MAX_PATH)) {
			info.FullPath = modPath;
			info.Name = ExtractFileName(modPath);

			// Get module information
			MODULEINFO modInfo = {};
			if (GetModuleInformation(hProcess.Get(), hMods[i], &modInfo, sizeof(modInfo))) {
				info.BaseAddress = reinterpret_cast<ULONG_PTR>(modInfo.lpBaseOfDll);
				info.Size = modInfo.SizeOfImage;
			}

			// Check if file is missing
			info.IsMissing = IsFileMissing(info.FullPath);

			// Check if module is signed (only if file exists)
			if (!info.IsMissing) {
				info.IsSigned = IsModuleSigned(info.FullPath, info.SignatureInfo);
			}

			modules.push_back(info);
		}
	}

	return modules;
}

bool ModuleManager::IsFileMissing(const std::wstring& filePath) const {
	if (filePath.empty()) {
		return true;
	}

	DWORD attributes = GetFileAttributesW(filePath.c_str());
	return (attributes == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND);
}

bool ModuleManager::IsModuleSigned(const std::wstring& filePath, std::wstring& signatureInfo) const {
	WINTRUST_FILE_INFO fileInfo = {};
	fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	fileInfo.pcwszFilePath = filePath.c_str();
	fileInfo.hFile = nullptr;
	fileInfo.pgKnownSubject = nullptr;

	GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA trustData = {};
	trustData.cbStruct = sizeof(WINTRUST_DATA);
	trustData.pPolicyCallbackData = nullptr;
	trustData.pSIPClientData = nullptr;
	trustData.dwUIChoice = WTD_UI_NONE;
	trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	trustData.dwUnionChoice = WTD_CHOICE_FILE;
	trustData.pFile = &fileInfo;
	trustData.dwStateAction = WTD_STATEACTION_VERIFY;
	trustData.hWVTStateData = nullptr;
	trustData.pwszURLReference = nullptr;
	trustData.dwProvFlags = WTD_SAFER_FLAG;
	trustData.dwUIContext = 0;

	LONG status = WinVerifyTrust(nullptr, &policyGUID, &trustData);

	// Cleanup
	trustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(nullptr, &policyGUID, &trustData);

	if (status == ERROR_SUCCESS) {
		// Try to get certificate information
		HCERTSTORE hStore = nullptr;
		HCRYPTMSG hMsg = nullptr;
		DWORD dwEncoding = 0;
		DWORD dwContentType = 0;
		DWORD dwFormatType = 0;

		if (CryptQueryObject(
			CERT_QUERY_OBJECT_FILE,
			filePath.c_str(),
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
			CERT_QUERY_FORMAT_FLAG_BINARY,
			0,
			&dwEncoding,
			&dwContentType,
			&dwFormatType,
			&hStore,
			&hMsg,
			nullptr)) {

			DWORD certCount = 0;
			DWORD certSize = sizeof(certCount);
			if (CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &certCount, &certSize)) {
				if (certCount > 0) {
					// Get signer info
					DWORD signerInfoSize = 0;
					CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize);
					if (signerInfoSize > 0) {
						std::vector<BYTE> signerInfo(signerInfoSize);
						if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfo.data(), &signerInfoSize)) {
							signatureInfo = L"Signed";
						}
					}
				}
			}

			if (hMsg) CryptMsgClose(hMsg);
			if (hStore) CertCloseStore(hStore, 0);
		}

		return true;
	}

	return false;
}

std::wstring ModuleManager::ExtractFileName(const std::wstring& fullPath) const {
	if (fullPath.empty()) {
		return L"";
	}

	size_t lastSlash = fullPath.find_last_of(L"\\/");
	if (lastSlash != std::wstring::npos && lastSlash + 1 < fullPath.length()) {
		return fullPath.substr(lastSlash + 1);
	}

	return fullPath;
}

} // namespace Core
} // namespace WinProcessInspector
