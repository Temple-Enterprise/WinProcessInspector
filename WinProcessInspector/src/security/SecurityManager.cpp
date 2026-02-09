#include "SecurityManager.h"
#include "../utils/ErrorHandler.h"
#include <sddl.h>
#include <sstream>

namespace WinProcessInspector {
namespace Security {

SecurityManager::SecurityManager() 
	: m_hToken(nullptr)
	, m_bTokenOpened(false)
{
	OpenCurrentProcessToken();
}

SecurityManager::~SecurityManager() {
	CloseToken();
}

bool SecurityManager::OpenCurrentProcessToken() {
	if (m_bTokenOpened) {
		return true;
	}

	HANDLE hProcess = GetCurrentProcess();
	if (!::OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &m_hToken)) {
		// Try impersonating self if no token exists
		if (GetLastError() == ERROR_NO_TOKEN) {
			if (!ImpersonateSelf(SecurityImpersonation)) {
				return false;
			}
			if (!::OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &m_hToken)) {
				return false;
			}
		} else {
			return false;
		}
	}

	m_bTokenOpened = true;
	return true;
}

void SecurityManager::CloseToken() {
	if (m_hToken && m_hToken != INVALID_HANDLE_VALUE) {
		CloseHandle(m_hToken);
		m_hToken = nullptr;
		m_bTokenOpened = false;
	}
}

bool SecurityManager::EnablePrivilege(const wchar_t* privilegeName) {
	if (!m_bTokenOpened && !OpenCurrentProcessToken()) {
		return false;
	}

	LUID luid;
	if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
		return false;
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(m_hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
		return false;
	}

	return GetLastError() == ERROR_SUCCESS;
}

bool SecurityManager::DisablePrivilege(const wchar_t* privilegeName) {
	if (!m_bTokenOpened && !OpenCurrentProcessToken()) {
		return false;
	}

	LUID luid;
	if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
		return false;
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(m_hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
		return false;
	}

	return GetLastError() == ERROR_SUCCESS;
}

bool SecurityManager::IsPrivilegeEnabled(const wchar_t* privilegeName) const {
	if (!m_bTokenOpened) {
		return false;
	}

	LUID luid;
	if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
		return false;
	}

	PRIVILEGE_SET privileges;
	privileges.PrivilegeCount = 1;
	privileges.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privileges.Privilege[0].Luid = luid;
	privileges.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL result = FALSE;
	PrivilegeCheck(m_hToken, &privileges, &result);
	return result == TRUE;
}

std::vector<Privilege> SecurityManager::GetPrivileges(HANDLE hToken) const {
	std::vector<Privilege> privileges;
	HANDLE token = hToken ? hToken : m_hToken;

	if (!token || token == INVALID_HANDLE_VALUE) {
		return privileges;
	}

	DWORD length = 0;
	GetTokenInformation(token, TokenPrivileges, nullptr, 0, &length);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		return privileges;
	}

	std::vector<BYTE> buffer(length);
	PTOKEN_PRIVILEGES tp = reinterpret_cast<PTOKEN_PRIVILEGES>(buffer.data());
	if (!GetTokenInformation(token, TokenPrivileges, tp, length, &length)) {
		return privileges;
	}

	for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
		Privilege priv;
		WCHAR name[256];
		DWORD nameLen = sizeof(name) / sizeof(name[0]);
		if (LookupPrivilegeNameW(nullptr, &tp->Privileges[i].Luid, name, &nameLen)) {
			priv.Name = name;
		}
		priv.Enabled = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
		priv.EnabledByDefault = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0;
		privileges.push_back(priv);
	}

	return privileges;
}

IntegrityLevel SecurityManager::GetProcessIntegrityLevel(DWORD processId) const {
	HANDLE hToken = nullptr;
	if (processId == 0) {
		hToken = m_hToken;
	} else {
		hToken = OpenProcessToken(processId, TOKEN_QUERY);
		if (!hToken) {
			return IntegrityLevel::Unknown;
		}
	}

	DWORD length = 0;
	GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &length);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		if (processId != 0) {
			CloseHandle(hToken);
		}
		return IntegrityLevel::Unknown;
	}

	std::vector<BYTE> buffer(length);
	PTOKEN_MANDATORY_LABEL ptml = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(buffer.data());
	if (!GetTokenInformation(hToken, TokenIntegrityLevel, ptml, length, &length)) {
		if (processId != 0) {
			CloseHandle(hToken);
		}
		return IntegrityLevel::Unknown;
	}

	if (processId != 0) {
		CloseHandle(hToken);
	}

	DWORD integrityLevel = *GetSidSubAuthority(ptml->Label.Sid, 
		static_cast<DWORD>(*GetSidSubAuthorityCount(ptml->Label.Sid) - 1));

	if (integrityLevel < SECURITY_MANDATORY_LOW_RID) {
		return IntegrityLevel::Untrusted;
	} else if (integrityLevel < SECURITY_MANDATORY_MEDIUM_RID) {
		return IntegrityLevel::Low;
	} else if (integrityLevel < SECURITY_MANDATORY_HIGH_RID) {
		return IntegrityLevel::Medium;
	} else if (integrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
		return IntegrityLevel::High;
	} else {
		return IntegrityLevel::System;
	}
}

std::vector<SecurityIdentifier> SecurityManager::GetGroups(HANDLE hToken) const {
	std::vector<SecurityIdentifier> groups;
	HANDLE token = hToken ? hToken : m_hToken;

	if (!token || token == INVALID_HANDLE_VALUE) {
		return groups;
	}

	DWORD length = 0;
	GetTokenInformation(token, TokenGroups, nullptr, 0, &length);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		return groups;
	}

	std::vector<BYTE> buffer(length);
	PTOKEN_GROUPS tg = reinterpret_cast<PTOKEN_GROUPS>(buffer.data());
	if (!GetTokenInformation(token, TokenGroups, tg, length, &length)) {
		return groups;
	}

	for (DWORD i = 0; i < tg->GroupCount; ++i) {
		SecurityIdentifier sid;
		WCHAR name[256];
		WCHAR domain[256];
		DWORD nameLen = sizeof(name) / sizeof(name[0]);
		DWORD domainLen = sizeof(domain) / sizeof(domain[0]);
		SID_NAME_USE use;

		if (LookupAccountSidW(nullptr, tg->Groups[i].Sid, name, &nameLen, domain, &domainLen, &use)) {
			sid.Name = name;
			sid.Domain = domain;
			sid.Type = use;
			groups.push_back(sid);
		}
	}

	return groups;
}

HANDLE SecurityManager::OpenProcessToken(DWORD processId, DWORD desiredAccess) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
	if (!hProcess) {
		return nullptr;
	}

	HANDLE hToken = nullptr;
	if (!::OpenProcessToken(hProcess, desiredAccess, &hToken)) {
		CloseHandle(hProcess);
		return nullptr;
	}

	CloseHandle(hProcess);
	return hToken;
}

int SecurityManager::ElevatePrivileges() {
	HANDLE hToken = nullptr;
	if (!::OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		if (GetLastError() == ERROR_NO_TOKEN) {
			if (!ImpersonateSelf(SecurityImpersonation)) {
				return GetLastError();
			}
			if (!::OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
				return GetLastError();
			}
		} else {
			return GetLastError();
		}
	}

	LUID luid;
	if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
		CloseHandle(hToken);
		return GetLastError();
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
		CloseHandle(hToken);
		return GetLastError();
	}

	CloseHandle(hToken);
	return GetLastError() == ERROR_SUCCESS ? 0 : GetLastError();
}

std::wstring IntegrityLevelToString(IntegrityLevel level) {
	switch (level) {
		case IntegrityLevel::Untrusted:
			return L"Untrusted";
		case IntegrityLevel::Low:
			return L"Low";
		case IntegrityLevel::Medium:
			return L"Medium";
		case IntegrityLevel::MediumPlus:
			return L"Medium+";
		case IntegrityLevel::High:
			return L"High";
		case IntegrityLevel::System:
			return L"System";
		case IntegrityLevel::Protected:
			return L"Protected";
		default:
			return L"Unknown";
	}
}

std::wstring SidNameUseToString(SID_NAME_USE use) {
	switch (use) {
		case SidTypeUser:
			return L"User";
		case SidTypeGroup:
			return L"Group";
		case SidTypeDomain:
			return L"Domain";
		case SidTypeAlias:
			return L"Alias";
		case SidTypeWellKnownGroup:
			return L"Well Known Group";
		case SidTypeDeletedAccount:
			return L"Deleted Account";
		case SidTypeInvalid:
			return L"Invalid";
		case SidTypeUnknown:
			return L"Unknown";
		case SidTypeComputer:
			return L"Computer";
		case SidTypeLabel:
			return L"Label";
		default:
			return L"Unknown";
	}
}

} // namespace Security
} // namespace WinProcessInspector
