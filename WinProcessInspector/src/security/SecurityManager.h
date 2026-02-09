#pragma once

#include <Windows.h>
#include <string>
#include <vector>

namespace WinProcessInspector {
namespace Security {

	/**
	 * Represents a Windows privilege
	 */
	struct Privilege {
		std::wstring Name;
		bool Enabled;
		bool EnabledByDefault;
	};

	/**
	 * Represents a security identifier (SID)
	 */
	struct SecurityIdentifier {
		std::wstring Name;
		std::wstring Domain;
		SID_NAME_USE Type;
	};

	/**
	 * Integrity level enumeration
	 */
	enum class IntegrityLevel : DWORD {
		Untrusted = SECURITY_MANDATORY_UNTRUSTED_RID,
		Low = SECURITY_MANDATORY_LOW_RID,
		Medium = SECURITY_MANDATORY_MEDIUM_RID,
		MediumPlus = SECURITY_MANDATORY_MEDIUM_PLUS_RID,
		High = SECURITY_MANDATORY_HIGH_RID,
		System = SECURITY_MANDATORY_SYSTEM_RID,
		Protected = SECURITY_MANDATORY_PROTECTED_PROCESS_RID,
		Unknown = 0xFFFFFFFFU
	};

	/**
	 * Security manager for handling tokens, privileges, and access rights
	 * Uses RAII principles for safe resource management
	 */
	class SecurityManager {
	public:
		SecurityManager();
		~SecurityManager();

		// Non-copyable
		SecurityManager(const SecurityManager&) = delete;
		SecurityManager& operator=(const SecurityManager&) = delete;

		/**
		 * Enable a privilege for the current process
		 * @param privilegeName Name of the privilege (e.g., SE_DEBUG_NAME)
		 * @return true if successful, false otherwise
		 */
		bool EnablePrivilege(const wchar_t* privilegeName);

		/**
		 * Disable a privilege for the current process
		 * @param privilegeName Name of the privilege
		 * @return true if successful, false otherwise
		 */
		bool DisablePrivilege(const wchar_t* privilegeName);

		/**
		 * Check if a privilege is enabled
		 * @param privilegeName Name of the privilege
		 * @return true if enabled, false otherwise
		 */
		bool IsPrivilegeEnabled(const wchar_t* privilegeName) const;

		/**
		 * Get all privileges for a token
		 * @param hToken Token handle (nullptr for current process)
		 * @return Vector of privileges
		 */
		std::vector<Privilege> GetPrivileges(HANDLE hToken = nullptr) const;

		/**
		 * Get integrity level of a process
		 * @param processId Process ID (0 for current process)
		 * @return Integrity level
		 */
		IntegrityLevel GetProcessIntegrityLevel(DWORD processId = 0) const;

		/**
		 * Get groups (SIDs) for a token
		 * @param hToken Token handle (nullptr for current process)
		 * @return Vector of security identifiers
		 */
		std::vector<SecurityIdentifier> GetGroups(HANDLE hToken = nullptr) const;

		/**
		 * Open a process token with appropriate access rights
		 * @param processId Process ID
		 * @param desiredAccess Desired access rights
		 * @return Token handle (caller must close)
		 */
		static HANDLE OpenProcessToken(DWORD processId, DWORD desiredAccess = TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES);

		/**
		 * Elevate current process privileges (enable SE_DEBUG_NAME)
		 * @return 0 on success, error code on failure
		 */
		static int ElevatePrivileges();

	private:
		HANDLE m_hToken;
		bool m_bTokenOpened;

		bool OpenCurrentProcessToken();
		void CloseToken();
	};

	/**
	 * Convert integrity level to human-readable string
	 */
	std::wstring IntegrityLevelToString(IntegrityLevel level);

	/**
	 * Convert SID name use to human-readable string
	 */
	std::wstring SidNameUseToString(SID_NAME_USE use);

} // namespace Security
} // namespace WinProcessInspector
