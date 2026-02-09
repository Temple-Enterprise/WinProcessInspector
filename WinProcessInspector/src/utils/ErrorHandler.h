#pragma once

#include <Windows.h>
#include <string>

namespace WinProcessInspector {
namespace Utils {

	/**
	 * Error handling utilities for Windows API calls
	 */
	class ErrorHandler {
	public:
		/**
		 * Get the last error as a formatted string
		 * @return Error message string
		 */
		static std::wstring GetLastErrorString();

		/**
		 * Get error message for a specific error code
		 * @param errorCode Windows error code
		 * @return Error message string
		 */
		static std::wstring GetErrorString(DWORD errorCode);

		/**
		 * Format a Windows API error message
		 * @param apiName Name of the API that failed
		 * @param errorCode Windows error code (0 = use GetLastError())
		 * @return Formatted error message
		 */
		static std::wstring FormatApiError(const wchar_t* apiName, DWORD errorCode = 0);

		/**
		 * Check if last error indicates access denied
		 * @return true if access denied
		 */
		static bool IsAccessDenied();

		/**
		 * Check if last error indicates process not found
		 * @return true if process not found
		 */
		static bool IsProcessNotFound();
	};

} // namespace Utils
} // namespace WinProcessInspector
