#include "ErrorHandler.h"
#include <sstream>

namespace WinProcessInspector {
namespace Utils {

std::wstring ErrorHandler::GetLastErrorString() {
	return GetErrorString(GetLastError());
}

std::wstring ErrorHandler::GetErrorString(DWORD errorCode) {
	if (errorCode == 0) {
		return L"Success";
	}

	LPWSTR messageBuffer = nullptr;
	DWORD length = FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr,
		errorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<LPWSTR>(&messageBuffer),
		0,
		nullptr
	);

	std::wstring message;
	if (length > 0 && messageBuffer) {
		message = messageBuffer;
		LocalFree(messageBuffer);
	} else {
		std::wostringstream oss;
		oss << L"Error code: 0x" << std::hex << errorCode;
		message = oss.str();
	}

	return message;
}

std::wstring ErrorHandler::FormatApiError(const wchar_t* apiName, DWORD errorCode) {
	if (errorCode == 0) {
		errorCode = GetLastError();
	}

	std::wostringstream oss;
	oss << apiName << L"() failed: " << GetErrorString(errorCode);
	return oss.str();
}

bool ErrorHandler::IsAccessDenied() {
	return GetLastError() == ERROR_ACCESS_DENIED;
}

bool ErrorHandler::IsProcessNotFound() {
	return GetLastError() == ERROR_INVALID_PARAMETER;
}

} // namespace Utils
} // namespace WinProcessInspector
