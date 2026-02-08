#pragma once

#include <Windows.h>
#include <memory>

namespace RuntimeInspector {
namespace Core {

class HandleWrapper {
public:
	HandleWrapper() : m_Handle(INVALID_HANDLE_VALUE) {}
	explicit HandleWrapper(HANDLE handle) : m_Handle(handle) {}
	
	~HandleWrapper() {
		Close();
	}
	
	HandleWrapper(const HandleWrapper&) = delete;
	HandleWrapper& operator=(const HandleWrapper&) = delete;
	
	HandleWrapper(HandleWrapper&& other) noexcept : m_Handle(other.m_Handle) {
		other.m_Handle = INVALID_HANDLE_VALUE;
	}
	
	HandleWrapper& operator=(HandleWrapper&& other) noexcept {
		if (this != &other) {
			Close();
			m_Handle = other.m_Handle;
			other.m_Handle = INVALID_HANDLE_VALUE;
		}
		return *this;
	}
	
	HANDLE Get() const { return m_Handle; }
	operator HANDLE() const { return m_Handle; }
	bool IsValid() const { return m_Handle != nullptr && m_Handle != INVALID_HANDLE_VALUE; }
	
	void Reset(HANDLE handle = INVALID_HANDLE_VALUE) {
		Close();
		m_Handle = handle;
	}
	
	HANDLE Release() {
		HANDLE temp = m_Handle;
		m_Handle = INVALID_HANDLE_VALUE;
		return temp;
	}
	
private:
	void Close() {
		if (IsValid()) {
			CloseHandle(m_Handle);
			m_Handle = INVALID_HANDLE_VALUE;
		}
	}
	
	HANDLE m_Handle;
};

class IconWrapper {
public:
	IconWrapper() : m_Icon(nullptr) {}
	explicit IconWrapper(HICON icon) : m_Icon(icon) {}
	
	~IconWrapper() {
		Close();
	}
	
	IconWrapper(const IconWrapper&) = delete;
	IconWrapper& operator=(const IconWrapper&) = delete;
	
	IconWrapper(IconWrapper&& other) noexcept : m_Icon(other.m_Icon) {
		other.m_Icon = nullptr;
	}
	
	IconWrapper& operator=(IconWrapper&& other) noexcept {
		if (this != &other) {
			Close();
			m_Icon = other.m_Icon;
			other.m_Icon = nullptr;
		}
		return *this;
	}
	
	HICON Get() const { return m_Icon; }
	operator HICON() const { return m_Icon; }
	bool IsValid() const { return m_Icon != nullptr; }
	
	void Reset(HICON icon = nullptr) {
		Close();
		m_Icon = icon;
	}
	
	HICON Release() {
		HICON temp = m_Icon;
		m_Icon = nullptr;
		return temp;
	}
	
private:
	void Close() {
		if (IsValid()) {
			DestroyIcon(m_Icon);
			m_Icon = nullptr;
		}
	}
	
	HICON m_Icon;
};

}
}
