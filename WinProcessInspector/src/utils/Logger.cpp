#include "Logger.h"
#include <sstream>
#include <iomanip>
#include <chrono>

namespace WinProcessInspector {
namespace Utils {

Logger& Logger::GetInstance() {
	static Logger instance;
	return instance;
}

void Logger::Log(Level level, const std::string& message) {
	std::lock_guard<std::mutex> lock(m_Mutex);
	
	auto now = std::chrono::system_clock::now();
	auto time = std::chrono::system_clock::to_time_t(now);
	std::tm tm;
	localtime_s(&tm, &time);
	
	std::ostringstream oss;
	oss << std::put_time(&tm, "%H:%M:%S") << " [";
	
	switch (level) {
		case Level::Info:
			oss << "INFO";
			break;
		case Level::Warning:
			oss << "WARN";
			break;
		case Level::Error:
			oss << "ERROR";
			break;
	}
	
	oss << "] " << message;
	
	m_Messages.push_back(oss.str());
	
	if (m_Messages.size() > MAX_MESSAGES) {
		m_Messages.erase(m_Messages.begin());
	}
}

void Logger::LogInfo(const std::string& message) {
	Log(Level::Info, message);
}

void Logger::LogWarning(const std::string& message) {
	Log(Level::Warning, message);
}

void Logger::LogError(const std::string& message) {
	Log(Level::Error, message);
}

void Logger::Clear() {
	std::lock_guard<std::mutex> lock(m_Mutex);
	m_Messages.clear();
}

}
}
