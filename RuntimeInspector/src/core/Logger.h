#pragma once

#include <string>
#include <vector>
#include <mutex>

namespace RuntimeInspector {
namespace Core {

class Logger {
public:
	enum class Level {
		Info,
		Warning,
		Error
	};
	
	static Logger& GetInstance();
	
	void Log(Level level, const std::string& message);
	void LogInfo(const std::string& message);
	void LogWarning(const std::string& message);
	void LogError(const std::string& message);
	
	const std::vector<std::string>& GetMessages() const { return m_Messages; }
	void Clear();
	
private:
	Logger() = default;
	~Logger() = default;
	Logger(const Logger&) = delete;
	Logger& operator=(const Logger&) = delete;
	
	std::vector<std::string> m_Messages;
	mutable std::mutex m_Mutex;
	static constexpr size_t MAX_MESSAGES = 1000;
};

}
}
