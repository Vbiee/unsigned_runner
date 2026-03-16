#include <iostream>
#include <fstream>
#include <format>
#include <ctime>
#include <chrono>
#include <mutex>
#include <sstream>
#include <iomanip>

//#define FILE_LOG L"C:\\Temp\\svc.log"
#define FILE_LOG_SVC        L"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\NCS\\svc.log"
#define FILE_LOG_MONITOR    L"C:\\testFim\\monitor.log"
#define FILE_CONFIG         L"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\NCS\\config.ini"

class CLoggerW {
public:
    enum class Level {
        DEBUG,
        INFO,
        WARNING,
        ERR,
        CRITICAL
    };

    enum class Output {
        Console,
        File,
        Both
    };

    // Constructor set default Output + Level
    CLoggerW(Output out = Output::Console,
        Level defaultLevel = Level::INFO,
        const std::wstring& filename = L"log.txt")
        : output(out),
        defaultLevel(defaultLevel)
    {        
        logFile.open(filename, std::ios::app);
        
        if (output != Output::Console && !logFile.is_open()) {
            throw std::runtime_error("Cannot open log file");
        }
    }

    // Destructor - ensure logs are flushed
    ~CLoggerW() {
        std::lock_guard<std::mutex> lock(mtx);
        if (logFile.is_open()) {
            logFile.flush();
            logFile.close();
        }
    }
    
    // Log with default level
    template<typename... Args>
    void Log(const std::wstring& fmt, Args&&... args) {
        Log(defaultLevel, fmt, std::forward<Args>(args)...);
    }

    // Log with specified level
    template<typename... Args>
    void Log(Level level, const std::wstring& fmt, Args&&... args) {
        if (level < defaultLevel)
            return;

        std::wstring msg = std::vformat(fmt, std::make_wformat_args(args...));
        std::wstring logLine = std::format(L"[{}][{}] {}", currentTime(), LevelToWString(level), msg);
        std::lock_guard<std::mutex> lock(mtx); // thread-safe

        if (output == Output::Console || output == Output::Both) {
            std::wcout << logLine << std::endl;
        }
        if ((output == Output::File || output == Output::Both) && logFile.is_open()) {
            logFile << logLine << std::endl;
            // Force immediate write for errors and critical messages
            if (level >= Level::ERR) {
                logFile.flush();
            }
        }
    }

    // Overloaded convenience methods for each log level
    template<typename... Args>
    void Debug(const std::wstring& fmt, Args&&... args) { Log(Level::DEBUG, fmt, std::forward<Args>(args)...); }

    template<typename... Args>
    void Info(const std::wstring& fmt, Args&&... args) { Log(Level::INFO, fmt, std::forward<Args>(args)...); }

    template<typename... Args>
    void Warning(const std::wstring& fmt, Args&&... args) { Log(Level::WARNING, fmt, std::forward<Args>(args)...); }

    template<typename... Args>
    void Error(const std::wstring& fmt, Args&&... args) { Log(Level::ERR, fmt, std::forward<Args>(args)...); }

    template<typename... Args>
    void Critical(const std::wstring& fmt, Args&&... args) { Log(Level::CRITICAL, fmt, std::forward<Args>(args)...); }

    // FIM-specific: Log performance metrics
    void LogPerformance(const std::wstring& operation, double durationMs, size_t itemCount = 0) {
        if (itemCount > 0) {
            Info(L"[PERF] {} completed in {:.2f}ms ({} items, {:.2f} items/sec)", 
                 operation, durationMs, itemCount, (itemCount / durationMs) * 1000.0);
        } else {
            Info(L"[PERF] {} completed in {:.2f}ms", operation, durationMs);
        }
    }

    // FIM-specific: Log with context (e.g., thread ID, volume, operation type)
    template<typename... Args>
    void LogWithContext(Level level, const std::wstring& context, const std::wstring& fmt, Args&&... args) {
        std::wstring msg = std::vformat(fmt, std::make_wformat_args(args...));
        Log(level, L"[{}] {}", context, msg);
    }

    // Explicit flush method for critical sections
    void Flush() {
        std::lock_guard<std::mutex> lock(mtx);
        if (logFile.is_open()) {
            logFile.flush();
        }
    }

private:
    Output output;
    Level defaultLevel;
    std::wofstream logFile;
    std::mutex mtx;

    std::wstring currentTime() {
        using namespace std::chrono;
        auto now = system_clock::now();
        auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
        
        std::time_t t = system_clock::to_time_t(now);
        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        
        // Format with milliseconds: YYYY-MM-DD HH:MM:SS.mmm
        return std::format(L"{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}.{:03d}",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<int>(ms.count()));
    }

    static std::wstring LevelToWString(Level level) {
        switch (level) {
        case Level::DEBUG: return L"DEBUG";
        case Level::INFO: return L"INFO";
        case Level::WARNING: return L"WARNING";
        case Level::ERR: return L"ERROR";
        case Level::CRITICAL: return L"CRITICAL";
        }
        return L"UNKNOWN";
    }

    /*std::wstring GetCurrentDirWithFile(const std::wstring& fileName)
    {
        wchar_t buffer[MAX_PATH];
        DWORD len = GetCurrentDirectoryW(MAX_PATH, buffer);
        if (len == 0 || len > MAX_PATH)
            return L""; // Error or path too long

        std::wstring path(buffer);

        // Make sure path ends with a backslash '\'
        if (!path.empty() && path.back() != L'\\')
            path += L'\\';

        path += fileName;
        return path;
    }*/

};
