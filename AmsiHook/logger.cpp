#include "logger.hpp"
#include <filesystem>
#include <iostream>
#include <Windows.h>
#include <chrono>
#include <shlwapi.h>


#pragma comment(lib, "Shlwapi.lib")

std::string get_current_timestamp() 
{
    using namespace std::chrono;
    auto epoch = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    std::ostringstream oss;
    oss << epoch;
    return oss.str();
}

std::string get_process_name()
{
    char process_file_path[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, process_file_path, MAX_PATH);
    return PathFindFileNameA(process_file_path);  
}

Logger::Logger() {

    std::filesystem::path homeDir = std::getenv("USERPROFILE");
    if (homeDir.empty()) {
        std::cerr << "Unable to determine the user's home directory!" << std::endl;
    }

    // Append "Desktop" to the home directory
    std::filesystem::path desktopPath = homeDir / "Desktop";

    std::string timestamp = get_current_timestamp();
    std::string process_name = get_process_name();
    DWORD pid = GetCurrentProcessId();

    std::ostringstream logFileName;
    logFileName << timestamp << "_" << process_name << "_" << pid << "_" << ".log";

    // Construct the log file path
    std::filesystem::path logFilePath = desktopPath / logFileName.str();

    logFile_.open(logFilePath, std::ios::out | std::ios::app);
    if (!logFile_) {
        std::cerr << "Unable to open log file!" << std::endl;
    }
}

Logger::~Logger() 
{
    if (logFile_.is_open()) 
    {
        logFile_.close();
    }
}

Logger& Logger::getInstance() 
{
    static Logger instance;
    return instance;
}

void Logger::log_string(const std::string& message) 
{
    std::lock_guard<std::mutex> lock(mutex_);
    logFile_ << message << "\n" << std::endl;
}

void Logger::log_buffer(uintptr_t buffer, unsigned long length)
{
    std::lock_guard<std::mutex> lock(mutex_);

    const unsigned char* byteBuffer = reinterpret_cast<const unsigned char*>(buffer);
    std::ostringstream oss;

    for (size_t i = 0; i < length; i++) 
    {
        oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << static_cast<int>(byteBuffer[i]) << " ";
    }

    logFile_ << oss.str() << "\n" << std::endl;
}