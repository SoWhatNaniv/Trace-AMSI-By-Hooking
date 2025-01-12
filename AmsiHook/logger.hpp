#pragma once

#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>
#include <mutex>
#include <fstream>

class Logger {
public:
    // Get the singleton instance
    static Logger& getInstance();

    // Delete copy constructor and assignment operator
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    // Log a string 
    void log_string(const std::string& message);
    // Log a buffer as hex values
    void log_buffer(uintptr_t buffer, unsigned long length);

private:
    std::ofstream logFile_;
    std::mutex mutex_;

    // Private constructor and destructor
    Logger();
    ~Logger();
};

#endif // LOGGER_HPP