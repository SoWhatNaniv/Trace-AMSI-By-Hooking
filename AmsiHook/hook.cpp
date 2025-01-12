#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include <amsi.h>
#include <DbgHelp.h>
#include <print>
#include <format>

#include "hook.hpp"
#include "safetyhook.hpp"
#include "logger.hpp"


EXTERN_C IMAGE_DOS_HEADER __ImageBase;


SafetyHookInline sh_amsi_scan_buffer{};
SafetyHookInline sh_amsi_scan_string{};
SafetyHookInline sh_create_process_w{};


std::string convert_LPCWSTR_to_string(LPCWSTR wide_string)
{
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wide_string, -1, nullptr, 0, nullptr, nullptr);
    std::string result(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide_string, -1, &result[0], sizeNeeded, nullptr, nullptr);
    return result;
}


uintptr_t get_current_process_handle()
{
    char filename[MAX_PATH];
    GetModuleFileNameA(NULL, filename, sizeof(filename));

    return reinterpret_cast<uintptr_t>(GetModuleHandleA(filename));
}


uintptr_t get_function_address(const char* module_name, const char* function_name) {
    // Get the module handle for the specified DLL (e.g., amsi.dll)
    HMODULE module_handle = GetModuleHandleA(module_name);
    if (!module_handle) {

        Logger::getInstance().log_string(
            std::format("Failed to get module handle for {}", module_name)
        );

        Logger::getInstance().log_string(
            std::format("Will load {} manually", module_name)
        );

        module_handle = LoadLibraryA(module_name);
    }

    if (!module_handle) {
        Logger::getInstance().log_string(
            std::format("Failed to load module {}", module_name)
        );
        return 0;
    }

    Logger::getInstance().log_string(
        std::format("{} loaded, module address: 0x{:X}", module_name, reinterpret_cast<uintptr_t>(module_handle))
    );

    // Get the address of the specified function (e.g., AmsiScanBuffer)
    FARPROC function_address = GetProcAddress(module_handle, function_name);
    if (!function_address) {
        Logger::getInstance().log_string(
            std::format("Failed to get function address for {}", function_name)
        );
        return 0;
    }

    Logger::getInstance().log_string(
        std::format("{} function address: 0x{:X}", function_name, reinterpret_cast<uintptr_t>(function_address))
    );

    // Return the function address as a uintptr_t
    return reinterpret_cast<uintptr_t>(function_address);
}


HRESULT
#if _WIN32 and !_WIN64
__stdcall
#endif
hook_amsi_scan_buffer(HAMSICONTEXT amsiContext, uintptr_t buffer, ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT* result)
{

    Logger::getInstance().log_string("AmsiScanBuffer:");

    if (buffer == NULL || length == 0) {
        Logger::getInstance().log_string("Buffer is null or length is zero.");
        return 1;
    }

    Logger::getInstance().log_buffer(buffer, length);

    return sh_amsi_scan_buffer.call<HRESULT>(amsiContext, buffer, length, contentName, amsiSession, result);
}

HRESULT
#if _WIN32 and !_WIN64
__stdcall
#endif
hook_amsi_scan_string(HAMSICONTEXT amsiContext, LPCWSTR string, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT* result)
{

    Logger::getInstance().log_string("AmsiScanString:");
    Logger::getInstance().log_string(convert_LPCWSTR_to_string(string));

    return sh_amsi_scan_string.call<HRESULT>(amsiContext, string, contentName, amsiSession, result);
}

BOOL
#if _WIN32 and !_WIN64
__stdcall
#endif
hook_create_process_w(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{


    if (!sh_create_process_w.call<BOOL>(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation))
    {
        Logger::getInstance().log_string(
            std::format("Creating process in suspended mode failed; error code = 0x{:X}", GetLastError())
        );
        return sh_create_process_w.call<BOOL>(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    char amsihook_path[MAX_PATH];
    GetModuleFileNameA((HINSTANCE)&__ImageBase, amsihook_path, MAX_PATH);
    size_t amsihook_path_len = strlen(amsihook_path) + 1;

    void* allocated_memory;
    HANDLE hThread;

    allocated_memory = VirtualAllocEx(lpProcessInformation->hProcess, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (allocated_memory == NULL) {
        Logger::getInstance().log_string(
            std::format("VirtualAllocEx failed; error code = 0x{:X}", GetLastError())
        );
        return 0;
    }

    if (WriteProcessMemory(lpProcessInformation->hProcess, allocated_memory, amsihook_path, amsihook_path_len, NULL) == 0) {
        Logger::getInstance().log_string(
            std::format("WriteProcessMemory failed; error code = 0x{:X}", GetLastError())
        );
        return 0;
    }

    hThread = CreateRemoteThread(lpProcessInformation->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocated_memory, 0, NULL);
    if (hThread == NULL) {
        Logger::getInstance().log_string(
            std::format("CreateRemoteThread failed; error code = 0x{:X}", GetLastError())
        );
        return 0;
    }

    if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) {
        Logger::getInstance().log_string(
            std::format("WaitForSingleObject failed; error code = 0x{:X}", GetLastError())
        );
        return 0;
    }

    CloseHandle(hThread);

    if (ResumeThread(lpProcessInformation->hThread) == -1) {
        Logger::getInstance().log_string(
            std::format("ResumeThread failed; error code = 0x{:X}", GetLastError())
        );
        return 0;
    }

    return 1;
}



uint64_t hook()
{

    const char* amsi_module_name = "amsi.dll";
    const char* amsi_scan_buffer = "AmsiScanBuffer";
    const char* amsi_scan_string = "AmsiScanString";

    const char* kernel_module_name = "Kernel32.dll";
    const char* create_process_w = "CreateProcessW";


    uintptr_t addr_create_process_w = get_function_address(kernel_module_name, create_process_w);
    uintptr_t addr_amsi_scan_buffer = get_function_address(amsi_module_name, amsi_scan_buffer);
    uintptr_t addr_amsi_scan_string = get_function_address(amsi_module_name, amsi_scan_string);

    sh_create_process_w = safetyhook::create_inline(reinterpret_cast<void*>(addr_create_process_w), reinterpret_cast<void*>(hook_create_process_w));
    sh_amsi_scan_buffer = safetyhook::create_inline(reinterpret_cast<void*>(addr_amsi_scan_buffer), reinterpret_cast<void*>(hook_amsi_scan_buffer));
    sh_amsi_scan_string = safetyhook::create_inline(reinterpret_cast<void*>(addr_amsi_scan_string), reinterpret_cast<void*>(hook_amsi_scan_string));

    return 0;
}
