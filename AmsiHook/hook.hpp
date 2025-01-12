#pragma once

#ifndef HOOK_HPP
#define HOOK_HPP

#include <cstdint> // For uintptr_t
#include <string>


std::string convert_LPCWSTR_to_string(LPCWSTR wide_string);
uintptr_t get_current_process_handle();
uintptr_t get_function_address(const char* module_name, const char* function_name);
uint64_t hook();

#endif // HOOK_HPP