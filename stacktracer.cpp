// stacktracer.cpp
#include "stacktracer.h"
#include <algorithm>	// for std::reverse()
#include <fstream>		// for std::ifstream
#include <sstream>		// for istringstream, stringstream, getline()
#include <array>		// for std::array
#include <memory>		// for std::unique_ptr
#include <signal.h>		// for signal()
#include <limits.h>		// for PATH_MAX

#if defined(STACK_TRACER_OS_WINDOWS)
#include <Windows.h>
#include <DbgHelp.h>
#pragma comment(lib, "DbgHelp.lib")

#elif defined(STACK_TRACER_OS_LINUX)
#include <unistd.h>		// for getpid(), readlink()
#include <libgen.h>		// for basename()
#include <cxxabi.h>		// for abi::__cxa_demangle()
#include <execinfo.h>	// backtrace, backtrace_symbols (This library doesn't support ARM architecture.)

#endif

// Define static member variables
#if defined(STACK_TRACER_OS_WINDOWS)
std::atomic<bool> StackTracer::m_is_symbol_initialized(false);
#endif
std::mutex StackTracer::m_mutex;
std::map< long long, std::vector<std::pair<void*, std::string>> > StackTracer::m_trace_map;

StackTracer::StackTracer() {
    // TODO :
}

StackTracer::~StackTracer() {
    // TODO :
}

#if defined(STACK_TRACER_OS_WINDOWS)
void StackTracer::_initialize_symbols() {
	std::lock_guard<std::mutex> lock(m_mutex);

	// Check the current state
	if (m_is_symbol_initialized.load()) {
		// Already initialized
		return;
	}

	// Get a handle of the current process
	HANDLE process_handle = GetCurrentProcess();

	// Initialize symbols
	SymInitialize(process_handle, NULL, TRUE);
	SymSetOptions(SYMOPT_DEFERRED_LOADS);

	// Register to call the symbol cleanup function when the program terminates
	atexit(StackTracer::_cleanup_symbols);

	// Switch the flag
	m_is_symbol_initialized.store(true);
}

void StackTracer::_cleanup_symbols() {
	SymCleanup(GetCurrentProcess());
}

#endif

void StackTracer::register_exception_handler() {
#if defined(STACK_TRACER_OS_WINDOWS)
	// Activate symbols (for Windows only)
	StackTracer::_initialize_symbols();

	// Set unhandled exception filter for SEH(Structured Exception Handling) (for Windows only)
	SetUnhandledExceptionFilter((PTOP_LEVEL_EXCEPTION_FILTER)StackTracer::_unhandled_exception_handler);
#endif

	// Register an exception handler for segment fault
	signal(SIGABRT, _backtrace_stackframe);	// Aborted (core dumped)
	signal(SIGSEGV, _backtrace_stackframe);	// Segment fault (It is limited on Windows)
	signal(SIGILL, _backtrace_stackframe);	// Illegal instruction
	signal(SIGFPE, _backtrace_stackframe);  // Erroneous arithmetic operation
#if defined(STACK_TRACER_OS_LINUX)
	signal(SIGBUS, _backtrace_stackframe);  // Bus error (for Linux only)
#endif
}

long long StackTracer::_capture_current_stackframe(long long thread_id, unsigned int skip_depth, bool enable_skip_capture_routines) {
#ifdef NDEBUG
	// If NDEBUG is defined, do nothing.
	return thread_id;
#endif

#if defined(STACK_TRACER_OS_WINDOWS)
	// Activate symbols (for Windows only)
	StackTracer::_initialize_symbols();
#endif

#if defined(STACK_TRACER_OS_WINDOWS)
	// Capture the current stackframe
	CONTEXT context;
	RtlCaptureContext(&context);

	STACKFRAME64 stackframe = {0, };
#ifdef _M_IX86
	DWORD machine_type = IMAGE_FILE_MACHINE_I386;
	stackframe.AddrPC.Offset = context.Eip;
	stackframe.AddrPC.Mode = AddrModeFlat;
	stackframe.AddrFrame.Offset = context.Ebp;
	stackframe.AddrFrame.Mode = AddrModeFlat;
	stackframe.AddrStack.Offset = context.Esp;
	stackframe.AddrStack.Mode = AddrModeFlat;
#elif _M_X64
	DWORD machine_type = IMAGE_FILE_MACHINE_AMD64;
	stackframe.AddrPC.Offset = context.Rip;
	stackframe.AddrPC.Mode = AddrModeFlat;
	stackframe.AddrFrame.Offset = context.Rsp;
	stackframe.AddrFrame.Mode = AddrModeFlat;
	stackframe.AddrStack.Offset = context.Rsp;
	stackframe.AddrStack.Mode = AddrModeFlat;
#else
#error "Unsupported platform"
#endif

	// Get handles of the current process and thread
	HANDLE process_handle = GetCurrentProcess();
	HANDLE thread_handle = GetCurrentThread();

	// Declare a temporary buffer to get virtual addresses
	std::vector<DWORD64> virtual_addresses;

	// Capture the backtrace
	while(StackWalk64(machine_type, process_handle, thread_handle, &stackframe, &context, nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) {
		// Check if there are any more stackframes left to trace
		if(stackframe.AddrPC.Offset == 0) {
			break;
		}
		// Get target addresses
		virtual_addresses.push_back(stackframe.AddrPC.Offset);
	}

#elif defined(STACK_TRACER_OS_LINUX)
	// Capture the current stackframe
	void* virtual_addresses[1024] = {0, };
    int trace_count = backtrace(virtual_addresses, 1024);

	// Check the validation
	if (trace_count < skip_depth) {
		throw std::runtime_error("failed to backtrace the stack frame");
	}

#endif

	// Declare the temporary buffer
	std::vector<std::pair<void*, std::string>> buffer;

#if defined(STACK_TRACER_OS_WINDOWS)
	// Push the results of backtracing the stack frame onto the buffer
	for (std::vector<DWORD64>::const_iterator it=virtual_addresses.begin(); it!=virtual_addresses.end(); ++it) {
		// Initialize a temporary buffer to get symbol informations
		char symbol_buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)] = {0, };
		SYMBOL_INFO* symbol = reinterpret_cast<SYMBOL_INFO*>(symbol_buffer);
		symbol->MaxNameLen = MAX_SYM_NAME;
		symbol->SizeOfStruct = sizeof(SYMBOL_INFO);

		// Get a symbol information from the virtual address
		// (also, convert the virtual addresses to correct addresses)
		std::string symbol_info;
		if(SymFromAddr(process_handle, *it, nullptr, symbol)) {
			symbol_info = symbol->Name;
		}
		else {
			symbol_info = std::string("Unknown function [") + StackTracer::convert_decimal_to_hex((uintptr_t)*it) + "]";
		}
		
		if (enable_skip_capture_routines) {
			if (symbol_info.find("StackTracer") != std::string::npos) {
				if (symbol_info.find("capture_current_stackframe") != std::string::npos
					|| symbol_info.find("backtrace_stackframe") != std::string::npos
					|| symbol_info.find("unhandled_exception_handler") != std::string::npos) {
					continue;
				}
			}
		}

		if(skip_depth > 0) {
			--skip_depth;
			continue;
		}

		buffer.push_back(std::pair<void*, std::string>((void*)*it, symbol_info));
	}

#elif defined(STACK_TRACER_OS_LINUX)
	// Get names of functions from the backtrace list
    char** symbols = backtrace_symbols(virtual_addresses, trace_count);

	// Check the validation
	if (symbols == nullptr) {
		throw std::runtime_error("failed to get symbol information");
	}

	// Change to the smart pointer
	std::unique_ptr<char*, decltype(&free)> symbols_ptr(symbols, &free);


	// Push the results of backtracing the stack frame onto the buffer
	for (int i=0; i<trace_count; ++i) {
		std::string symbol_info(symbols_ptr.get()[i]);

		if (enable_skip_capture_routines) {
			if (symbol_info.find("StackTracer") != std::string::npos) {
				if (symbol_info.find("capture_current_stackframe") != std::string::npos
					|| symbol_info.find("backtrace_stackframe") != std::string::npos) {
					continue;
				}
			}

#if defined(__SANITIZE_ADDRESS__)
			if (symbol_info.find("libasan.so") != std::string::npos) {
				continue;
			}
#endif
		}

		if (skip_depth > 0) {
			--skip_depth;
			continue;
		}

		buffer.push_back(std::pair<void*, std::string>(virtual_addresses[i], symbol_info));
    }

#endif

	// Reorder the elements in the opposite order
	std::reverse(buffer.begin(), buffer.end());

	// Safely lock the mutex
	std::lock_guard<std::mutex> lock(m_mutex);

	// Get a reference to the static buffer to store the backtrace list
	std::vector<std::pair<void*, std::string>>& backtrace_list = m_trace_map[thread_id];

	// Push the re-ordered backtrace list onto the static buffer
	backtrace_list.insert(backtrace_list.end(), buffer.begin(), buffer.end());

	return thread_id;
}

long long StackTracer::capture_current_stackframe(long long thread_id, unsigned int skip_depth) {
	return _capture_current_stackframe(thread_id, skip_depth, true);
}

long long StackTracer::capture_current_stackframe(std::thread::id thread_id, unsigned int skip_depth) {
	return _capture_current_stackframe(_translate_thread_id(thread_id), skip_depth, true);
}

long long StackTracer::capture_current_stackframe() {
	return _capture_current_stackframe(_translate_thread_id(std::this_thread::get_id()), 0, true);
}

std::string StackTracer::get_traceback_log() {
	// Get the current thread id
	long long thread_id = _translate_thread_id(std::this_thread::get_id());

	// Initialize a buffer for backtrace logs.
	std::string trace_log("Traceback (most recent call last):");

	// Safely lock the mutex
	std::lock_guard<std::mutex> lock(m_mutex);

	// Get a reference to the buffer to get the backtrace list
	std::vector<std::pair<void*, std::string>>& buffer = m_trace_map[thread_id];

	// Check the validation
	if (buffer.size() == 0) {
		trace_log += std::string("\n  (N/A)");
		trace_log += std::string("\nnote: To avoid performance degradation, stackframe is not captured if NDEBUG is defined.");
		trace_log += std::string("\n      Also, to get correct results you need to turn off optimizations and enable the -g, -rdynamic flags.");
		return trace_log;
	}

#if defined(STACK_TRACER_OS_WINDOWS)
	// Get a handle of the current process
	HANDLE process_handle = GetCurrentProcess();

	// Generate traceback logs by analyzing symbol informations
	for(std::vector<std::pair<void*, std::string>>::const_iterator it=buffer.cbegin(); it!=buffer.cend(); ++it) {
		// Initialize essential parameters
		DWORD displacement = 0;
		IMAGEHLP_LINE64 line_data;
		line_data.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

		// Get filename and line number
		if(SymGetLineFromAddr64(process_handle, (DWORD64)(it->first) - 1, &displacement, &line_data)) {
			// Record the more detail informations in POSIX standard style
			std::string filename_and_linenumber = std::string(line_data.FileName) + ":" + std::to_string(line_data.LineNumber);
			trace_log += std::string("\n  File \"") + filename_and_linenumber + "\", in " + it->second;
		}
		else {
			// Record a basic symbol information (no use)
			//trace_log += std::string("\n  Unknown location in ") + it->second;
			continue;
		}
	}

#elif defined(STACK_TRACER_OS_LINUX)
	// Get the base address of the current process
	uintptr_t base_address_decimal = get_base_address_decimal();

	// Get the current execution program name
	std::vector<std::string> program_names = get_program_name();

	// Generate traceback logs by analyzing symbol informations
	for (std::vector<std::pair<void*, std::string>>::const_iterator it=buffer.cbegin(); it!=buffer.cend(); ++it) {
		// Convert the virtual addresses to correct addresses
		uintptr_t virtual_address_decimal = reinterpret_cast<uintptr_t>(it->first);
		std::string correct_address_hex = convert_decimal_to_hex(virtual_address_decimal - base_address_decimal - 1);
		
        // Use addr2line to get function name, filename, and line number
        std::string command = "addr2line -f -C -e " + std::string(program_names[0]) + " " + correct_address_hex;
		std::vector<std::string> results = split_string_into_lines(execute_command(command));

		// Check the validation
		if (results.size() == 0) {
			throw std::runtime_error("failed to execute 'addr2line' command");
		}

		if (results.size() != 2 || results[0].substr(0,2) == "??" || results[1].substr(0,2) == "??") {
			// Record an original symbol information
			trace_log += std::string("\n  ") + it->second;
		}
		else {
			// Record the more detail informations in POSIX standard style
			std::string module_name = demangle(results[0]);
			std::string filename_and_linenumber = results[1];
			trace_log += std::string("\n  File \"") + filename_and_linenumber + "\", in " + module_name;
		}
    }

#endif

	// Clear the buffer and release the memory
	buffer.clear();
	std::vector<std::pair<void*, std::string>>().swap(buffer);

	// Return the 'Traceback' log
	return trace_log;
}

void StackTracer::_backtrace_stackframe(int signal) {
	// Capture the backtrace list of the current thread
	_capture_current_stackframe(_translate_thread_id(std::this_thread::get_id()), 0, true);

	// Capture the stack frame of the current thread, and backtrace it.
	std::string trace_log = get_traceback_log();

	// Print out the Traceback log
	std::printf("%s\n", trace_log.c_str());

	// Terminate this program
	std::exit(1);
}

#if defined(STACK_TRACER_OS_WINDOWS)
long StackTracer::_unhandled_exception_handler(void* exception_info) {
	// Structured exception handling
	PEXCEPTION_RECORD pER = ((EXCEPTION_POINTERS*)exception_info)->ExceptionRecord;
	
	char error_log[512] = {0, };

	if(pER->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		sprintf_s(error_log, sizeof(error_log), "attempt to %s data at address %p",
			pER->ExceptionInformation[0] ? "write" : "read",
			(void*)pER->ExceptionInformation[1]);
	}
	else {
		sprintf_s(error_log, sizeof(error_log), "ExceptionCode=%x, ExceptionAddress=%p", pER->ExceptionCode, pER->ExceptionAddress);
	}

	std::printf("error: %s\n", error_log);
	
	// Capture the backtrace list of the current thread
	_capture_current_stackframe(_translate_thread_id(std::this_thread::get_id()), 0, true);

	// Capture the stack frame of the current thread, and backtrace it.
	std::string trace_log = get_traceback_log();

	// Print out the Traceback log
	std::printf("%s\n", trace_log.c_str());

	/* Notifies the system that an exception handler has been called.
	   If this function was called by SetUnhandledExceptionFilter(), the current process is terminated.
	   If it was called as a parameter to the __except() statement,
	   the code inside the __except block is executed after the function ends.  */
	return EXCEPTION_EXECUTE_HANDLER;
}

#endif

long long StackTracer::get_current_thread_id() {
	return _translate_thread_id(std::this_thread::get_id());
}

long long StackTracer::_translate_thread_id(std::thread::id thread_id) {
	long long translated_id;

	std::stringstream stream;
	stream << thread_id;
	stream >> translated_id;

	return translated_id;
}

std::vector<std::string> StackTracer::split_string_into_lines(const std::string& multiline_string) {
	std::istringstream stream(multiline_string);
	std::string line;
	std::vector<std::string> lines;

	while (std::getline(stream, line)) {
		lines.push_back(line);
	}

	return lines;
}

#if defined(STACK_TRACER_OS_LINUX)

std::string StackTracer::execute_command(std::string command, bool enable_error_skip) {
	// Modify the command
	if (enable_error_skip) {
		command += " 2>/dev/null";
	}

	// Open the pipeline
    FILE* pipe = popen(command.c_str(), "r");
	
	// Check the validation
	if (!pipe) {
		throw std::runtime_error("failed to execute the command");
	}

	// Get the results of command execution
	std::array<char, 256> buffer;
    std::string command_result;
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        command_result += buffer.data();
    }

	// Close the pipeline
	pclose(pipe);

	return command_result;
}

std::vector<std::string> StackTracer::get_program_name() {
	// Get the current execution program name
	char filepath[PATH_MAX] = {0, };	// must be initialized
    ssize_t len = readlink("/proc/self/exe", filepath, sizeof(filepath) - 1);
	if (len == -1) {
		throw std::runtime_error("failed to get the name of the current program");
	}

	std::vector<std::string> program_names;
	program_names.push_back(filepath);
	program_names.push_back(basename(filepath));

	return program_names;
}

std::string StackTracer::get_base_address_hex(pid_t process_id, std::string process_name, bool enable_uppercase) {
	// Get the base address of the running process
    std::string command = "pmap " + std::to_string(process_id) + " | grep \"[rwxs-]\\{5\\} " + process_name + "$\"";
	std::string command_result = execute_command(command, false);

	// Split the multi-line string into lines
	std::vector<std::string> lines = split_string_into_lines(command_result);

	// Check the validation
    if (lines.size() == 0) {
		throw std::runtime_error("failed to get base address of the current program");
	}

	// Extract the first word of the first line
	std::istringstream lineStream(lines[0]);
    std::string base_address_hex;
	lineStream >> base_address_hex;

	// Convert to upper case
	if (enable_uppercase) {
		for (char& c : base_address_hex) {
			if (std::isalpha(c)) {
				c = std::toupper(c);
			}
		}
	}

	return base_address_hex;
}

std::string StackTracer::get_base_address_hex(bool enable_uppercase) {
	// Get a filename(including file path) of the current process
	std::string current_filename = get_program_name()[0];

	// Open the memory map file
	std::ifstream map_file("/proc/self/maps");

	// Check the validation
	if (!map_file.is_open()) {
		throw std::runtime_error("unable to open /proc/self/maps");
	}
	
	// Split the file into lines, and check the if statement condition
	std::string base_address_hex, line;
    while (std::getline(map_file, line)) {
		if ( (line.find("r-xp") != std::string::npos || line.find("r--p") != std::string::npos)
			&& line.find(current_filename) != std::string::npos) {
			line = line.substr(0, line.find(' '));
			base_address_hex = line.substr(0, line.find('-'));
			break;
		}
	}

	// Close the file
	map_file.close();

	// Convert to upper case
	if (enable_uppercase) {
		for (char& c : base_address_hex) {
			if (std::isalpha(c)) {
				c = std::toupper(c);
			}
		}
	}

	return base_address_hex;
}

uintptr_t StackTracer::get_base_address_decimal(pid_t process_id, std::string process_name) {
	// Get the base address of the running process
	std::string base_address_hex = get_base_address_hex(process_id, process_name);

	// Convert to decimal
	uintptr_t base_address_decimal = convert_hex_to_decimal(base_address_hex);

	return base_address_decimal;
}

uintptr_t StackTracer::get_base_address_decimal() {
	// Get the base address of the current process
	std::string base_address_hex = get_base_address_hex();

	// Convert to decimal
	uintptr_t base_address_decimal = convert_hex_to_decimal(base_address_hex);

	return base_address_decimal;
}

#endif

uintptr_t StackTracer::convert_hex_to_decimal(std::string hex) {
	// Input into the string stream
	std::stringstream stream;
	stream << std::hex << hex;

	// Convert to decimal
	uintptr_t decimal = 0;
	stream >> decimal;

	// Clear the stream
	stream.str("");
	stream.clear();

	return decimal;
}

std::string StackTracer::convert_decimal_to_hex(uintptr_t decimal, bool enable_uppercase) {
	// Input into the string stream
	std::ostringstream stream;
	if (enable_uppercase) {
		stream << std::hex << std::uppercase << decimal;
	}
	else {
		stream << std::hex << decimal;
	}

	// Convert to hexadecimal
	std::string hex = stream.str();

	// Clear the stream
	stream.str("");
	stream.clear();

	return hex;
}

#if defined(STACK_TRACER_OS_LINUX)

std::string StackTracer::demangle(const std::string& mangled_name) {
	// Demangle the symbol name using C++11 smart pointer
	int status = 0;
	std::unique_ptr<char, void(*)(void*)> demangled_name(
		abi::__cxa_demangle(mangled_name.c_str(), nullptr, nullptr, &status),
		std::free);
	
	// Check the validation : demangle failed
	if (status != 0 || demangled_name.get() == NULL) {
		return mangled_name;
	}
	
	return std::string(demangled_name.get());
}

#endif
