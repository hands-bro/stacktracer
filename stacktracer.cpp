// stacktracer.cpp
#include "stacktracer.h"
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
std::mutex StackTracer::m_mutex;
std::map< long long, std::vector<std::pair<void*, std::string>> > StackTracer::m_trace_map;

StackTracer::StackTracer() {
    // TODO :
}

StackTracer::~StackTracer() {
    // TODO :
}

void StackTracer::register_exception_handler() {
	// Register an exception handler for segment fault
	signal(SIGABRT, _backtrace_stackframe);	// Aborted (core dumped)
	signal(SIGSEGV, _backtrace_stackframe);	// Segment fault
	signal(SIGILL, _backtrace_stackframe);	// Illegal instruction
	signal(SIGFPE, _backtrace_stackframe);  // Erroneous arithmetic operation
#if defined(STACK_TRACER_OS_LINUX)
	signal(SIGBUS, _backtrace_stackframe);  // Bus error (for Linux only)
#endif
}

long long StackTracer::_capture_current_stackframe(long long thread_id, unsigned int skip_depth) {
    void* virtual_addresses[1024] = {0, };
    size_t trace_count;

    // Capture the backtrace
    trace_count = backtrace(virtual_addresses, 1024);
    char **symbols = backtrace_symbols(virtual_addresses, trace_count);  

	// Check the validation
	if (trace_count < skip_depth) {
		throw std::runtime_error("failed to backtrace the stack frame");
	}

	// Safely lock the mutex
	std::lock_guard<std::mutex> lock(m_mutex);

	// Push the results of backtracing the stack frame onto the buffer
	std::vector<std::pair<void*, std::string>>& buffer = m_trace_map[thread_id];

    for (int i=trace_count-1; i>=skip_depth; --i) {
		buffer.push_back(std::pair<void*, std::string>(virtual_addresses[i], std::string(symbols[i])));
    }

	// Release the symbols array
	free(symbols);

	return thread_id;
}

long long StackTracer::capture_current_stackframe(long long thread_id) {
	return _capture_current_stackframe(thread_id, 2);
}

long long StackTracer::capture_current_stackframe(std::thread::id thread_id) {
	return _capture_current_stackframe(_translate_thread_id(thread_id), 2);
}

long long StackTracer::capture_current_stackframe() {
	return _capture_current_stackframe(_translate_thread_id(std::this_thread::get_id()), 2);
}

std::string StackTracer::get_traceback_log() {
	// Get the current thread id
	long long thread_id = _translate_thread_id(std::this_thread::get_id());

	// Safely lock the mutex
	std::lock_guard<std::mutex> lock(m_mutex);

	// Get the current execution program name
	std::vector<std::string> program_names = get_program_name();

	// Get the base address of the current process
	uintptr_t base_address_decimal = get_base_address_decimal();

	// Print out the traceback log
	std::string trace_log("Traceback (most recent call last / line numbers may differ from actual):");
	std::vector<std::pair<void*, std::string>>& buffer = m_trace_map[thread_id];
	
	for (std::vector<std::pair<void*, std::string>>::const_iterator it=buffer.cbegin(); it!=buffer.cend(); ++it) {
		// Convert the virtual addresses to correct addresses
		uintptr_t virtual_address_decimal = reinterpret_cast<uintptr_t>(it->first);
		std::string correct_address_hex = convert_decimal_to_hex(virtual_address_decimal - base_address_decimal - 1);
		
        // Use addr2line to get function name, filename, and and line number
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
			// Record the more detail informations
			std::string module_name = demangle(results[0]);
			std::string filename_and_linenumber = results[1];
			trace_log += std::string("\n  File \"") + filename_and_linenumber + "\", in " + module_name;
		}
    }

	// Clear the buffer and release the memory
	buffer.clear();
	std::vector<std::pair<void*, std::string>>().swap(buffer);

	// Return the 'Traceback' log
	return trace_log;
}

void StackTracer::_backtrace_stackframe(int signal) {
	// Capture the backtrace list of the current thread
	_capture_current_stackframe(_translate_thread_id(std::this_thread::get_id()), 2);

	// Capture the stack frame of the current thread, and backtrace it.
	std::string trace_log = get_traceback_log();

	// Print out the Traceback log
	std::printf("%s\n", trace_log.c_str());

	// Terminate this program
	std::exit(1);
}

long long StackTracer::_translate_thread_id(std::thread::id thread_id) {
	long long translated_id;

	std::stringstream stream;
	stream << thread_id;
	stream >> translated_id;

	return translated_id;
}

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

std::vector<std::string> StackTracer::split_string_into_lines(const std::string& multiline_string) {
	std::istringstream stream(multiline_string);
	std::string line;
	std::vector<std::string> lines;

	while (std::getline(stream, line)) {
		lines.push_back(line);
	}

	return lines;
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
