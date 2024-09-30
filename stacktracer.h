// stacktracer.h

#ifndef __STACK_TRACER_H__
#define __STACK_TRACER_H__

#include <iostream>     // for uintptr_t, pid_t
#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// Definitions for exporting and importing this API
#if ( (defined(_WIN32) || defined(_WIN64) /* Windows platform */) \
	&& (defined(_MSC_VER) /* Microsoft Visual C++ Compiler */) )
    #define STACK_TRACER_OS_WINDOWS
	#ifdef STACK_TRACER_DLL_EXPORTS
		#define STACK_TRACER_API __declspec(dllexport)
	#else
		#define STACK_TRACER_API __declspec(dllimport)
	#endif
#elif ( (defined(__unix__) || defined(__linux__) /* UNIX and Linux platform */) \
	&& (defined(__GNUC__) && defined(__cplusplus) /* GNU C++ Compiler */) )
    #define STACK_TRACER_OS_LINUX
	#define STACK_TRACER_API __attribute__((__visibility__("default")))
#else
	// Other platforms and compilers are not yet supported.
	#define STACK_TRACER_API
#endif

typedef class STACK_TRACER_API StackTracer
{
public:
    StackTracer();
    virtual ~StackTracer();

    /**
     *  @brief  Register this class as an error signal handler.
     *  @note  The target signals SIGABRT, SIGSEGV, SIGBUS, SIGILL, and SIGFPE.
     */
    static void register_exception_handler();

    /**
     *  @brief  Capture the backtrace list from the stackframe of the current thread and store it in std::map.
     *  @param thread_id  Keyword to use when storing/deleting the backtrace list in the map buffer.
     *  @return  Return the ID of the current thread that captured the backtrace list as a long long type.
     *           The returned ID will be the same as the 'thread_id'.
     *  @note  If NDEBUG is defined, do nothing.
     *         Also, to get correct results you need to turn off optimizations and enable the -g, -rdynamic flags.
     */
    static long long capture_current_stackframe(long long thread_id);

    /**
     *  @brief  Capture the backtrace list from the stackframe of the current thread and store it in std::map.
     *  @param thread_id  Keyword to use when storing/deleting the backtrace list in the map buffer.
     *  @return  Return the ID of the current thread that captured the backtrace list as a long long type.
     *           The returned ID will be the same as the 'thread_id'.
     *  @note  If NDEBUG is defined, do nothing.
     *         Also, to get correct results you need to turn off optimizations and enable the -g, -rdynamic flags.
     */
    static long long capture_current_stackframe(std::thread::id thread_id);

    /**
     *  @brief  Capture the backtrace list from the stackframe of the current thread and store it in std::map.
     *          This method use the current thread ID as a keyword.
     *  @return  Return the ID of the current thread that captured the backtrace list as a long long type.
     *  @note  If NDEBUG is defined, do nothing.
     *         Also, to get correct results you need to turn off optimizations and enable the -g, -rdynamic flags.
     */
    static long long capture_current_stackframe();

    /**
     *  @brief  Generate a 'Traceback' log from the backtrace list captured by the capture_current_stackframe() function.
     *          The backtrace informations include the filename, line number, and function name of each call.
     *  @return  Return the 'Traceback' log as std::string.
     *  @note
     *  - When this function is called, all the backtrace list captured so far using the current thread ID are deleted.
     * 
     *  - This function internally uses the 'addr2line' commands on Linux.
     */
    static std::string get_traceback_log();

protected:
#if defined(STACK_TRACER_OS_WINDOWS)
    /**
    *  @brief  To run SymInitialize() and SymSetOptions().
    *          Called only once when register_exception_handler() or capture_current_stackframe() is executed for the first time.
    *          (Multi-thread safe)
    */
    static void _initialize_symbols();

    /**
    *  @brief  To run SymCleanup().
    *          This function is registered with atexit() and is automatically called when the program terminates.
    */
    static void _cleanup_symbols();

#endif

    /**
     *  @brief  Capture the backtrace list from the stackframe of the current thread and store it in std::map.
     *  @param thread_id  Keyword to use when storing/deleting the backtrace list in the map buffer.
     *  @param skip_depth  Set the number of stackframes to omit when capturing the stackframe.
     *                     If 'enable_skip_capture_routines' is true, the capture routine is excluded from counting.
     *  @param enable_skip_capture_routines  If set to the default(true), the call informations for this function and internal routines are omitted.
     *  @return  Return the ID of the current thread that captured the backtrace list as a long long type.
     *           The returned ID will be the same as the 'thread_id'.
     *  @note  If NDEBUG is defined, do nothing.
     *         Also, to get correct results you need to turn off optimizations and enable the -g, -rdynamic flags.
     */
    static long long _capture_current_stackframe(long long thread_id, unsigned int skip_depth, bool enable_skip_capture_routines = true);

    /**
     *  @brief  Capture the stackframe of the current thread, and backtrace it.
     *          The backtrace informations include the filename, line number, and function name of each call.
     *          Additionally, if capture_current_stackframe() was previously called with the same thread ID,
     *          the backtrace list captured at that time is also included.
     *  @param signal  Parameter for error signal handling. When calling directly, enter the default value(-1).
     *  @note
     *  - When this function is called, all the backtrace list captured so far using the current thread ID are deleted.
     * 
     *  - This function internally uses the 'addr2line' commands on Linux.
     * 
     *  - This function forcibly terminates the current program after execution.
     */
    static void _backtrace_stackframe(int signal = -1);

#if defined(STACK_TRACER_OS_WINDOWS)
    /**
    *  @brief  Exception handler to support SEH(Structured Exception Handling) on Microsoft Windows.
    *
    *          This function is a global exception handler that can handle unhandled exceptions.
    *          Unlike the try-catch statement, this function is the last exception handler called
    *          just before the program and other exception handlers terminate without handling the exception,
    *          and the program terminates after the function ends.
    *
    *          SEH using this function is necessary for the following reasons:
    *          1. In the Windows C++ environment, the standard function signal() cannot handle certain asynchronous exceptions such as stack overflow.
    *          2. The Windows-only function _set_se_translator() has similar limitations, and must be called separately for each thread.
    *          3. The __try/__except statement is a powerful exception handler, but it cannot be used within a function where local variables are declared.
    *
    *  @note  On Windows, after enabling the SEH support option(/EHa) of the 'cl' compiler,
    *         this method should be registered as a SE handler
    *         exactly once at program startup by SetUnhandledExceptionFilter.
    *         (If the current platform is not Windows, these actions are unnecessary.)
    */
    static long __stdcall _unhandled_exception_handler(void* exception_info);

#endif

    /* Convert the data type of the thread ID from std::thread::id to long long.  */
    static long long _translate_thread_id(std::thread::id thread_id);

    /* Split the multi-line string into lines.  */
    static std::vector<std::string> split_string_into_lines(const std::string& multiline_string);

#if defined(STACK_TRACER_OS_LINUX)
    /**
     *  @brief  Execute the input command on the console.
     *  @param command  User-defined command.
     *  @param enable_error_skip  Whether to omit log output when an error occurrs. (default: true)
     *  @return  Command execution result.
     */
    static std::string execute_command(std::string command, bool enable_error_skip = true);

    /**
     *  @brief  Get the current program name.
     *  @return  { filename(including path), filename(base) }
     */
    static std::vector<std::string> get_program_name();

    /* Get the base address of a running process in hexadecimal.  */
    static std::string get_base_address_hex(pid_t process_id, std::string process_name, bool enable_uppercase = false);

    /* Get the base address of the current process in hexadecimal.  */
    static std::string get_base_address_hex(bool enable_uppercase = false);

    /* Get the base address of a running process in decimal.  */
    static uintptr_t get_base_address_decimal(pid_t process_id, std::string process_name);

    /* Get the base address of the current process in decimal.  */
    static uintptr_t get_base_address_decimal();

#endif

    /* Convert a hexadecimal string to a decimal value.  */
    static uintptr_t convert_hex_to_decimal(std::string hex);

    /* Convert a decimal value to a hexadecimal string.  */
    static std::string convert_decimal_to_hex(uintptr_t decimal, bool enable_uppercase = false);

    // Symbol initialization flag
    static std::atomic<bool> m_is_symbol_initialized;

#if defined(STACK_TRACER_OS_LINUX)
    /**
     *  @brief  Demangle the mangled name in C/C++.
     *  @return  Demangled name.
     */
    static std::string demangle(const std::string& mangled_name);

#endif

    // Variable to control asynchronous logic
    static std::mutex m_mutex;

    // Buffer to store backtrace list
    static std::map< long long, std::vector<std::pair<void*, std::string>> > m_trace_map;

} StackTracer;

#endif  // #ifndef __STACK_TRACER_H__
