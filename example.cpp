#include "stacktracer.h"

// For test
#include <chrono>
#include <thread>
std::thread* p1 = NULL;
std::thread* p2 = NULL;

void functionC1() {
	// Case 1 : Print stack trace after exception handling.
	try {
		printf("Start %s() in a new thread...\n", __FUNCTION__);
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		throw std::runtime_error("runtime error occurred!");
	}
	catch (std::exception& e) {
		printf("exception: %s\n", e.what());
		StackTracer::capture_current_stackframe();
		std::cout << StackTracer::get_traceback_log() << std::endl;
	}
	printf("\n");
}

void functionC2() {
	// Case 2 : Print stack trace without exception handling.
	printf("Start %s() in a new thread...\n", __FUNCTION__);
	std::this_thread::sleep_for(std::chrono::milliseconds(2000));
	
	// If you are running in the IDE, please continue.
	int* a = NULL;
	*a = 0;
}

void functionB1() {
	functionC1();
}

void functionB2() {
	functionC2();
}

void functionA() {
	StackTracer::capture_current_stackframe( (p1 = new std::thread(functionB1))->get_id() );
	StackTracer::capture_current_stackframe( (p2 = new std::thread(functionB2))->get_id() );
}

int main() {
	// Register an exception handler for segment fault
	StackTracer::register_exception_handler();

	functionA();

	while (!p1 && !p2) {
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	p1->join();
	p2->join();

	return 0;
}
