#include "stacktracer.h"

// For test
#include <unistd.h>	// for sleep()
#include <chrono>
#include <random>
#include <thread>
std::thread* p1 = NULL;
std::thread* p2 = NULL;

int random_sleep(unsigned int min_time_milliseconds, unsigned int max_time_milliseconds) {
    std::random_device rd;  // Seed generator
    std::mt19937 gen(rd()); // Mersenne Twister engine
    std::uniform_int_distribution<> dis(min_time_milliseconds, max_time_milliseconds);

	// Generate a random time
    int sleep_time_ms = dis(gen);

    // Sleep
    std::this_thread::sleep_for(std::chrono::milliseconds(sleep_time_ms));

	return sleep_time_ms;
}

void functionC1() {
	// Case 1 : Print stack trace after exception handling.
	try {
		printf("Start %s() in a new thread...\n", __FUNCTION__);
		random_sleep(1000, 1500);
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
	random_sleep(2000, 3000);
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
		sleep(100);
	}
	p1->join();
	p2->join();

	return 0;
}
