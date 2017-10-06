#include "Farm.h"
#include <thread>

void SpinLock::lock() {
	while (locked.test_and_set(std::memory_order_acquire)) { ; }
}
void SpinLock::unlock() {
	locked.clear(std::memory_order_release);
}

void Farm::worker() {
	while (true) {
		s.lock();
		if (!tasks.empty()) {
			Task* t = tasks.front();
			tasks.pop();
			s.unlock();
			t->run();
		}
		else {
			if (done) { s.unlock(); return; }
			s.unlock();
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	}
}
void Farm::run() {
	int threadCount = std::thread::hardware_concurrency();
	threads = new std::thread[threadCount];
	for (auto i = 0; i < threadCount; i++) {
		threads[i] = std::thread(&Farm::worker, this);
	}
	for (auto i = 0; i < threadCount; i++) {
		threads[i].join();
	}
	delete[] threads;
}
void Farm::addTask(Task* t) {
	s.lock();
	tasks.push(t);
	s.unlock();
}

void Farm::addEnd()
{
	class EndTask : public Task
	{
		bool* done;
	public:
		EndTask(bool* _done) : done(_done) {}
		void run() override {
			*done = true;
		}
	};
	addTask(new EndTask(&done));
}
