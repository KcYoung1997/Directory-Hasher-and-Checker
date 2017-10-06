#pragma once
#include <queue>
#include <atomic>
#include <thread>

class SpinLock {
	std::atomic_flag locked;
public:
	void lock();
	void unlock();
};
class Task {
public:
	virtual ~Task()
	{
	}

	virtual void run() = 0;
};
class Farm {
	SpinLock s;
	std::queue<Task*> tasks;
	std::thread* threads;
	bool done = false;
	void worker();
public:
	void run();
	void addTask(Task* t);
	void addEnd();
};
