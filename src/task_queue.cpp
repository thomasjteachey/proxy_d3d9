#include "task_queue.h"
#include <vector>
#include <mutex>
static std::vector<std::function<void()>> gQ;
static std::mutex gM;

void ScheduleNextFrame(std::function<void()> fn) {
    std::lock_guard<std::mutex> l(gM);
    gQ.push_back(std::move(fn));
}
void RunScheduled() {
    std::vector<std::function<void()>> jobs;
    {
        std::lock_guard<std::mutex> l(gM);
        jobs.swap(gQ);
    }
    for (auto& f : jobs) f();
}
