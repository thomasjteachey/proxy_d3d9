#include "task_queue.h"
#include "frame_fence.h"
#include <vector>
#include <mutex>
struct ScheduledTask {
    unsigned dueFrame;
    std::function<void()> fn;
};
static std::vector<ScheduledTask> gQ;
static std::mutex gM;

void ScheduleNextFrame(std::function<void()> fn) {
    std::lock_guard<std::mutex> l(gM);
    gQ.push_back({ FrameFence_Id() + 1, std::move(fn) });
}
void RunScheduled(unsigned curFrame) {
    std::vector<ScheduledTask> ready;
    {
        std::lock_guard<std::mutex> l(gM);
        auto it = gQ.begin();
        while (it != gQ.end()) {
            if (it->dueFrame <= curFrame) {
                ready.push_back(std::move(*it));
                it = gQ.erase(it);
            }
            else {
                ++it;
            }
        }
    }
    for (auto& job : ready) {
        job.fn();
    }
}
