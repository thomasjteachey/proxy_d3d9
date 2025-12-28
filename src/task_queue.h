#pragma once
#include <functional>
void ScheduleNextFrame(std::function<void()> fn);
void RunScheduled(unsigned curFrame);
