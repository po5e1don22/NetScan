#pragma once

#include "ja3.h"
#include <queue>
#include <mutex>

extern std::queue<JA3Record> unknown_queue;
extern std::mutex queue_mutex;