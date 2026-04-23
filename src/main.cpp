#include <thread>
#include "gui/gui_runner.h"
#include "core/queue_worker.h"

int main()
{
    std::thread worker(process_unknowns);
    worker.detach();

    return run_gui();
}