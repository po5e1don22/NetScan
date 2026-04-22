#include "db_writer.h"
#include "ja3.h"

#include <queue>
#include <mutex>
#include <thread>
#include <iostream>

extern std::queue<JA3Record> unknown_queue;
extern std::mutex queue_mutex;

void process_unknowns()
{
    while (true)
    {
        JA3Record record;

        {
            std::lock_guard<std::mutex> lock(queue_mutex);

            if (unknown_queue.empty())
                continue;

            record = unknown_queue.front();
            unknown_queue.pop();
        }

        std::cout << "\n[UNKNOWN DETECTED]\n";
        std::cout << "JA3: " << record.ja3 << "\n";
        std::cout << "JA3S: " << record.ja3s << "\n";

        std::cout << "Add to DB? (y/n): ";
        char choice;
        std::cin >> choice;

        if (choice == 'y' || choice == 'Y')
        {
            add_unknown_fingerprint(record, "data/fingerprints.json");
        }
    }
}