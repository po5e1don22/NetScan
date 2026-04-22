#include "ja3.h"
#include "fingerprint_db.h"
#include "db_writer.h"
#include "unknown_queue.h"

#include <vector>
#include <unordered_map>
#include <iostream>

void match_fingerprints(const std::vector<JA3Record>& records, const FingerprintDB& db)
{
    for (const auto& r : records)
    {
        std::cout << "--------------------------------\n";
        std::cout << r.src_ip << " -> " << r.dest_ip << std::endl;
        
        //ja3 + ja3s match
        bool full_match_found = false;

        if (!r.ja3.empty() && !r.ja3s.empty())
        {
            for (const auto& meta : db.full_pairs)
            {
                if (meta.ja3 == r.ja3 && meta.ja3s == r.ja3s)
                {
                    std::cout << "[FULL MATCH]\n";
                    std::cout << "JA3: " << r.ja3 << "\n";
                    std::cout << "JA3S: " << r.ja3s << "\n";
                    std::cout << "Label: " << meta.label << "\n";
                    std::cout << "Category: " << meta.category << "\n";
                    std::cout << "Source: " << meta.source << "\n";
                    std::cout << "Notes: " << meta.notes << "\n";

                    full_match_found = true;
                    break;
                }
            }
        }
        if (full_match_found)
            continue;

        //ja3 match
        if (!r.ja3.empty())
        {
            auto it = db.ja3_map.find(r.ja3);
            if (it != db.ja3_map.end())
            {
                const auto& meta = it->second;

                std::cout << "[WEAK MATCH - JA3]\n";
                std::cout << "JA3: " << r.ja3 << "\n";
                std::cout << "Label: " << meta.label << "\n";
                std::cout << "Category: " << meta.category << "\n";
                std::cout << "Source: " << meta.source << "\n";
                std::cout << "Notes: " << meta.notes << "\n";

                continue;
            }
        }

        //ja3s match
        if (!r.ja3s.empty())
        {
            auto it = db.ja3s_map.find(r.ja3s);
            if (it != db.ja3s_map.end())
            {
                const auto& meta = it->second;

                std::cout << "[WEAK MATCH - JA3S]\n";
                std::cout << "JA3S: " << r.ja3s << "\n";
                std::cout << "Label: " << meta.label << "\n";
                std::cout << "Category: " << meta.category << "\n";
                std::cout << "Source: " << meta.source << "\n";
                std::cout << "Notes: " << meta.notes << "\n";

                continue;
            }
        }

        //unknown
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            unknown_queue.push(r);
        }
    }
}