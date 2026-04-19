#include "ja3.h"
#include "fingerprint_db.h"

#include <vector>
#include <unordered_map>
#include <iostream>

void match_fingerprints(const std::vector<JA3Record>& records, const std::unordered_map<std::string, FingerprintMeta>& db)
{
    for (const auto& r : records)
    {
        std::cout << "--------------------------------\n";
        std::cout << r.src_ip << " -> " << r.dest_ip << std::endl;
        
        if (r.ja3.empty())
        {
            std::cout << "[SKIP] No JA3" << std::endl;
            continue;
        }
        auto it = db.find(r.ja3);

        if (it != db.end())
        {
            const auto& meta = it -> second;
            
            std::cout << "[MATCH]\n";
            std::cout << "JA3: " << r.ja3 << "\n";
            std::cout << "Label: " << meta.label << "\n";
            std::cout << "Category: " << meta.category << "\n";
            std::cout << "Source: " << meta.source << "\n";
            std::cout << "Notes: " << meta.notes << "\n";
        }
        else
        {
            std::cout << "[UNKNOWN]\n";
            std::cout << "JA3: " << r.ja3 << "\n";
        }
    }
}