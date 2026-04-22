//ja3/ja3s fingerprint db loader

#include "fingerprint_db.h"
#include "third_party/json.hpp"

#include <fstream>
#include <iostream>
#include <unordered_map>

using json = nlohmann::json;

FingerprintDB load_fingerprints(const std::string& path)
{
    FingerprintDB db;

    std::ifstream file(path);
    if (!file.is_open())
    {
        std::cerr << "[ERROR] Cannot open fingerprint DB: " << path << std::endl;
        return db;
    }

    json j;
    try 
    {
        file >> j;
    }
    catch (std::exception& e)
    {
        std::cerr << "[ERROR] JSON parse failed: " << e.what() << std::endl;
        return db;
    }

    if (!j.is_array())
    {
        std::cerr << "[ERROR] Invalid DB format (expected array)" << std::endl;
        return db; 
    }

    for (const auto& item : j)
    {
        try
        {
            FingerprintMeta meta;

            //fingerprint
            if (item.contains("fingerprint"))
            {
                const auto& fp = item["fingerprint"];

                if (fp.contains("ja3"))
                    meta.ja3 = fp["ja3"];

                if (fp.contains("ja3s"))
                    meta.ja3s = fp["ja3s"];
            }

            //meta
            if (item.contains("meta"))
            {
                const auto& m =item["meta"];

                if (m.contains("label"))
                    meta.label = m["label"];

                if (m.contains("category"))
                    meta.category = m["category"];

                if (m.contains("source"))
                    meta.source = m["source"];

                if (m.contains("notes"))
                    meta.notes = m["notes"];
            }

            //full pair loader
            if (!meta.ja3.empty() && !meta.ja3s.empty())
            {
                db.full_pairs.push_back(meta);
            }
            //only ja3
            else if (!meta.ja3.empty())
            {
                db.ja3_map[meta.ja3] = meta;
            }

            //only ja3s
            else if (!meta.ja3s.empty())
            {
                db.ja3s_map[meta.ja3s] = meta; 
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << "[WARN] Skipping bad entry" <<  e.what() << std::endl;
        }
    }

    std::cout << "[INFO] Loaded:\n";
    std::cout << "  JA3 only: " << db.ja3_map.size() << "\n";
    std::cout << "  JA3S only: " << db.ja3s_map.size() << "\n";
    std::cout << "  FULL pairs: " << db.full_pairs.size() << "\n";

    return db;
}