#include "fingerprint_db.h"
#include "third_party/json.hpp"

#include <fstream>
#include <iostream>

using json = nlohmann::json;

static std::string normalize(const std::string& s)
{
    size_t start = s.find_first_not_of(" \n\r\t");
    size_t end   = s.find_last_not_of(" \n\r\t");

    if (start == std::string::npos)
        return "";

    return s.substr(start, end - start + 1);
}

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

            // fingerprint
            if (item.contains("fingerprint"))
            {
                const auto& fp = item["fingerprint"];

                if (fp.contains("ja3"))
                    meta.ja3 = normalize(fp["ja3"].get<std::string>());

                if (fp.contains("ja3s"))
                    meta.ja3s = normalize(fp["ja3s"].get<std::string>());
            }

            // meta
            if (item.contains("meta"))
            {
                const auto& m = item["meta"];

                if (m.contains("label"))
                    meta.label = m["label"];

                if (m.contains("category"))
                    meta.category = m["category"];

                if (m.contains("source"))
                    meta.source = m["source"];

                if (m.contains("notes"))
                    meta.notes = m["notes"];
            }

            // =========================
            // ВАЖНО: индексируем ВСЕГДА
            // =========================

            if (!meta.ja3.empty())
            {
                db.ja3_map[meta.ja3] = meta;
            }

            if (!meta.ja3s.empty())
            {
                db.ja3s_map[meta.ja3s] = meta;
            }

            if (!meta.ja3.empty() && !meta.ja3s.empty())
            {
                db.full_pairs.push_back(meta);
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << "[WARN] Skipping bad entry: " << e.what() << std::endl;
        }
    }

    std::cout << "[INFO] Loaded:\n";
    std::cout << "  JA3 index: " << db.ja3_map.size() << "\n";
    std::cout << "  JA3S index: " << db.ja3s_map.size() << "\n";
    std::cout << "  FULL pairs: " << db.full_pairs.size() << "\n";

    return db;
}