#include "matcher.h"
#include "ja3.h"
#include "fingerprint_db.h"
#include "db_writer.h"
#include "unknown_queue.h"

#include <vector>
#include <unordered_map>
#include <iostream>

std::vector<MatchResult> match_fingerprints(const std::vector<JA3Record>& records, const FingerprintDB& db)
{
    std::vector<MatchResult> results;

    for (const auto& r : records)
    {
        MatchResult res;
        res.src_ip = r.src_ip;
        res.dest_ip = r.dest_ip;
        res.ja3 = r.ja3;
        res.ja3s = r.ja3s;

        bool full_match_found = false;

        // FULL MATCH
        if (!r.ja3.empty() && !r.ja3s.empty())
        {
            for (const auto& meta : db.full_pairs)
            {
                if (meta.ja3 == r.ja3 && meta.ja3s == r.ja3s)
                {
                    res.match_type = "FULL";
                    res.label = meta.label;
                    res.category = meta.category;
                    res.source = meta.source;
                    res.notes = meta.notes;

                    results.push_back(res);
                    full_match_found = true;
                    break;
                }
            }
        }

        if (full_match_found)
            continue;

        // JA3 match
        if (!r.ja3.empty())
        {
            auto it = db.ja3_map.find(r.ja3);
            if (it != db.ja3_map.end())
            {
                const auto& meta = it->second;

                res.match_type = "WEAK_JA3";
                res.label = meta.label;
                res.category = meta.category;
                res.source = meta.source;
                res.notes = meta.notes;

                results.push_back(res);
                continue;
            }
        }

        // JA3S match
        if (!r.ja3s.empty())
        {
            auto it = db.ja3s_map.find(r.ja3s);
            if (it != db.ja3s_map.end())
            {
                const auto& meta = it->second;

                res.match_type = "WEAK_JA3S";
                res.label = meta.label;
                res.category = meta.category;
                res.source = meta.source;
                res.notes = meta.notes;

                results.push_back(res);
                continue;
            }
        }

        // UNKNOWN
        res.match_type = "UNKNOWN";
        results.push_back(res);

        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            unknown_queue.push(r);
        }
    }

    return results;
}