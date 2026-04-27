#include "matcher.h"
#include "ja3.h"
#include "fingerprint_db.h"
#include "unknown_queue.h"

#include <vector>
#include <mutex>

extern std::mutex queue_mutex;
extern std::queue<JA3Record> unknown_queue;

std::vector<MatchResult> match_fingerprints(
    const std::vector<JA3Record>& records,
    const FingerprintDB& db)
{
    std::vector<MatchResult> results;
    results.reserve(records.size());

    for (const auto& r : records)
    {
        MatchResult res;
        res.src_ip = r.src_ip;
        res.dest_ip = r.dest_ip;
        res.ja3 = r.ja3;
        res.ja3s = r.ja3s;

        // =========================
        // 1. FULL MATCH
        // =========================
        bool full_match_found = false;

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

                    full_match_found = true;
                    break;
                }
            }
        }

        if (full_match_found)
        {
            results.push_back(res);
            continue;
        }

        // =========================
        // 2. CHECK JA3 / JA3S
        // =========================
        bool ja3_match = false;
        bool ja3s_match = false;

        FingerprintMeta ja3_meta{};
        FingerprintMeta ja3s_meta{};

        if (!r.ja3.empty())
        {
            auto it = db.ja3_map.find(r.ja3);
            if (it != db.ja3_map.end())
            {
                ja3_match = true;
                ja3_meta = it->second;
            }
        }

        if (!r.ja3s.empty())
        {
            auto it = db.ja3s_map.find(r.ja3s);
            if (it != db.ja3s_map.end())
            {
                ja3s_match = true;
                ja3s_meta = it->second;
            }
        }

        // =========================
        // 3. DECISION
        // =========================
        if (ja3_match)
        {
            res.match_type = "WEAK_JA3";
            res.label = ja3_meta.label;
            res.category = ja3_meta.category;
            res.source = ja3_meta.source;
            res.notes = ja3_meta.notes;
        }
        else if (ja3s_match)
        {
            res.match_type = "WEAK_JA3S";
            res.label = ja3s_meta.label;
            res.category = ja3s_meta.category;
            res.source = ja3s_meta.source;
            res.notes = ja3s_meta.notes;
        }
        else
        {
            res.match_type = "UNKNOWN";

            std::lock_guard<std::mutex> lock(queue_mutex);
            unknown_queue.push(r);
        }

        results.push_back(res);
    }

    return results;
}

MatchResult match_single(const JA3Record& r, const FingerprintDB& db)
{
    MatchResult res;

    res.src_ip = r.src_ip;
    res.dest_ip = r.dest_ip;
    res.ja3 = r.ja3;
    res.ja3s = r.ja3s;

    // =========================
    // 1. FULL MATCH
    // =========================
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

                return res;
            }
        }
    }

    // =========================
    // 2. JA3 / JA3S
    // =========================
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

            return res;
        }
    }

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

            return res;
        }
    }

    // =========================
    // 3. UNKNOWN
    // =========================
    res.match_type = "UNKNOWN";

    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        unknown_queue.push(r);
    }

    return res;
}