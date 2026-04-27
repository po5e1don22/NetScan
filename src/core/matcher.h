#pragma once

#include "ja3.h"
#include "fingerprint_db.h"

#include <vector>

struct MatchResult
{
    std::string src_ip;
    std::string dest_ip;

    std::string ja3;
    std::string ja3s;

    std::string match_type;

    std::string label;
    std::string category;
    std::string source;
    std::string notes;
};

std::vector<MatchResult> match_fingerprints(const std::vector<JA3Record>& records, const FingerprintDB& db);
MatchResult match_single(const JA3Record& r, const FingerprintDB& db);