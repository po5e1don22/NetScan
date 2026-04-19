#pragma once

#include "ja3.h"
#include "fingerprint_db.h"

#include <vector>
#include <unordered_map>

void match_fingerprints(const std::vector<JA3Record>& records, const std::unordered_map<std::string, FingerprintMeta>& db);