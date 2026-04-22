#pragma once

#include "ja3.h"
#include "fingerprint_db.h"

#include <vector>

void match_fingerprints(const std::vector<JA3Record>& records, const FingerprintDB& db);