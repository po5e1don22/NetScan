#pragma once
#include <string>
#include <vector>
#include "core/ja3.h"
#include "core/fingerprint_db.h"

struct ScanResult
{
    std::vector<JA3Record> records;
};

bool run_suricata_stage(const std::string& pcap, std::string& out_dir);
ScanResult parse_stage(const std::string& eve_path);
FingerprintDB load_db();
void match_stage(const ScanResult& result, const FingerprintDB& db);