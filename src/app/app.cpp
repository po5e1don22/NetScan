#include "app.h"

#include "suricata/suricata_runner.h"
#include "core/analyzer.h"
#include "core/fingerprint_db.h"
#include "core/matcher.h"

bool run_suricata_stage(const std::string& pcap, std::string& out_dir)
{
    out_dir = run_suricata(pcap, "output");
    return !out_dir.empty();
}

ScanResult parse_stage(const std::string& eve_path)
{
    ScanResult result;
    result.records = parse_eve_json(eve_path);
    return result;
}

FingerprintDB load_db()
{
    return load_fingerprints("data/fingerprints.json");
}

void match_stage(const ScanResult& result, const FingerprintDB& db)
{
    match_fingerprints(result.records, db);
}