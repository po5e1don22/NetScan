#include <iostream>

#include "suricata/suricata_runner.h"
#include "core/analyzer.h"
#include "core/fingerprint_db.h"
#include "core/matcher.h"

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0]
                  << " <pcap_file>" << std::endl;
        return 1;
    }

    std::string pcap_file = argv[1];

    std::string output_dir = run_suricata(pcap_file, "output");

    if (output_dir.empty())
        return 1;

    std::string eve_file = output_dir + "/eve.json";

    auto records = parse_eve_json(eve_file);

    std::cout << "Found records: " << records.size() << std::endl;

    // 4. вывод
    for (const auto& r : records)
    {
        std::cout << r.src_ip << " -> "
                  << r.dest_ip
                  << " | JA3: " << r.ja3
                  << " | JA3S: " << r.ja3s
                  << std::endl;
    }

    auto db = load_fingerprints("data/fingerprints.json");

    match_fingerprints(records, db);
    return 0;
}