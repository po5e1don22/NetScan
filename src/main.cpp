#include <iostream>

#include "suricata/suricata_runner.h"

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <pcap_file> <output_dir>" << std::endl;
        return 1;
    }

    std::string pcap_file = argv[1];
    std::string output_dir = argv [2];

    if (!run_suricata(pcap_file, output_dir))
    {
        return 1;
    }
    return 0;
}