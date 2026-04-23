#pragma once
#include <string>
#include <vector>
#include "core/ja3.h"

struct GUIState
{
    char pcap_path[512] = "";

    std::vector<JA3Record> records;
    bool scan_running = false;
};