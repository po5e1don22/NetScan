#pragma once
#include <string>
#include <vector>
#include "core/ja3.h"
#include "core/matcher.h"

struct GUIState
{
    char pcap_path[512] = "";

    std::vector<JA3Record> records;
    std::vector<MatchResult> matches;
    bool scan_running = false;
};