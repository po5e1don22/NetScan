#pragma once
#include <string>
#include <vector>
#include "core/ja3.h"
#include "core/matcher.h"

#include "imgui.h"

struct GUIState
{
    char pcap_path[512] = "";

    std::vector<JA3Record> records;
    std::vector<MatchResult> matches;
    bool scan_running = false;

    // popup state
    bool popup_open = false;
    int selected_index = -1;

    char input_label[128] = "";
    char input_category[64] = "";
    char input_notes[256] = "";
};

static const char* CATEGORY_ITEMS[] = {
    "benign",
    "suspicious",
    "malicious"
};

inline ImVec4 GetCategoryColor(const std::string& cat)
{
    if (cat == "benign")
        return ImVec4(0.2f, 1.0f, 0.2f, 1.0f);   // green
        
    if (cat == "suspicious")
        return ImVec4(1.0f, 0.6f, 0.0f, 1.0f);   // orange
    
        if (cat == "malicious")
        return ImVec4(1.0f, 0.2f, 0.2f, 1.0f);   // red


    return ImVec4(1,1,1,1);
}