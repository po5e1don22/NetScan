#include "third_party/json.hpp"
#include "ja3.h"

#include <fstream>
#include <iostream>
#include <string>

using json = nlohmann::json;

void add_unknown_fingerprint(const JA3Record& record, const std::string& db_path)
{
    json db;

    std::ifstream in(db_path);
    if (in.is_open())
        in >> db;
    
    if (!db.is_array())
        db = json::array();
    
    std::string label, category, source, notes;

    std::cout << "\n[NEW FINGERPRINT]\n";
    std::cout << "JA3: " << record.ja3 << "\n";

    std::cout << "Enter label: ";
    std::getline(std::cin >> std::ws, label);

    std::cout << "Enter category (benign/suspicious/malicious): ";
    std::getline(std::cin, category);

    std::cout << "Enter notes: ";
    std::getline(std::cin, notes);

    json entry = {
        {"fingerprint", {
            {"ja3", record.ja3},
            {"ja3s", record.ja3s}
        }},
        {"meta", {
            {"label", label},
            {"category", category},
            {"source", "user_added"},
            {"notes", notes}
        }}
    };


    for (const auto& item : db)
    {
        if (item.contains("fingerprint") && item["fingerprint"].contains("ja3") && item["fingerprint"]["ja3"] == record.ja3)
        {
            std::cout << "[INFO] JA3 already exists in DB\n";
            return;
        }
    }

    db.push_back(entry);

    std::ofstream out(db_path);
    out << db.dump(4);

    std::cout << "[INFO] Fingerprint added to DB\n";
}