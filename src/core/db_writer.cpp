#include "third_party/json.hpp"
#include "ja3.h"

#include <fstream>
#include <iostream>
#include <string>

using json = nlohmann::json;

void add_unknown_fingerprint(const JA3Record& record, const std::string& db_path)
{
    std::cout << "\n[?] Add this fingerprint? (y/n): ";
    char confirm;
    std::cin >> confirm;

    if (confirm != 'y' && confirm != 'Y')
        return;

    std::cin.ignore();

    json db;

    std::ifstream in(db_path);
    if (in.is_open())
        in >> db;
    
    if (!db.is_array())
        db = json::array();
    
    std::string label, category, source, notes;

    std::cout << "\n[NEW FINGERPRINT]\n";
    std::cout << "JA3: " << record.ja3 << "\n";

    if (!record.ja3s.empty())
    std::cout << "JA3S: " << record.ja3s << "\n";

    std::cout << "Enter label: ";
    std::getline(std::cin >> std::ws, label);

    std::cout << "Enter category (benign/suspicious/malicious): ";
    std::getline(std::cin, category);

    if (category.empty())
    category = "unknown";

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
        if (!item.contains("fingerprint"))
            continue;

        const auto& fp = item["fingerprint"];

        std::string ja3 = fp.value("ja3", "");
        std::string ja3s = fp.value("ja3s", "");

        // FULL match
        if (!record.ja3.empty() && !record.ja3s.empty() &&
            ja3 == record.ja3 && ja3s == record.ja3s)
        {
            std::cout << "[INFO] Full fingerprint already exists\n";
            return;
        }

        // JA3 match
        if (!record.ja3.empty() && ja3 == record.ja3)
        {
            std::cout << "[INFO] JA3 already exists\n";
            return;
        }

        // JA3S match
        if (!record.ja3s.empty() && ja3s == record.ja3s)
        {
            std::cout << "[INFO] JA3S already exists\n";
            return;
        }
    }

    db.push_back(entry);

    std::ofstream out(db_path);
    out << db.dump(4);

    std::cout << "[INFO] Fingerprint added to DB\n";
}