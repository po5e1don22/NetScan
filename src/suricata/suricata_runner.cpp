#include <cstdlib>
#include <iostream>
#include <filesystem>

bool run_suricata(const std::string& pcap_file, const std::string& output_dir)
{
    try //create output folder if not exist
    {
        if (!std::filesystem::exists(output_dir))
        {
            std::filesystem::create_directories(output_dir);
            std::cout << "[INFO] Created output directory: " << output_dir << std::endl;
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << "[ERROR] Faild to create directory: " << e.what() << std::endl;
        return false;
    }

    //suricata run command 
    std::string command = "suricata -r " + pcap_file + " -l " + output_dir;

    std::cout << "[INFO] Running: " << command << std::endl;
    int result = std::system(command.c_str());

    if (result !=0)
    {
        std::cerr << "[ERROR] Suricata failed with code:" << result << std::endl;
        return false;
    }
    return true;
}