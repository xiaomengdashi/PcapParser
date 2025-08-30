#include <iostream>

#include "PcapParser.h"

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <pcap_file_path> <output_csv_file_path>" << std::endl;
        return 1;
    }

    std::string pcapFilePath = argv[1];
    std::string outputCsvFilePath = argv[2];
    PcapParser parser(pcapFilePath, outputCsvFilePath);

    if (!parser.ParseFile())
    {
        std::cerr << "Failed to parse pcap file." << std::endl;
        return 1;
    }

    return 0;
}
