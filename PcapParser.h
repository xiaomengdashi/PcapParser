#pragma once

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "pcapplusplus/ArpLayer.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/IPv6Layer.h"
#include "pcapplusplus/IcmpLayer.h"
#include "pcapplusplus/IcmpV6Layer.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/RawPacket.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/UdpLayer.h"

struct PacketInfo
{
    double timeDelta = 0.0;
    int packetLength = 0;
    std::string ethSrcMac = "";
    std::string ethDstMac = "";
    std::string ethType = "";
    std::string ipv4SrcIp = "";
    std::string ipv4DstIp = "";
    int ipv4TTL = 0;
    int ipv4Protocol = 0;
    std::string ipv6SrcIp = "";
    std::string ipv6DstIp = "";
    int ipv6NextHeader = 0;
    int ipv6HopLimit = 0;
    std::string arpOperation = "";
    std::string arpSenderMac = "";
    std::string arpSenderIp = "";
    std::string arpTargetMac = "";
    std::string arpTargetIp = "";
    int udpSrcPort = 0;
    int udpDstPort = 0;
    int udpLength = 0;
    int tcpSrcPort = 0;
    int tcpDstPort = 0;
    long tcpSequenceNumber = 0;
    long tcpAckNumber = 0;
    int tcpWindowSize = 0;
    long tcpTsVal = 0;
    long tcpTsEcr = 0;
    int icmpType = 0;
    int icmpCode = 0;
    std::string icmpChecksum = "";
    int icmpv6Type = 0;
    int icmpv6Code = 0;
    std::string icmpv6Checksum = "";

    PacketInfo() = default;
};

/**
 * @brief A C++ class for parsing pcap files using PcapPlusPlus library.
 */
class PcapParser
{
   public:
    /**
     * @brief Default constructor for PcapParser.
     */
    PcapParser();

    /**
     * @brief Constructor for PcapParser with file paths.
     * @param pcapFilePath The path to the pcap file to be parsed.
     * @param outputCsvFilePath The path to the output CSV file.
     */
    explicit PcapParser(const std::string& pcapFilePath, const std::string& outputCsvFilePath);

    /**
     * @brief Destructor for PcapParser.
     */
    ~PcapParser();

    /**
     * @brief Parses the pcap file and prints information about each packet.
     * @return True if parsing is successful, false otherwise.
     */
    bool ParseFile();

    /**
     * @brief Prints all parsed packet information in a table format.
     * @param filename The output CSV file name.
     */
    void PrintPacketInfoTable(const std::string& filename);

    /**
     * @brief Parses TCP options from the TCP layer.
     * @param tcpLayer The TCP layer to parse options from.
     * @param info The packet info structure to populate.
     */
    void ParseTcpOptions(pcpp::TcpLayer* tcpLayer, PacketInfo& info);

    /**
     * @brief Processes a single packet and extracts relevant information.
     * @param rawPacket The raw packet data.
     */
    void ProcessPacket(pcpp::RawPacket& rawPacket);

    /**
     * @brief Filter packets by protocol type
     * @param protocol Protocol type (6=TCP, 17=UDP, 1=ICMP, etc.)
     * @return List of filtered packets
     */
    std::vector<PacketInfo> FilterByProtocol(int protocol) const;

    /**
     * @brief Filter packets by IP address
     * @param ip IP address string
     * @param isSource Filter source IP if true, destination IP if false
     * @return List of filtered packets
     */
    std::vector<PacketInfo> FilterByIp(const std::string& ip, bool isSource = true) const;

    /**
     * @brief Filter packets by port number
     * @param port Port number
     * @param isSource Filter source port if true, destination port if false
     * @return List of filtered packets
     */
    std::vector<PacketInfo> FilterByPort(int port, bool isSource = true) const;

    /**
     * @brief Search packets containing specific content
     * @param keyword Search keyword
     * @param caseSensitive Whether case sensitive search
     * @return List of packets containing the keyword
     */
    std::vector<PacketInfo> SearchPackets(const std::string& keyword, bool caseSensitive = false) const;

    /**
     * @brief Get all parsed packets
     * @return Constant reference to the packet list
     */
    const std::vector<PacketInfo>& GetAllPackets() const;

   private:
    timespec m_lastTimestamp;
    std::string m_pcapFilePath;
    std::string m_outputCsvFilePath;
    pcpp::PcapFileReaderDevice* m_pcapReader;
    std::vector<PacketInfo> m_packetInfos;
};
