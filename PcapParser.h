#ifndef PCAP_PARSER_H
#define PCAP_PARSER_H

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
     * @brief Constructor for PcapParser.
     * @param pcapFilePath The path to the pcap file to be parsed.
     */
    explicit PcapParser(const std::string& pcapFilePath, const std::string& outputCsvFilePath);

    /**
     * @brief Destructor for PcapParser.
     */
    ~PcapParser();

   private:
    timespec m_lastTimestamp;

   public:
    /**
     * @brief Parses the pcap file and prints information about each packet.
     * @return True if parsing is successful, false otherwise.
     */
    bool parseFile();

    /**
     * @brief Prints all parsed packet information in a table format.
     */
    void printPacketInfoTable(const std::string& filename);
    void parseTcpOptions(pcpp::TcpLayer* tcpLayer, PacketInfo& info);

   private:
    std::string m_pcapFilePath;
    std::string m_outputCsvFilePath;
    pcpp::PcapFileReaderDevice* m_pcapReader;
    std::vector<PacketInfo> m_packetInfos;

    /**
     * @brief Processes a single packet and extracts relevant information.
     * @param rawPacket The raw packet data.
     */
    void processPacket(pcpp::RawPacket& rawPacket);

    /**
     * @brief Prints Ethernet layer information.
     * @param ethLayer The Ethernet layer object.
     */
    void printEthLayer(pcpp::EthLayer* ethLayer);

    /**
     * @brief Prints IPv4 layer information.
     * @param ipv4Layer The IPv4 layer object.
     */
    void printIPv4Layer(pcpp::IPv4Layer* ipv4Layer);

    /**
     * @brief Prints IPv6 layer information.
     * @param ipv6Layer The IPv6 layer object.
     */
    void printIPv6Layer(pcpp::IPv6Layer* ipv6Layer);

    /**
     * @brief Prints ARP layer information.
     * @param arpLayer The ARP layer object.
     */
    void printArpLayer(pcpp::ArpLayer* arpLayer);

    /**
     * @brief Prints UDP layer information.
     * @param udpLayer The UDP layer object.
     */
    void printUdpLayer(pcpp::UdpLayer* udpLayer);

    /**
     * @brief Prints TCP layer information.
     * @param tcpLayer The TCP layer object.
     */
    void printTcpLayer(pcpp::TcpLayer* tcpLayer);

    /**
     * @brief Prints ICMP layer information.
     * @param icmpLayer The ICMP layer object.
     */
    void printIcmpLayer(pcpp::IcmpLayer* icmpLayer);

    /**
     * @brief Prints raw data in hexadecimal and ASCII format.
     * @param data The raw data buffer.
     * @param dataLen The length of the raw data.
     */
    void printRawData(const uint8_t* data, size_t dataLen);
};

#endif  // PCAP_PARSER_H
