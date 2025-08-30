#include "PcapParser.h"

#include <sstream>

PcapParser::PcapParser()
    : m_lastTimestamp({0, 0}),
      m_pcapFilePath(""),
      m_outputCsvFilePath(""),
      m_pcapReader(nullptr)
{
}

PcapParser::PcapParser(const std::string& pcapFilePath, const std::string& outputCsvFilePath)
    : m_lastTimestamp({0, 0}),
      m_pcapFilePath(pcapFilePath),
      m_outputCsvFilePath(outputCsvFilePath),
      m_pcapReader(nullptr)
{
    m_pcapReader = new pcpp::PcapFileReaderDevice(pcapFilePath);
}

PcapParser::~PcapParser()
{
    if (m_pcapReader != nullptr)
    {
        if (m_pcapReader->isOpened())
            m_pcapReader->close();
        delete m_pcapReader;
    }
}

bool PcapParser::ParseFile()
{
    if (!m_pcapReader->open())
    {
        std::cerr << "Error opening the pcap file: " << m_pcapFilePath << std::endl;
        return false;
    }

    pcpp::RawPacket rawPacket;
    while (m_pcapReader->getNextPacket(rawPacket))
    {
        ProcessPacket(rawPacket);
    }

    m_pcapReader->close();
    PrintPacketInfoTable(m_outputCsvFilePath);
    return true;
}

void PcapParser::ProcessPacket(pcpp::RawPacket& rawPacket)
{
    pcpp::Packet parsedPacket(&rawPacket);
    PacketInfo info;

    timespec currentTimestamp = rawPacket.getPacketTimeStamp();
    if (m_lastTimestamp.tv_sec == 0 && m_lastTimestamp.tv_nsec == 0)
    {
        info.timeDelta = 0.0;
    }
    else
    {
        info.timeDelta = (double)(currentTimestamp.tv_sec - m_lastTimestamp.tv_sec) +
                         (double)(currentTimestamp.tv_nsec - m_lastTimestamp.tv_nsec) / 1000000000.0;
    }
    m_lastTimestamp = currentTimestamp;
    info.packetLength = rawPacket.getRawDataLen();

    pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ethLayer != nullptr)
    {
        info.ethSrcMac = ethLayer->getSourceMac().toString();
        info.ethDstMac = ethLayer->getDestMac().toString();
        std::stringstream ss;
        ss << "0x" << std::hex << ethLayer->getEthHeader()->etherType;
        info.ethType = ss.str();
    }

    pcpp::ArpLayer* arpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();
    if (arpLayer != nullptr)
    {
        info.arpOperation = (arpLayer->getArpHeader()->opcode == pcpp::ARP_REQUEST ? "Request" : "Reply");
        info.arpSenderMac = arpLayer->getSenderMacAddress().toString();
        info.arpSenderIp = arpLayer->getSenderIpAddr().toString();
        info.arpTargetMac = arpLayer->getTargetMacAddress().toString();
        info.arpTargetIp = arpLayer->getTargetIpAddr().toString();
    }

    pcpp::IPv4Layer* ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    if (ipv4Layer != nullptr)
    {
        info.ipv4SrcIp = ipv4Layer->getSrcIPv4Address().toString();
        info.ipv4DstIp = ipv4Layer->getDstIPv4Address().toString();
        info.ipv4TTL = (int)ipv4Layer->getIPv4Header()->timeToLive;
        info.ipv4Protocol = (int)ipv4Layer->getIPv4Header()->protocol;
    }

    pcpp::IPv6Layer* ipv6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
    if (ipv6Layer != nullptr)
    {
        info.ipv6SrcIp = ipv6Layer->getSrcIPv6Address().toString();
        info.ipv6DstIp = ipv6Layer->getDstIPv6Address().toString();
        info.ipv6NextHeader = (int)ipv6Layer->getIPv6Header()->nextHeader;
        info.ipv6HopLimit = (int)ipv6Layer->getIPv6Header()->hopLimit;
    }

    pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    if (tcpLayer != nullptr)
    {
        info.tcpSrcPort = ntohs(tcpLayer->getTcpHeader()->portSrc);
        info.tcpDstPort = ntohs(tcpLayer->getTcpHeader()->portDst);
        info.tcpSequenceNumber = ntohl(tcpLayer->getTcpHeader()->sequenceNumber);
        info.tcpAckNumber = ntohl(tcpLayer->getTcpHeader()->ackNumber);
        info.tcpWindowSize = ntohs(tcpLayer->getTcpHeader()->windowSize);
        ParseTcpOptions(tcpLayer, info);
    }

    pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    if (udpLayer != nullptr)
    {
        info.udpSrcPort = ntohs(udpLayer->getUdpHeader()->portSrc);
        info.udpDstPort = ntohs(udpLayer->getUdpHeader()->portDst);
        info.udpLength = ntohs(udpLayer->getUdpHeader()->length);
    }

    pcpp::IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
    if (icmpLayer != nullptr)
    {
        info.icmpType = (int)icmpLayer->getIcmpHeader()->type;
        info.icmpCode = (int)icmpLayer->getIcmpHeader()->code;
        std::stringstream ss;
        ss << "0x" << std::hex << ntohs(icmpLayer->getIcmpHeader()->checksum);
        info.icmpChecksum = ss.str();
    }

    pcpp::IcmpV6Layer* icmpv6Layer = parsedPacket.getLayerOfType<pcpp::IcmpV6Layer>();
    if (icmpv6Layer != nullptr)
    {
        info.icmpv6Type = (int)icmpv6Layer->getMessageType();
        info.icmpv6Code = (int)icmpv6Layer->getCode();
        std::stringstream ss;
        ss << "0x" << std::hex << ntohs(icmpv6Layer->getChecksum());
        info.icmpv6Checksum = ss.str();
    }

    m_packetInfos.push_back(info);
}

void PcapParser::ParseTcpOptions(pcpp::TcpLayer* tcpLayer, PacketInfo& info)
{
    if (tcpLayer == nullptr)
        return;

    for (pcpp::TcpOption tcpOption = tcpLayer->getFirstTcpOption(); tcpOption.isNotNull();
         tcpOption = tcpLayer->getNextTcpOption(tcpOption))
    {
        if (tcpOption.getTcpOptionEnumType() == static_cast<pcpp::TcpOptionEnumType>(pcpp::PCPP_TCPOPT_TIMESTAMP))
        {
            const uint8_t* optionData = tcpOption.getValue();
            if (optionData != nullptr && tcpOption.getDataSize() >= 8)
            {
                uint32_t tsval = ntohl(*reinterpret_cast<const uint32_t*>(optionData));
                uint32_t tsecr = ntohl(*reinterpret_cast<const uint32_t*>(optionData + 4));
                info.tcpTsVal = tsval;
                info.tcpTsEcr = tsecr;
                break;
            }
        }
    }
}

void PcapParser::PrintPacketInfoTable(const std::string& filename)
{
    std::ofstream outputFile(filename);
    if (!outputFile.is_open())
    {
        std::cerr << "Error: Could not open file " << filename << " for writing." << std::endl;
        return;
    }

    outputFile
        << "No,Time Delta,Length,Eth Src,Eth Dst,Eth Type,IPv4 Src,IPv4 Dst,IPv4 TTL,IPv4 Proto,IPv6 Src,IPv6 Dst,IPv6 "
           "Next,IPv6 Hop,ARP Op,ARP Sender MAC,ARP Sender IP,ARP Target MAC,ARP Target IP,TCP Src,TCP Dst,TCP Seq,TCP "
           "Ack,TCP Win,TCP TSval,TCP TSecr,UDP Src,UDP Dst,UDP Len,ICMP Type,ICMP Code,ICMP Chksum,ICMPv6 Type,ICMPv6 "
           "Code,ICMPv6 Chksum"
        << std::endl;

    int seqNo = 1;
    for (const auto& info : m_packetInfos)
    {
        outputFile << seqNo++ << "," << std::fixed << std::setprecision(6) << info.timeDelta << "," << info.packetLength
                   << "," << info.ethSrcMac << "," << info.ethDstMac << ","
                   << (info.ethType.empty() ? "-" : info.ethType) << ","
                   << (info.ipv4SrcIp.empty() ? "-" : info.ipv4SrcIp) << ","
                   << (info.ipv4DstIp.empty() ? "-" : info.ipv4DstIp) << ","
                   << (info.ipv4TTL == 0 ? "-" : std::to_string(info.ipv4TTL)) << ","
                   << (info.ipv4Protocol == 0 ? "-" : std::to_string(info.ipv4Protocol)) << ","
                   << (info.ipv6SrcIp.empty() ? "-" : info.ipv6SrcIp) << ","
                   << (info.ipv6DstIp.empty() ? "-" : info.ipv6DstIp) << ","
                   << (info.ipv6NextHeader == 0 ? "-" : std::to_string(info.ipv6NextHeader)) << ","
                   << (info.ipv6HopLimit == 0 ? "-" : std::to_string(info.ipv6HopLimit)) << ","
                   << (info.arpOperation.empty() ? "-" : info.arpOperation) << ","
                   << (info.arpSenderMac.empty() ? "-" : info.arpSenderMac) << ","
                   << (info.arpSenderIp.empty() ? "-" : info.arpSenderIp) << ","
                   << (info.arpTargetMac.empty() ? "-" : info.arpTargetMac) << ","
                   << (info.arpTargetIp.empty() ? "-" : info.arpTargetIp) << ","
                   << (info.tcpSrcPort == 0 ? "-" : std::to_string(info.tcpSrcPort)) << ","
                   << (info.tcpDstPort == 0 ? "-" : std::to_string(info.tcpDstPort)) << ","
                   << (info.tcpSequenceNumber == 0 ? "-" : std::to_string(info.tcpSequenceNumber)) << ","
                   << (info.tcpAckNumber == 0 ? "-" : std::to_string(info.tcpAckNumber)) << ","
                   << (info.tcpWindowSize == 0 ? "-" : std::to_string(info.tcpWindowSize)) << ","
                   << (info.tcpTsVal == 0 ? "-" : std::to_string(info.tcpTsVal)) << ","
                   << (info.tcpTsEcr == 0 ? "-" : std::to_string(info.tcpTsEcr)) << ","
                   << (info.udpSrcPort == 0 ? "-" : std::to_string(info.udpSrcPort)) << ","
                   << (info.udpDstPort == 0 ? "-" : std::to_string(info.udpDstPort)) << ","
                   << (info.udpLength == 0 ? "-" : std::to_string(info.udpLength)) << ","
                   << (info.icmpType == 0 ? "-" : std::to_string(info.icmpType)) << ","
                   << (info.icmpCode == 0 ? "-" : std::to_string(info.icmpCode)) << ","
                   << (info.icmpChecksum.empty() ? "-" : info.icmpChecksum) << ","
                   << (info.icmpv6Type == 0 ? "-" : std::to_string(info.icmpv6Type)) << ","
                   << (info.icmpv6Code == 0 ? "-" : std::to_string(info.icmpv6Code)) << ","
                   << (info.icmpv6Checksum.empty() ? "-" : info.icmpv6Checksum) << std::endl;
    }

    outputFile.close();
}
