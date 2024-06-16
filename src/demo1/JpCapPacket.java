package demo1;

import jpcap.JpcapCaptor;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;

import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.util.Vector;

public class JpCapPacket {
    private JpcapCaptor jpcap;

    public JpCapPacket(JpcapCaptor jpcap) {
        this.jpcap = jpcap;
    }

    void capture() throws InterruptedException {
        int i = 0;
        while (true) {
            synchronized (JpCapMain.getThread()) {
                if (JpCapMain.isPause()) {
                    JpCapMain.getThread().wait();
                }
            }
            Packet packet = jpcap.getPacket();
            if (packet instanceof IPPacket && ((IPPacket) packet).version == 4) {
                i++;
                IPPacket ip = (IPPacket) packet;//此处经过询问得知可直接强转

                System.out.println("版本：IPv4");
                System.out.println("优先权：" + ip.priority);
                System.out.println("区分服务：最大的吞吐量： " + ip.t_flag);
                System.out.println("区分服务：最高的可靠性：" + ip.r_flag);
                System.out.println("长度：" + ip.length);
                System.out.println("标识：" + ip.ident);
                System.out.println("DF:Don't Fragment: " + ip.dont_frag);
                System.out.println("NF:Nore Fragment: " + ip.more_frag);
                System.out.println("片偏移：" + ip.offset);
                System.out.println("生存时间：" + ip.hop_limit);

                String protocol = "";
                switch (new Integer(ip.protocol)) {
                    case 1:
                        protocol = "ICMP";
                        break;
                    case 2:
                        protocol = "IGMP";
                        break;
                    case 6:
                        protocol = "TCP";
                        break;
                    case 8:
                        protocol = "EGP";
                        break;
                    case 9:
                        protocol = "IGP";
                        break;
                    case 17:
                        protocol = "UDP";
                        break;
                    case 41:
                        protocol = "IPv6";
                        break;
                    case 89:
                        protocol = "OSPF";
                        break;
                    default:
                        break;
                }
                //控制台部分
                System.out.println("协议：" + protocol);
                System.out.println("源IP " + ip.src_ip.getHostAddress());
                System.out.println("目的IP " + ip.dst_ip.getHostAddress());
                System.out.println("源主机名： " + ip.src_ip);
                System.out.println("目的主机名： " + ip.dst_ip);
                String filterInput = JpCapFrame.getFilterField().getText();
                if (filterInput.equals(ip.src_ip.getHostAddress()) ||
                        filterInput.equals(ip.dst_ip.getHostAddress()) ||
                        filterInput.equals(protocol) ||
                        filterInput.equals("")) {
                    Vector dataVector = new Vector();
                    Timestamp timestamp = new Timestamp((packet.sec * 1000) + (packet.usec / 1000));


                    //传入前台
                    //提前解析数据包？然后再进行传入？
                    byte[] packetData=packet.data;
                    String analyzed = AnalyzePacket(packetData,protocol);

                    dataVector.addElement(i + "");
                    dataVector.addElement(timestamp.toString());//数据包时间
                    dataVector.addElement(ip.src_ip.getHostAddress());
                    dataVector.addElement(ip.dst_ip.getHostAddress());
                    dataVector.addElement(protocol);
                    dataVector.addElement(packet.data.length);
                    dataVector.addElement(analyzed); //数据内容

                    JpCapFrame.getModel().addRow(dataVector);
                }
            }
        }
    }

    private String AnalyzePacket(byte[] packetData, String protocol) {
        StringBuilder result = new StringBuilder();
        ByteBuffer buffer=ByteBuffer.wrap(packetData);

        try {
            if (protocol.equals("ICMP")) {
                // 解析 ICMP 协议数据包
                // 解析ICMP类型
                byte icmpType = buffer.get();
                result.append("Type: ").append(icmpType).append("\n");

                // 解析ICMP代码
                byte icmpCode = buffer.get();
                result.append("Code: ").append(icmpCode).append("\n");

                // 解析ICMP校验和
                short checksum = buffer.getShort();
                result.append("Checksum: 0x").append(String.format("%04X", checksum)).append("\n");

                // 根据ICMP类型，可能还有额外的数据需要解析
                // 例如，对于类型为0（回显应答）和8（回显请求）的ICMP数据包，会有一个标识符和序列号
                if (icmpType == 0 || icmpType == 8) {
                    // 解析标识符
                    int identifier = buffer.getShort();
                    result.append("Identifier: 0x").append(String.format("%04X", identifier)).append("\n");

                    // 解析序列号
                    int sequenceNumber = buffer.getShort();
                    result.append("Sequence Number: ").append(sequenceNumber).append("\n");
                }


                result.append("ICMP packet analyzed");
            } else if (protocol.equals("IGMP")) {
                // 解析 IGMP 协议数据包
                // 跳过以太网头部（14字节）和IP头部（20字节）
                buffer.position(buffer.position() + 14 + 20);

                // 解析IGMP类型
                byte igmpType = buffer.get();
                result.append("Type: ").append(igmpType).append("\n");

                // 解析IGMP最大响应时间（对于查询消息）
                short maxResponseTime = buffer.getShort();
                if (igmpType == 0x11) { // 类型为0x11表示查询消息
                    result.append("Maximum Response Time: ").append(maxResponseTime / 10.0).append(" seconds\n");
                }

                // 解析IGMP校验和
                short checksum = buffer.getShort();
                result.append("Checksum: 0x").append(String.format("%04X", checksum)).append("\n");

                // 解析IGMP组地址（对于报告和离开消息）
                int groupAddress = buffer.getInt();
                if (igmpType == 0x12 || igmpType == 0x16) { // 类型为0x12表示报告消息，0x16表示离开消息
                    result.append("Group Address: ").append(intToIp(groupAddress)).append("\n");
                }

                result.append("IGMP packet analyzed");
            } else if (protocol.equals("TCP")) {
                // 解析 TCP 协议数据包

                // 跳过以太网头部（14字节）和IP头部（20字节）
                buffer.position(buffer.position() + 14 + 20);

                // 解析TCP源端口
                int sourcePort = buffer.getShort() & 0xFFFF;
                result.append("Source Port: ").append(sourcePort).append("\n");

                // 解析TCP目的端口
                int destinationPort = buffer.getShort() & 0xFFFF;
                result.append("Destination Port: ").append(destinationPort).append("\n");

                // 解析TCP序列号
                int sequenceNumber = buffer.getInt();
                result.append("Sequence Number: ").append(sequenceNumber).append("\n");

                // 解析TCP确认号
                int acknowledgmentNumber = buffer.getInt();
                result.append("Acknowledgment Number: ").append(acknowledgmentNumber).append("\n");

                // 解析TCP数据偏移（头部长度）
                int dataOffset = (buffer.get() & 0xF0) >> 4;
                result.append("Data Offset: ").append(dataOffset * 4).append(" bytes\n");

                // 解析TCP标志位
                byte flags = buffer.get();
                result.append("Flags: ");
                result.append((flags & 0x01) != 0 ? "FIN, " : "");
                result.append((flags & 0x02) != 0 ? "SYN, " : "");
                result.append((flags & 0x04) != 0 ? "RST, " : "");
                result.append((flags & 0x08) != 0 ? "PSH, " : "");
                result.append((flags & 0x10) != 0 ? "ACK, " : "");
                result.append((flags & 0x20) != 0 ? "URG, " : "");
                result.append("\n");

                // 解析TCP窗口大小
                int windowSize = buffer.getShort() & 0xFFFF;
                result.append("Window Size: ").append(windowSize).append("\n");

                // 解析TCP校验和
                int checksum = buffer.getShort() & 0xFFFF;
                result.append("Checksum: 0x").append(String.format("%04X", checksum)).append("\n");

                // 解析TCP紧急指针（如果有URG标志位）
                if ((flags & 0x20) != 0) {
                    int urgentPointer = buffer.getShort() & 0xFFFF;
                    result.append("Urgent Pointer: ").append(urgentPointer).append("\n");
                }

                // 根据数据偏移，计算TCP选项和数据的开始位置
                int optionsLength = (dataOffset * 4) - 20; // TCP头部固定长度为20字节
                buffer.position(buffer.position() + optionsLength);

                // 解析TCP数据载荷
                int payloadLength = buffer.remaining();
                byte[] payload = new byte[payloadLength];
                buffer.get(payload);
                result.append("Payload Length: ").append(payloadLength).append(" bytes\n");

                result.append("TCP packet analyzed");
            } else if (protocol.equals("EGP")) {
                // 解析 EGP 协议数据包

                result.append("EGP packet analyzed");
            } else if (protocol.equals("UDP")) {
                // 解析 UDP 协议数据包

                // 跳过以太网头部（14字节）和IP头部（20字节）
                buffer.position(buffer.position() + 14 + 20);

                // 解析UDP源端口
                int sourcePort = buffer.getShort() & 0xFFFF;
                result.append("Source Port: ").append(sourcePort).append("\n");

                // 解析UDP目的端口
                int destinationPort = buffer.getShort() & 0xFFFF;
                result.append("Destination Port: ").append(destinationPort).append("\n");

                // 解析UDP长度
                int length = buffer.getShort() & 0xFFFF;
                result.append("Length: ").append(length).append("\n");

                // 解析UDP校验和
                int checksum = buffer.getShort() & 0xFFFF;
                result.append("Checksum: 0x").append(String.format("%04X", checksum)).append("\n");

                // 解析UDP数据载荷
                int payloadLength = length - 8; // UDP头部固定长度为8字节
                byte[] payload = new byte[payloadLength];
                buffer.get(payload);
                result.append("Payload Length: ").append(payloadLength).append(" bytes\n");
                result.append("UDP packet analyzed");

            } else if (protocol.equals("IPv6")) {
                // 解析 IPv6 协议数据包

                // 解析IPv6版本和流量标签
                byte versionTrafficClassFlowLabel = buffer.get();
                result.append("Version/Traffic Class/Flow Label: 0x").append(String.format("%02X", versionTrafficClassFlowLabel)).append("\n");

                // 解析IPv6下一个头部
                byte nextHeader = buffer.get();
                result.append("Next Header: 0x").append(String.format("%02X", nextHeader)).append("\n");

                // 解析IPv6跳数限制
                int hopLimit = buffer.get();
                result.append("Hop Limit: ").append(hopLimit).append("\n");

                // 解析IPv6源地址
                int sourceAddress = buffer.getInt();
                result.append("Source Address: ").append(intToIpv6(sourceAddress)).append("\n");

                // 解析IPv6目的地址
                int destinationAddress = buffer.getInt();
                result.append("Destination Address: ").append(intToIpv6(destinationAddress)).append("\n");

                result.append("IPv6 packet analyzed");
            } else {
                result.append("Unsupported protocol");
            }
        } catch (Exception e) {
            result.append("Error in analyzing packet: ").append(e.getMessage());
        }

        return result.toString();
    }


    private String intToIp(int ipAddress) {
        return String.format("%d.%d.%d.%d",
                (ipAddress & 0xff),
                (ipAddress >> 8 & 0xff),
                (ipAddress >> 16 & 0xff),
                (ipAddress >> 24 & 0xff));
    }

    private String intToIpv6(int ipAddress) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            sb.append(String.format("%02X", (ipAddress >> (8 * i) & 0xFF)));
            if (i < 7) {
                sb.append(":");
            }
        }
        return sb.toString();
    }
}

