#ifdef LOCAL

#ifndef __cplusplus
#error Why are you using a C compiler?
#endif
#if __cplusplus > 199711L
#error Why are you using C++11 or higher?
#endif

// <cstdint> not available in C++98
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

// static_assert not available in C++98
#define STATIC_ASSERT(expr, msg) char STATIC_ASSERTION__##msg[(expr) ? 1 : -1]
STATIC_ASSERT(sizeof(uint8_t) == 1, uint8_t_is_1_byte);
STATIC_ASSERT(sizeof(uint16_t) == 2, uint16_t_is_2_bytes);
STATIC_ASSERT(sizeof(uint32_t) == 4, uint32_t_is_4_bytes);

// <arpa/inet.h> or <winsock2.h>, should be provided by OS
extern "C" {
uint32_t htonl(uint32_t hostlong);
uint16_t htons(uint16_t hostshort);
uint32_t ntohl(uint32_t netlong);
uint16_t ntohs(uint16_t netshort);
}

// <sys/socket.h> & <netinet/in.h> or <winsock2.h>
typedef uint32_t in_addr_t;
typedef unsigned short u_short;
struct in_addr {
    in_addr_t s_addr;
};
struct sockaddr_in {
    short sin_family;
    u_short sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};

#define IPPROTO_TCP 6

// -- predefined --

typedef uint32_t UINT32;
typedef uint16_t uint16;
typedef uint8_t uint8;

/// 序列号错误
#define STUD_TCP_TEST_SEQNO_ERROR (0x01)

/// 源端口错误
#define STUD_TCP_TEST_SRCPORT_ERROR (0x02)

/// 目的端口错误
#define STUD_TCP_TEST_DSTPORT_ERROR (0x03)

/// 数据
#define PACKET_TYPE_DATA (0x00)

/// SYN 标志位开
#define PACKET_TYPE_SYN (0x01)

/// ACK 标志位开
#define PACKET_TYPE_ACK (0x02)

/// SYN、ACK 标志位开
#define PACKET_TYPE_SYN_ACK ((PACKET_TYPE_SYN) | (PACKET_TYPE_ACK))

/// FIN 标志位开
#define PACKET_TYPE_FIN (0x04)

/// FIN、ACK 标志位开
#define PACKET_TYPE_FIN_ACK ((PACKET_TYPE_FIN) | (PACKET_TYPE_ACK))

#else
#include "sysinclude.h"
#endif

#include <cstring>
#include <stdexcept>
#include <vector>

int gSrcPort = 2005;
int gDstPort = 2006;
int gSeqNum = 1;
int gAckNum = 1;

/**
 * @brief TCP 处理中由于某种原因丢弃报文
 *
 * @param pBuffer 指向被丢弃的报文
 * @param type 报文丢弃的原因
 */
void tcp_DiscardPkt(char* pBuffer, int type);

/**
 * @brief IP 报文发送函数
 * @param pData IP 上层协议数据
 * @param len IP 上层协议数据长度
 * @param srcAddr 源 IP 地址
 * @param dstAddr 目的 IP 地址
 * @param ttl 跳极限
 */
void tcp_sendIpPkt(unsigned char* pData, uint16 len, unsigned int srcAddr, unsigned int dstAddr,
                   uint8 ttl);

/**
 * @brief IP 数据报文主动接收
 *
 * @param pBuffer 接收缓冲区的指针
 * @param timeout 等待时间
 * @return 如果正确接收则返回接收到的数据长度，否则返回 @c -1
 */
int waitIpPacket(char* pBuffer, int timeout);

/**
 * @brief 客户端获得本机 IPv4 地址
 * @return 本机 IPv4 地址
 */
UINT32 getIpv4Address();

/**
 * @brief 客户端获得服务器IPv4 地址
 * @return 服务器 IPv4 地址
 */
UINT32 getServerIpv4Address();

// -- required --

/**
 * @brief TCP 分组接收函数
 * @param pBuff 指向接收缓冲区的指针，从 TCP 头开始
 * @param len 缓冲区数据长度
 * @param srcAddr 源 IP 地址
 * @param dstAddr 目的 IP 地址
 * @return 如果成功则返回 @c 0 ，否则返回 @c -1
 */
int stud_tcp_input(char* pBuff, unsigned short len, unsigned int srcAddr, unsigned int dstAddr);

/**
 * @brief TCP 分组发送函数
 * @param pData 数据指针
 * @param len 数据长度
 * @param flag 分组类型
 * @param srcPort 源端口
 * @param dstPort 目的端口
 * @param srcAddr 源 IP 地址
 * @param dstAddr 目的 IP 地址
 */
void stud_tcp_output(char* pData, unsigned short len, unsigned char flag, unsigned short srcPort,
                     unsigned short dstPort, unsigned int srcAddr, unsigned int dstAddr);

/**
 * @brief 获得 socket 描述符
 * @param domain 套接字标志符，缺省为 @c INET
 * @param type 类型，缺省为 @c SOCK_STREAM
 * @param protocol 协议，缺省为 @c IPPROTO_TCP
 * @return 如果正确建连则返回 socket 值，否则返回 @c -1
 */
int stud_tcp_socket(int domain, int type, int protocol);

/**
 * @brief TCP 建立连接函数
 * @param sockfd 套接字标志符
 * @param addr socket 地址结构指针
 * @param addrlen 地址结构的大小
 * @return 如果正确发送则返回 @c 0 ，否则返回 @c -1
 */
int stud_tcp_connect(int sockfd, struct sockaddr_in* addr, int addrlen);

/**
 * @brief TCP 报文发送函数
 * @param sockfd 套接字标志符
 * @param pData 数据缓冲区指针
 * @param datalen 数据长度
 * @param flags 标志
 * @return 如果正确接收则返回 @c 0 ，否则返回 @c -1
 */
int stud_tcp_send(int sockfd, const unsigned char* pData, unsigned short datalen, int flags);

/**
 * @brief TCP 报文接收函数
 * @param sockfd 套接字标识符
 * @param pData 数据缓冲区指针
 * @param datalen 数据长度
 * @param flags 标志
 * @return 如果正确接收则返回 @c 0 ，否则返回 @c -1
 */
int stud_tcp_recv(int sockfd, unsigned char* pData, unsigned short datalen, int flags);

/**
 * @brief TCP 关闭连接函数
 * @param sockfd 连接描述符
 * @return 如果正常关闭则返回 @c 0 ，否则返回 @c -1
 */
int stud_tcp_close(int sockfd);

// -- implementation --

#pragma pack(1)
struct TCPPseudoHeader {
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcpLength;
};
struct TCPHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t ns : 1;
    uint8_t reserved : 3;
    uint8_t offset : 4;
    uint8_t fin : 1;
    uint8_t syn : 1;
    uint8_t rst : 1;
    uint8_t psh : 1;
    uint8_t ack : 1;
    uint8_t urg : 1;
    uint8_t ece : 1;
    uint8_t cwr : 1;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgentPointer;

    uint16_t verifyChecksum(const TCPPseudoHeader* pesudoHeader) const {
        uint32_t sum = 0;
        const uint16_t* p1 = reinterpret_cast<const uint16_t*>(pesudoHeader);
        const uint16_t* p2 = reinterpret_cast<const uint16_t*>(this);
        for (int i = 0; i < 6; i++) {
            sum += ntohs(p1[i]);
        }
        const int length = ntohs(pesudoHeader->tcpLength);
        for (int i = 0; i < length / 2; i++) {
            sum += ntohs(p2[i]);
        }
        if (length % 2 != 0) {
            sum += ntohs(p2[length / 2] & 0xff00);
        }
        return sum + (sum >> 16);
    }

    void generateChecksum(const TCPPseudoHeader* pesudoHeader) {
        checksum = 0;
        uint16_t should = verifyChecksum(pesudoHeader);
        checksum = ~htons(should);
    }
};
#pragma pack()

class StuTcpTestException : public std::runtime_error {
public:
    uint8_t type;
    StuTcpTestException(uint8_t type = 0) : std::runtime_error("StuTcpTestException"), type(type) {}
};

class TCB {
    enum {
        LISTEN,
        SYN_SENT,
        SYN_RECEIVED,
        ESTABLISHED,
        FIN_WAIT_1,
        FIN_WAIT_2,
        CLOSE_WAIT,
        CLOSING,
        LAST_ACK,
        TIME_WAIT,
        CLOSED
    } status;
    uint32_t seq;          ///< 下一次发送报文的 seq 值
    uint32_t ack;          ///< 下一次发送报文的 ack 值
    uint32_t expectedAck;  ///< 期望下次收到的 ACK 值
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint16_t srcPort;
    uint16_t dstPort;

    TCB(const TCB&);             // deleted
    TCB& operator=(const TCB&);  // deleted

    uint32_t stepNum(uint32_t totalLen) {
        if (status == ESTABLISHED) {
            return totalLen - sizeof(TCPHeader);
        } else {
            return 1;
        }
    }

public:
    TCB(uint32_t srcAddr, uint32_t dstAddr, uint16_t srcPort, uint16_t dstPort)
        : status(CLOSED),
          seq(gSeqNum),
          ack(gAckNum),
          expectedAck(0),
          srcAddr(srcAddr),
          dstAddr(dstAddr),
          srcPort(srcPort),
          dstPort(dstPort) {}

    static TCB& getInstance(uint32_t srcAddr, uint32_t dstAddr, uint16_t srcPort,
                            uint16_t dstPort) {
        static TCB instance(srcAddr, dstAddr, srcPort, dstPort);
        return instance;
    }

    /** 网络序 */
    uint32_t getSeq() const {
        return htonl(seq);
    }

    /** 网络序 */
    uint32_t getAck() const {
        return htonl(ack);
    }

    void receive(const TCPHeader* header, uint32_t totalLen) {
        const TCPPseudoHeader pesudoHeader = {
            htonl(srcAddr), htonl(dstAddr), 0, IPPROTO_TCP, htons(totalLen),
        };
        if (header->verifyChecksum(&pesudoHeader) != 0xffff) {
            throw StuTcpTestException();
        }
        if (ntohl(header->ackNum) != expectedAck) {
            throw StuTcpTestException(STUD_TCP_TEST_SEQNO_ERROR);
        }
        if (ntohs(header->srcPort) != dstPort) {
            throw StuTcpTestException(STUD_TCP_TEST_SRCPORT_ERROR);
        }
        if (ntohs(header->dstPort) != srcPort) {
            throw StuTcpTestException(STUD_TCP_TEST_DSTPORT_ERROR);
        }
        seq = ntohl(header->ackNum);
        ack = ntohl(header->seqNum) + stepNum(totalLen);

        switch (status) {
            case SYN_SENT: {
                if (header->syn && header->ack) {
                    send(NULL, 0, PACKET_TYPE_ACK);
                    status = ESTABLISHED;
                    return;
                }
                break;
            }
            case ESTABLISHED: {
                send(NULL, 0, PACKET_TYPE_ACK);
                return;
            }
            case FIN_WAIT_1: {
                if (header->ack) {
                    status = FIN_WAIT_2;
                    return;
                }
                break;
            }
            case FIN_WAIT_2: {
                if (header->fin) {
                    send(NULL, 0, PACKET_TYPE_ACK);
                    status = TIME_WAIT;
                    // Should sleep for a while
                    status = CLOSED;
                    return;
                }
                break;
            }
            default: break;
        }
        throw std::runtime_error("Illegal status");
    }

    void send(const char* data, unsigned short dataLen, unsigned char flag) {
        const std::size_t totalLen = dataLen + sizeof(TCPHeader);
        unsigned char* buffer = new unsigned char[totalLen];
        std::memset(buffer, 0, totalLen);
        std::memcpy(buffer + sizeof(TCPHeader), data, dataLen);

        TCPHeader* header = reinterpret_cast<TCPHeader*>(buffer);
        TCPPseudoHeader pesudoHeader = {
            htonl(srcAddr), htonl(dstAddr), 0, IPPROTO_TCP, htons(totalLen),
        };
        header->srcPort = htons(srcPort);
        header->dstPort = htons(dstPort);
        header->offset = 5;
        switch (flag) {
            case PACKET_TYPE_SYN: header->syn = 1; break;
            case PACKET_TYPE_ACK: header->ack = 1; break;
            case PACKET_TYPE_SYN_ACK:
                header->syn = 1;
                header->ack = 1;
                break;
            case PACKET_TYPE_FIN: header->fin = 1; break;
            case PACKET_TYPE_FIN_ACK:
                header->fin = 1;
                header->ack = 1;
                break;
        }
        header->window = htons(1);
        header->seqNum = getSeq();
        header->ackNum = getAck();
        header->generateChecksum(&pesudoHeader);

        switch (status) {
            case CLOSED: {
                if (header->syn) {
                    status = SYN_SENT;
                }
                break;
            }
            case ESTABLISHED: {
                if (header->fin) {
                    status = FIN_WAIT_1;
                }
                break;
            }
            default: break;
        }
        expectedAck = seq + stepNum(totalLen);

        tcp_sendIpPkt(buffer, totalLen, srcAddr, dstAddr, 60);
        delete[] buffer;
    }
};

int stud_tcp_input(char* pBuff, unsigned short len, unsigned int srcAddr, unsigned int dstAddr) {
    const TCPHeader* header = reinterpret_cast<TCPHeader*>(pBuff);
    TCB& tcb = TCB::getInstance(srcAddr, dstAddr, header->srcPort, header->dstPort);
    try {
        tcb.receive(header, len);
        return 0;
    } catch (StuTcpTestException& e) {
        if (e.type) {
            tcp_DiscardPkt(pBuff, e.type);
        }
        return -1;
    }
}

void stud_tcp_output(char* pData, unsigned short len, unsigned char flag, unsigned short srcPort,
                     unsigned short dstPort, unsigned int srcAddr, unsigned int dstAddr) {
    TCB& tcb = TCB::getInstance(srcAddr, dstAddr, srcPort, dstPort);
    tcb.send(pData, len, flag);
}

std::vector<TCB*> sockets = std::vector<TCB*>(1);

int stud_tcp_socket(int domain, int type, int protocol) {
    static_cast<void>(domain);
    static_cast<void>(type);
    static_cast<void>(protocol);
    sockets.push_back(NULL);
    return sockets.size() - 1;
}

//! CRITICAL ERROR: how large it should be?
/** waitIpPacket 不告诉我需要多少内存分配，迫不得已只能使用定长缓冲区 */
char globalBuffer[1024];

int stud_tcp_connect(int sockfd, struct sockaddr_in* addr, int addrlen) {
    static_cast<void>(addrlen);
    sockets[sockfd] =
        new TCB(getIpv4Address(), getServerIpv4Address(), gSrcPort++, ntohs(addr->sin_port));
    return stud_tcp_send(sockfd, NULL, 0, PACKET_TYPE_SYN);
}

int stud_tcp_send(int sockfd, const unsigned char* pData, unsigned short datalen, int flags) {
    TCB& tcb = *sockets[sockfd];
    tcb.send(reinterpret_cast<const char*>(pData), datalen, flags);
    int len = -1;
    do {
        len = waitIpPacket(globalBuffer, 5000);
    } while (len == -1);
    try {
        tcb.receive(reinterpret_cast<TCPHeader*>(globalBuffer), len);
    } catch (StuTcpTestException& e) {
        if (e.type) {
            tcp_DiscardPkt(globalBuffer, e.type);
        }
        return -1;
    }
    return 0;
}

int stud_tcp_recv(int sockfd, unsigned char* pData, unsigned short datalen, int flags) {
    static_cast<void>(datalen);
    static_cast<void>(flags);
    TCB& tcb = *sockets[sockfd];
    int len = -1;
    do {
        len = waitIpPacket(globalBuffer, 5000);
    } while (len == -1);
    try {
        tcb.receive(reinterpret_cast<TCPHeader*>(globalBuffer), len);
        std::memcpy(pData, globalBuffer + sizeof(TCPHeader), len - sizeof(TCPHeader));
    } catch (StuTcpTestException& e) {
        if (e.type) {
            tcp_DiscardPkt(globalBuffer, e.type);
        }
        return -1;
    }
    return 0;
}

int stud_tcp_close(int sockfd) {
    //! Why? 我觉得应该是 FIN 而不是 FIN+ACK
    stud_tcp_send(sockfd, NULL, 0, PACKET_TYPE_FIN_ACK); 
    TCB& tcb = *sockets[sockfd];
    int len = -1;
    do {
        len = waitIpPacket(globalBuffer, 5000);
    } while (len == -1);
    try {
        tcb.receive(reinterpret_cast<TCPHeader*>(globalBuffer), len);
    } catch (StuTcpTestException& e) {
        if (e.type) {
            tcp_DiscardPkt(globalBuffer, e.type);
        }
        return -1;
    }
    delete sockets[sockfd];
    sockets[sockfd] = NULL;
    return 0;
}
