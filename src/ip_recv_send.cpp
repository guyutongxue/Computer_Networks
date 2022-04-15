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

// -- predefined --

typedef unsigned char byte;

/// IP 校验和出错
#define STUD_IP_TEST_CHECKSUM_ERROR (0x01)

/// TTL 值出错
#define STUD_IP_TEST_TTL_ERROR (0x02)

/// IP 版本号错
#define STUD_IP_TEST_VERSION_ERROR (0x03)

/// 头部长度错
#define STUD_IP_TEST_HEADLEN_ERROR (0x04)

/// 目的地址错
#define STUD_IP_TEST_DESTINATION_ERROR (0x05)

/**
 * @brief 丢弃分组
 *
 * @param pBuffer 指向被丢弃分组的指针
 * @param type 分组被丢弃的原因
 */
void ip_DiscardPkt(char* pBuffer, int type);

/**
 * @brief 发送分组
 *
 * @param pBuffer 指向待发送的 IPv4 分组头部的指针
 * @param length 待发送的 IPv4 分组长度
 */
void ip_SendtoLower(char* pBuffer, int length);

/**
 * @brief 上层接收
 *
 * @param pBuffer 指向要上交的上层协议报文头部的指针
 * @param length 上交报文长度
 */
void ip_SendtoUp(char* pBuffer, int length);

/**
 * @brief 获取本机 IPv4 地址
 *
 * @return 本机 IPv4 地址
 */
unsigned int getIpv4Address();

#else
#include "sysinclude.h"
#endif

#include <cstring>
#include <new>

// -- required --

/**
 * @brief 接收接口
 *
 * @param pBuffer 指向接收缓冲区的指针，指向 IPv4 分组头部
 * @param length IPv4 分组长度
 * @return @c 0 ：成功接收 IP 分组并交给上层处理； @c 1 ：IP 分组接收失败
 */
int stud_ip_recv(char* pBuffer, unsigned short length);

/**
 * @brief 发送接口
 *
 * @param pBuffer 指向发送缓冲区的指针，指向 IPv4 上层协议数据头部
 * @param len IPv4 上层协议数据长度
 * @param srcAddr 源 IPv4 地址
 * @param dstAddr 目的 IPv4 地址
 * @param protocol IPv4 上层协议号
 * @param ttl 生存时间（Time To Live）
 * @return @c 0 ：成功发送 IP 分组； @c 1 ：发送 IP 分组失败
 */
int stud_ip_Upsend(char* pBuffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr,
                   byte protocol, byte ttl);

// -- implementation --

enum { STUD_OK = 0, STUD_ERR = 1 };

#pragma pack(1)
struct IPv4Header {
    uint8_t ihl : 4;
    uint8_t version : 4;
    uint8_t ecn : 2;
    uint8_t dscp : 6;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagsAndFragmentOffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t headerChecksum;
    uint32_t srcAddr;
    uint32_t dstAddr;

    uint16_t verifyChecksum() const {
        uint32_t sum = 0;
        const uint16_t* p = reinterpret_cast<const uint16_t*>(this);
        for (int i = 0; i < 10; i++) {
            sum += ntohs(p[i]);
        }
        return sum + (sum >> 16);
    }
    
    void generateChecksum() {
        headerChecksum = 0;
        int checksum = verifyChecksum();
        headerChecksum = ~htons(checksum);
    }
};
#pragma pack()

int stud_ip_recv(char* pBuffer, unsigned short length) {
    const IPv4Header* header = reinterpret_cast<IPv4Header*>(pBuffer);
    if (header->verifyChecksum() != 0xffff) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_CHECKSUM_ERROR);
        return STUD_ERR;
    }
    if (header->version != 4) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_VERSION_ERROR);
        return STUD_ERR;
    }
    if (header->ihl < 5) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_HEADLEN_ERROR);
        return STUD_ERR;
    }
    if (header->ttl == 0) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_TTL_ERROR);
        return STUD_ERR;
    }
    const uint32_t dstAddr = ntohl(header->dstAddr);
    if (dstAddr == getIpv4Address() || dstAddr == 0xffffffff) {
        const int dataLength = length - header->ihl * 4;
        ip_SendtoUp(pBuffer, dataLength);
        return STUD_OK;
    } else {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_DESTINATION_ERROR);
        return STUD_ERR;
    }
}

int stud_ip_Upsend(char* pBuffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr,
                   byte protocol, byte ttl) {
    const int dataLength = len + 20;

    char* resultBuffer = new char[dataLength]();
    IPv4Header* header = new (resultBuffer) IPv4Header();

    header->version = 4;
    header->ihl = 5;
    header->totalLength = ntohs(dataLength);
    header->ttl = ttl;
    header->protocol = protocol;
    header->srcAddr = htonl(srcAddr);
    header->dstAddr = htonl(dstAddr);
    header->generateChecksum();

    std::memcpy(resultBuffer + 20, pBuffer, len);
    ip_SendtoLower(resultBuffer, dataLength);

    header->~IPv4Header();
    delete[] resultBuffer;

    return STUD_OK;
}
