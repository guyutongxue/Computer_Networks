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

struct stud_route_msg {
    unsigned int dest;
    unsigned int masklen;
    unsigned int nexthop;
};

/// TTL 错误
#define STUD_FORWARD_TEST_TTLERROR (0x01)

/// 找不到路由
#define STUD_FORWARD_TEST_NOROUTE (0x02)

#else
#include "sysinclude.h"
#endif

/**
 * @brief 将 IP 分组上交本机上层协议的函数
 * 本函数是 IPv4 协议接收流程的上层接口函数，在对 IPv4
 * 的分组完成解析处理之后，如果分组的目的地址是本机的地址，
 * 则调用本函数将正确分组交上层相应协议模块进一步处理。
 * @param pBuffer 指向分组的 IP 头
 * @param length 表示分组的长度
 */
void fwd_LocalRcv(char* pBuffer, int length);

/**
 * @brief 将封装完成的 IP 分组通过链路层发送出去的函数
 * 本函数是发送流程的下层接口函数，在 IPv4 协议模块完成发送封装工作后
 * 调用该接口函数进行后续发送处理。其中，后续的发送处理过程包括分片处理、
 * IPv4 地址到 MAC 地址的映射（ARP 协议）、封装成 MAC 帧等工作，
 * 这部分内容不需要学生完成，由实验系统提供支持。
 * @param pBuffer 指向所要发送的 IPv4 分组头部
 * @param length 分组长度（包括分组头部）
 * @param nexthop 转发时下一跳的地址
 */
void fwd_SendtoLower(char* pBuffer, int length, unsigned int nexthop);

/**
 * @brief 丢弃 IP 分组的函数
 * 本函数是丢弃分组的函数，
 * 在接收流程中检查到错误时调用此函数将分组丢弃。
 * @param pBuffer 指向被丢弃的 IPV4 分组头部
 * @param type 表示错误类型，包括 TTL 错误和找不到路由两种错误
 */
void fwd_DiscardPkt(char* pBuffer, int type);

/**
 * @brief 获取本机的 IPv4 地址
 * 本函数用于获取本机的IPv4地址，学生调用该函数即可返回本机的 IPv4
 * 地址，可以用来判断 IPV4 分组是否为本机接收。
 * @return 本机 IPv4 地址
 */
unsigned int getIpv4Address();

#include <cstring>
#include <set>

// -- required --

/**
 * @brief 系统处理收到的 IP 分组的函数
 * 本函数是 IPv4 协议接收流程的下层接口函数，实验系统从网络中接收
 * 到分组后会调用本函数。调用该函数之前已完成 IP 报文的合法性检查，
 * 因此学生在本函数中应该实现如下功能：
 * a. 判定是否为本机接收的分组，如果是则调用 @c fwd_LocalRcv() ；
 * b. 按照最长匹配查找路由表获取下一跳，查找失败则调用 @c fwd_DiscardPkt() ；
 * c. 调用 @c fwd_SendtoLower() 完成报文发送；
 * d. 转发过程中注意 TTL 的处理及校验和的变化。
 * @param pBuffer 指向接收到的 IPv4 分组头部
 * @param length IPv4 分组的长度
 * @return @c 0 为成功， @c 1 为失败
 */
int stud_fwd_deal(char* pBuffer, int length);

/**
 * @brief 向路由表添加路由的函数
 * 本函数为路由表配置接口，系统在配置路由表时需要调用此接口。
 * 此函数功能为向路由表中增加一个新的表项，
 * 将参数所传递的路由信息添加到路由表中。
 * @param proute 指向需要添加路由信息的结构体头部
 */
void stud_route_add(stud_route_msg* proute);

/**
 * @brief 路由表初始化函数
 * 本函数将在系统启动的时候被调用，
 * 学生可将初始化路由表的代码写在这里。
 */
void stud_Route_Init();

// -- implementation --

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

struct RouteTableItem {
    uint32_t dest;
    uint32_t mask;
    uint32_t nextHop;

    bool operator<(const RouteTableItem& rhs) const {
        return mask > rhs.mask;
    }
};

std::set<RouteTableItem> routeTable;

int stud_fwd_deal(char* pBuffer, int length) {
    IPv4Header* header = reinterpret_cast<IPv4Header*>(pBuffer);
    if (header->ttl == 0) {
        fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_TTLERROR);
        return 1;
    }
    const uint32_t dstAddr = ntohl(header->dstAddr);
    if (dstAddr == getIpv4Address()) {
        fwd_LocalRcv(pBuffer, length);
        return 0;
    }
    typedef std::set<RouteTableItem>::iterator RouteIter;
    for (RouteIter i = routeTable.begin(); i != routeTable.end(); ++i) {
        if ((i->dest & i->mask) == (dstAddr & i->mask)) {
            char* newBuffer = new char[length];
            memcpy(newBuffer, pBuffer, length);
            IPv4Header* newHeader = reinterpret_cast<IPv4Header*>(newBuffer);
            newHeader->ttl -= 1;
            newHeader->generateChecksum();
            fwd_SendtoLower(newBuffer, length, i->nextHop);
            delete[] newBuffer;
            return 0;
        }
    }
    fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_NOROUTE);
    return 1;
}

void stud_route_add(stud_route_msg* proute) {
    RouteTableItem item = {};
    int maskLen = ntohl(proute->masklen);
    item.mask = ~((1 << (32 - maskLen)) - 1);
    item.dest = ntohl(proute->dest);
    item.nextHop = ntohl(proute->nexthop);
    routeTable.insert(item);
}

void stud_Route_Init() {
    routeTable.clear();
}