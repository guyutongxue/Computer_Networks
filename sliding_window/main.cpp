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

typedef uint8_t UINT8;
typedef uint32_t UINT32;

/// 某个帧超时
#define MSG_TYPE_TIMEOUT ((UINT8)0x01)

/// 系统要发送一个帧
#define MSG_TYPE_SEND ((UINT8)0x02)

/// 系统接收到一个帧的 ACK
#define MSG_TYPE_RECEIVE ((UINT8)0x03)

/**
 * @brief 发送帧函数
 *
 * @param pData 指向要发送的帧的内容的指针
 * @param len 要发送的帧的长度
 */
void SendFRAMEPacket(unsigned char* pData, unsigned int len);

#else
#include "sysinclude.h"
#endif

// -- required --

/// 停等协议测试函数
int stud_slide_window_stop_and_wait(char* pBuffer, int bufferSize, UINT8 messageType);

/// 回退 N 帧协议测试函数
int stud_slide_window_back_n_frame(char* pBuffer, int bufferSize, UINT8 messageType);

/// 选择性重传协议测试函数
int stud_slide_window_choice_frame_resend(char* pBuffer, int bufferSize, UINT8 messageType);

enum FrameKind { DATA, ACK, NAK };
struct FrameHead {
    FrameKind kind;           // 帧类型
    unsigned seq;             // 序列号
    unsigned ack;             // 确认号
    unsigned char data[100];  // 数据
};
struct Frame {
    FrameHead head;  // 帧头
    unsigned size;   // 数据的大小
};

// -- implementation --

#include <iostream>
#include <queue>

struct Buffer {
    Frame data;
    int size;
};

std::ostream& operator<<(std::ostream& os, const FrameKind& kind) {
    switch (ntohl(kind)) {
        case DATA: os << "DATA"; break;
        case ACK: os << "ACK"; break;
        case NAK: os << "NAK"; break;
        default: os << "unknown"; break;
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const Frame& frame) {
    int seq = ntohl(frame.head.seq);
    int ack = ntohl(frame.head.ack);
    os << "{ kind: " << frame.head.kind << ", seq: " << seq << ", ack: " << ack
       << ", size: " << frame.size << " }";
    return os;
}

const char* messageTypeToStr(UINT8 messageType) {
    switch (messageType) {
        case MSG_TYPE_TIMEOUT: return "MSG_TYPE_TIMEOUT";
        case MSG_TYPE_SEND: return "MSG_TYPE_SEND";
        case MSG_TYPE_RECEIVE: return "MSG_TYPE_RECEIVE";
        default: return "unknown";
    }
}

#define WINDOW_SIZE_STOP_WAIT 1
#define WINDOW_SIZE_BACK_N_FRAME 4

template <bool ResendAll>
struct Resender;

template <>
struct Resender<true> {
    template <std::size_t WindowSize>
    void operator()(Buffer (&window)[WindowSize], std::size_t seq, std::size_t begin,
                    std::size_t end) {
        seq = begin;
        while (seq < end) {
            Buffer& buffer = window[seq % WindowSize];
            std::cout << "Action: resend (" << seq + 1 << ")" << std::endl;
            SendFRAMEPacket(reinterpret_cast<unsigned char*>(&buffer.data), buffer.size);
            seq++;
        }
    }
};

template <>
struct Resender<false> {
    template <std::size_t WindowSize>
    void operator()(Buffer (&window)[WindowSize], std::size_t seq, std::size_t begin,
                    std::size_t end) {
        Buffer& buffer = window[seq - 1 % WindowSize];
        std::cout << "Action: resend (" << seq << ")" << std::endl;
        SendFRAMEPacket(reinterpret_cast<unsigned char*>(&buffer.data), buffer.size);
        seq++;
        static_cast<void>(begin), static_cast<void>(end);
    }
};

template <std::size_t WindowSize, bool ResendAll>
static int stud_slide_window(char* pBuffer, int bufferSize, UINT8 messageType) {
    static Buffer window[WindowSize];
    static std::size_t lower = 0, upper = 0;
    static std::queue<Buffer> waiting;
    static Resender<ResendAll> resender;

    Frame currentFrame = *reinterpret_cast<Frame*>(pBuffer);
    const std::size_t currentAck = ntohl(currentFrame.head.ack);
    FrameKind currentKind = static_cast<FrameKind>(ntohl(currentFrame.head.kind));
    std::cout << messageTypeToStr(messageType) << ' ' << currentFrame << std::endl;
    std::cout << "window: [" << lower << ", " << upper << ']' << std::endl;
    switch (messageType) {
        case MSG_TYPE_SEND: {
            Buffer buffer = {currentFrame, bufferSize};
            if (upper - lower < WindowSize) {
                // 窗口可变宽，直接发送
                window[upper % WindowSize] = buffer;
                upper++;
                std::cout << "Action: send" << std::endl;
                SendFRAMEPacket(reinterpret_cast<unsigned char*>(&currentFrame), bufferSize);
            } else {
                // 窗口已满，等待
                std::cout << "Action: wait" << std::endl;
                waiting.push(buffer);
            }
            return 0;
        }
        case MSG_TYPE_RECEIVE: {
            // ACK 帧不在窗口内，丢弃
            if (currentAck <= lower || currentAck > upper) {
                std::cout << "Action: dismiss" << std::endl;
                return 1;
            }
            if (currentKind == NAK) {
                // 重发
                std::size_t seq = currentAck;
                resender(window, seq, lower, upper);
            } else {
                // 确认
                while (lower + 1 <= currentAck) {
                    lower++;
                    if (waiting.size() > 0) {
                        Buffer buffer = waiting.front();
                        waiting.pop();
                        window[upper % WindowSize] = buffer;
                        std::cout << "Action: ack " << lower << ", then send " << upper
                                  << std::endl;
                        upper++;
                        SendFRAMEPacket(reinterpret_cast<unsigned char*>(&buffer.data),
                                        buffer.size);
                    } else {
                        std::cout << "Action: ack " << lower << std::endl;
                    }
                }
            }
            return 0;
        }
        case MSG_TYPE_TIMEOUT: {
            std::size_t seq = *reinterpret_cast<UINT32*>(&currentFrame);
            std::cout << "Timeout seq: " << seq << std::endl;
            resender(window, seq, lower, upper);
            return 0;
        }
        default: return -1;
    }
}

int stud_slide_window_stop_and_wait(char* pBuffer, int bufferSize, UINT8 messageType) {
    return stud_slide_window<WINDOW_SIZE_STOP_WAIT, true>(pBuffer, bufferSize, messageType);
}

int stud_slide_window_back_n_frame(char* pBuffer, int bufferSize, UINT8 messageType) {
    return stud_slide_window<WINDOW_SIZE_BACK_N_FRAME, true>(pBuffer, bufferSize, messageType);
}

int stud_slide_window_choice_frame_resend(char* pBuffer, int bufferSize, UINT8 messageType) {
    return stud_slide_window<WINDOW_SIZE_BACK_N_FRAME, false>(pBuffer, bufferSize, messageType);
}
