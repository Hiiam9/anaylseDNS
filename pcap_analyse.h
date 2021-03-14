#ifndef PCAP_ANALYSE_H
#define PCAP_ANALYSE_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>




#define BUFSIZE 10240;
#define STRLEN 1024;

#define BSWAP_64(x) \
        (int)((((int)(x) & 0xff00000000000000) >> 56 |) \
             (((int)(x) & 0x00ff000000000000) >> 48 |) \
             (((int)(x) & 0x0000ff0000000000) >> 32 |) \
             (((int)(x) & 0x000000ff00000000) >> 8  |) \
             (((int)(x) & 0x00000000ff000000) << 8  |) \
             (((int)(x) & 0x0000000000ff0000) << 32 |) \
             (((int)(x) & 0x000000000000ff00) << 48 |) \
             (((int)(x) & 0x00000000000000ff) << 56 |) \
        )   
#define BSWAP_32(x) \
        (int)((((int)(x) & 0xff000000) >> 24) | \
                              (((int)(x) & 0x00ff0000) >> 8) | \
                              (((int)(x) & 0x0000ff00) << 8) | \
                              (((int)(x) & 0x000000ff) << 24) \
             )


#define BSWAP_16(x) \
        (int)((((int)(x) & 0x00ff) << 8) | \
                (((int)(x) & 0xff00) >> 8) \
             )


/*pcap 文件头结构（24B）*/
typedef struct pcap_header
{
    int magic;  //4B 标识位
    unsigned short major; //2B 主要版本号
    unsigned short minor; //2B 副版本号
    unsigned int thiszone;        //4B 当地的标准时间；全零
    unsigned int sigfigs;//4B 时间戳精度
    unsigned int snaplen;  //4B 数据包最大长度 
    unsigned int linktype; //4B 链路层类型

}pcap_header;

/*时间戳*/
struct time_stamp
{
    unsigned int t_secH;  //4B 时间戳高位秒计时
    unsigned int t_usecL; //4B 时间戳低位微秒计时
};


//packet header（16B）
struct packet_header
{
    struct time_stamp ts; //8B 时间戳
    unsigned caplen;      //4B 当前长度
    unsigned len;         //4B 数据包长度
};

//ETH 帧头 14B
typedef struct eth_FrameHdr
{   
    unsigned char src_mac[6];  // 目的mac
    unsigned char dst_mac[6];  // 源mac
    unsigned short frame_type;  //frmae类型
    
}eth_FrameHdr;

//IPv4 20B
typedef struct IPv4_Hdr
{
    unsigned char ver_HdrLen;     //版本和长度
    unsigned char dsf;            //服务类型               
    unsigned short totalLen;      //总长度                 
    unsigned short ID;            //标识                
    unsigned short flag_Segment;  //标志+片偏移            
    unsigned char ttl;            //生存周期               
    unsigned char protocol;       //协议类型
    unsigned short checkSum;      //首部校验和             
    unsigned char srcIP[4];          //源IP地址               
    unsigned char dstIP[4];          //目的IP地址          
}IPv4_Hdr;


//udp数据报头8B
typedef struct udp_Hdr
{
    unsigned short srcPort;  //源端口
    unsigned short dstPort;  //目的端口
    unsigned short udpLen;   //长度
    unsigned short udpCheck; //udp校验 
}udp_Hdr;

//dns 的数据大小不定，所以只取前面的信息封装结构
typedef struct DNS_t{

    unsigned short TransID; //事务ID
    unsigned short Flags;   //标志
    unsigned short Ques;    //问题数
    unsigned short AnsRRs;  //回答资源数
    unsigned short AuthRRs; //服务器计数
    unsigned short AddRRs;  //附加资源数
}DNS_t;



//用到的函数声明
int getFileSize(FILE *fp);
#endif
