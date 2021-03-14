#include "pcap_analyse.h"




int main(int argc,char **argv){

    //建立各帧头结构
    
    struct pcap_header *pcap_file_Hdr;
    struct packet_header *packet_Hdr;
    struct eth_FrameHdr *eth_Hdr; //以太网帧头
    struct IPv4_Hdr *ip_Hdr;
    struct udp_Hdr *udpHdr;
    struct DNS_t *dns;
    
       
    //定义变量
    int offest = 0; //偏移量
    time_t time_temp;
    int i = 0; //数据包计数
    char rtime[1024]; //时间戳字符数组
    int curLocal; //记录当前文件流指针位置    
    int src_Port;
    int dst_Port;
    int j=0;      //记录dns数
    //1.打开文件
    FILE *fp;

    if(argc == 3){
        fp = fopen(argv[2],"rb");
    }
    else
        fp = fopen(argv[1],"rb");
    if(NULL == fp){  
        printf("pcap file open failed.\n");
        goto ERR;
    }
    

    //读取pcap文件头
    pcap_file_Hdr = (struct pcap_header*)malloc(sizeof(pcap_header));
    offest = 0;
    fseek(fp,offest,SEEK_SET);
    fread(pcap_file_Hdr,sizeof(pcap_header),1,fp);
   
    //打印pcap文件头信息
    printf("文件头信息：\n");
    printf("文件开始标识 magic : %02x.\n",pcap_file_Hdr->magic);
    printf("主版本号 major : %02x.\n",pcap_file_Hdr->major);
    printf("次版本号 minor : %02x.\n",pcap_file_Hdr->minor);
    printf("当地标准时间 thiszone : %02x.\n",pcap_file_Hdr->thiszone);   
    printf("时间戳精度 sigfigs : %02x.\n",pcap_file_Hdr->sigfigs);
    printf("最大数据包长度 snaplen : %02x.\n",pcap_file_Hdr->snaplen);
    printf("链路类型 linktype : %02x.\n",pcap_file_Hdr->linktype);
    printf("\n");
    //打印packet header信息
    
    //数据包内存空间开辟
    packet_Hdr = (struct packet_header*)malloc(sizeof(struct packet_header));
    eth_Hdr = (struct eth_FrameHdr*)malloc(sizeof(struct eth_FrameHdr));
    ip_Hdr = (struct IPv4_Hdr*)malloc(sizeof(struct IPv4_Hdr));
    udpHdr = (struct udp_Hdr*)malloc(sizeof(struct udp_Hdr));
    dns = (struct DNS_t*)malloc(sizeof(struct DNS_t));

    offest = 24;
    
    while((fseek(fp,offest,SEEK_SET)) == 0){
        
      if(strcmp(argv[1],"-a")==0 && argc == 3){     
        if((fread(packet_Hdr,sizeof(struct packet_header),1,fp)) !=1){
            printf("Read packet_header Fail.\n");
            goto ERR;
        }
        
        i++;
        //包头信息
        printf("***数据包%d信息***\n",i);
        offest +=16 + packet_Hdr->caplen;
        
        //printf("文件大小为：%d.\n",getFileSize(fp));
        time_temp = packet_Hdr->ts.t_secH;
        //显示时间戳
        strftime(rtime,sizeof(rtime),"Date:%Y-%m-%d    Time:%I:%M:%S\n", localtime(&(time_temp)));
        
        printf("时间：%s",rtime);
        printf("当前长度：%d\n",packet_Hdr->caplen);
        printf("数据包长度：%d\n",packet_Hdr->len);

        curLocal = offest - packet_Hdr->caplen;
        fseek(fp,curLocal,SEEK_SET);
        
        //printf("curlocal:%d\n",ftell(fp));
        
        //读取eth信息
        if((fread(eth_Hdr,14,1,fp)) != 1){
            printf("Read eth frame fail.\n");
            goto ERR;
        
        }
        //打印mac信息        
        printf("源地址 Source：%02x:%02x:%02x:%02x:%02x:%02x.\n",eth_Hdr->dst_mac[0],eth_Hdr->dst_mac[1],eth_Hdr->dst_mac[2],eth_Hdr->dst_mac[3],eth_Hdr->dst_mac[4],eth_Hdr->dst_mac[5]);

        printf("目的地址 Destination：%02x:%02x:%02x:%02x:%02x:%02x.\n",eth_Hdr->src_mac[0],eth_Hdr->src_mac[1],eth_Hdr->src_mac[2],eth_Hdr->src_mac[3],eth_Hdr->src_mac[4],eth_Hdr->src_mac[5]);
        
        printf("帧类型 :0x%02x.\n",eth_Hdr->frame_type);
    
        //读取IPV4信息
        if((fread(ip_Hdr,20,1,fp)) != 1) {
            printf("Read IPV4 header fail.\n");
            goto ERR;        
        }
        //打印ipv4信息 
        printf("IPv4 Version : %x\n",ip_Hdr->ver_HdrLen&0xf0>>3);
        printf("服务类型 :%02x\n",ip_Hdr->dsf);
        printf("总长度 : %02x\n",ip_Hdr->totalLen);
        printf("ID :%02x\n",BSWAP_16(ip_Hdr->ID));
        printf("标志与偏移：%02x\n",ip_Hdr->flag_Segment);
        printf("生存周期：%d\n",ip_Hdr->ttl);
        printf("协议类型：%d\n",ip_Hdr->protocol);
        printf("检验和：%02x\n",BSWAP_16(ip_Hdr->checkSum));
        printf("源ip：%d.%d.%d.%d\n",ip_Hdr->srcIP[0],ip_Hdr->srcIP[1],ip_Hdr->srcIP[2],ip_Hdr->srcIP[3]);
        printf("目的IP：%d.%d.%d.%d\n",ip_Hdr->dstIP[0],ip_Hdr->dstIP[1],ip_Hdr->dstIP[2],ip_Hdr->dstIP[3]);
    
    
        //读取udp信息
        if((fread(udpHdr,8,1,fp)) !=1){
            printf("Read UDP header Fail\n");
            goto ERR;
        
        }

        //打印udp信息
        src_Port = BSWAP_16(udpHdr->srcPort);
        printf("源端口：%d\n",src_Port);
        
        dst_Port = BSWAP_16(udpHdr->dstPort);
        printf("目的端口：%d\n",dst_Port);
            
        printf("udp长度 : %d\n",BSWAP_16(udpHdr->udpLen));
        printf("udp Checksum : %02x\n",BSWAP_16(udpHdr->udpCheck));
    
        //================判断DNS============================//
        //特征：srcPort 或 dstPort 为53端口                  //
        //===================================================//
    

        if(src_Port==53 || dst_Port==53){
            printf("this is DNS\n");
        
        }
        else{
            continue;
        }
        if((fread(dns,12,1,fp)) != 1){
            printf("Read Dns Fail\n");
            goto ERR;
        }
        
        printf("Questions :%d\n",BSWAP_16(dns->Ques));
    
        printf("Answer RRs :%d\n",BSWAP_16(dns->AnsRRs));
        
        printf("Authority RRs: %d\n",BSWAP_16(dns->AuthRRs));

        printf("Additional RRs : %d\n",BSWAP_16(dns->AddRRs));
    
        j++;
        if(offest == getFileSize(fp)){
            printf("共%d条数据.其中 DNS %d 条\n",i,j);
            printf("文件读取完毕，已退出.\n");
            break;
        }     
        printf("\n");
      }
      else
      {
        
            
        if((fread(packet_Hdr,sizeof(struct packet_header),1,fp)) !=1){   
            printf("Read packet_header Fail.\n");
            goto ERR;
        }
        i++;
        offest += 16+packet_Hdr->caplen;
        curLocal = 34;
        fseek(fp,curLocal,SEEK_CUR);
        //================判断DNS============================//
        //特征：srcPort 或 dstPort 为53端口                  //
        //===================================================//
    
        if((fread(udpHdr,8,1,fp)) !=1){
            printf("Read UDP header Fail\n");
            goto ERR;
        
        }

        src_Port = BSWAP_16(udpHdr->srcPort);
        dst_Port = BSWAP_16(udpHdr->dstPort);
        
        if(src_Port==53 || dst_Port==53){
            printf("this is DNS\n");
        
        }
        else{
            continue;
        }
        if((fread(dns,12,1,fp)) != 1){
            printf("Read Dns Fail\n");
            goto ERR;
        }
        
        printf("Questions :%d\n",BSWAP_16(dns->Ques));
    
        printf("Answer RRs :%d\n",BSWAP_16(dns->AnsRRs));
        
        printf("Authority RRs: %d\n",BSWAP_16(dns->AuthRRs));

        printf("Additional RRs : %d\n",BSWAP_16(dns->AddRRs));
        j++;
        
        if(offest == getFileSize(fp)){
            printf("共%d条数据.其中 DNS %d 条\n",i,j);
            printf("文件读取完毕，已退出.\n");
            break;
        }     
        printf("\n");
      
      }
    }
    


ERR:
    fclose(fp);

    return 0;
}

//函数名：getFileSize(FILE *fp)
//功能：获取文件大小
int getFileSize(FILE *fp){
    fseek(fp,0,SEEK_END);
    return ftell(fp);
}

