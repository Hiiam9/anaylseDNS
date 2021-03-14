<h1 align<h1 align="center">Welcome to analyse 👋</h1>

<p>
  <img src="https://img.shields.io/badge/analyse-v1.0-blue"/>
  </p>
    
⬇️[下载地址](https://github.com/Hiiam9/anaylseDNS/releases/tag/1.0)
#### 功能： 解析pcap文件<br>
    
-开发环境：ubuntu 14.04

-编程语言：c

-编译器：gcc-4.8.4


##### 数据结构
![](src/0x00.png)
![](src/0x01.png)

#### 使用示例
-准备好pcap文件
-编译程序：make 
-参数：
    默认打印DNS主要参数
    -a打印全部信息

```
#analyse -a xxx.pcap
```

![](src/test.png)


```
#analyse xxx.pcap
```
![](src/test2.png)

#### 跨平台
    未使用任何平台相关代码，具有良好的跨平台功能，Linux&Windows皆可以编译运行
