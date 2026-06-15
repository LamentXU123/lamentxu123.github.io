---
title: "vsCTF 2024 re awa-jelly wp"
date: 2024-06-16 17:43
updated: 2024-06-16 17:43
categories: "CTF"
tags:
  - "CTF"
  - "Writeup"
  - "Reverse"
description: "vsCTF算我为数不多能打的国外比赛了，来记一道很有意思的reverse题目 JellyCTF has some amazing challenges on Jelly Hoshiumi (星海ジェリー), one of the few VTubers who loves CTF. Inspired"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18250981"
---
vsCTF算我为数不多能打的国外比赛了，来记一道很有意思的reverse题目

JellyCTF has some amazing challenges on Jelly Hoshiumi (星海ジェリー), one of the few VTubers who loves CTF. Inspired by a challenge, I made one based on AWA5.0. Can you find the redacted input that matches the screenshot?

![](/images/migrated/18250981/01.png)

[awa5.0在线编译器](https://temptempai.github.io/AWA5.0/)

# 预期解

去看了一下这个什么awa语言，逆天的很，我本来以为只是一种特殊的编码方式，结果好嘛

看了一下官方的文档和视频，破防了

[awa入门视频](https://www.youtube.com/watch?v=DY70AcaXq40&t=891s)

逆天得很，也就是说我们要对这段又臭又长的awa代码做如下事情

1.删掉开头的awa  
2.转化awa为二进制， awa代表0，wa代表1

![](/images/migrated/18250981/02.png)

3.二进制转十进制  
4.根据这个又臭又长的表格列出命令

![](/images/migrated/18250981/03.png)

5.根据awascii表转化对应字符串（对没错他自己定义了一种编码方式，取代ascii指日可待（bushi））

![](/images/migrated/18250981/04.png)

6.详细阅读官方文档，了解每个命令的含义  
7.逆向出input

我勒个豆啊这我做nm，先把官方的硬核正解写了吧，再写我怎么做这题的

官方的正解跟上面的步骤一样，直接肉眼瞪出命令

```
red
pop
sbm 2
sbm 3
sbm 4
sbm 1
sbm 6
sbm 5
sbm 3
sbm 10
sbm 20
sbm 22
sbm 25
sbm 3
sbm 0
sbm 0
sbm 2
sbm 3
sbm 4
sbm 1
sbm 6
sbm 5
sbm 3
sbm 10
sbm 20
sbm 22
sbm 25
sbm 3
sbm 0
sbm 0
sbm 0
sbm 16
sbm 26
sbm 31
prn
```

注意到是个位移编码，编写解码脚本

```
data = list("1o1i_awlaw_aowsay3wa0awa!iJlooHi")
subm = [2, 3, 4, 1, 6, 5, 3, 10, 20, 22, 25, 3, 0, 0, 2, 3, 4, 1, 6, 5, 3, 10, 20, 22, 25, 3, 0, 0, 0, 16, 26, 31]

for i in subm[::-1]:
    if i != 0:
        data = [data[i]] + data[0:i] + data[i+1:]
```

# 非预期解

好好好，接下来说我的做法（官方果然硬核）

注意到字符串1o1i\_awlaw\_aowsay3wa0aa!iJlooHi有感叹号，可能为位移编码（注意力惊人）

由于位移密码的特性，随便输入不重复的字符，获取每个位置对应的位移量

注意到，q,z,x,v再输入后会直接消失（我也不知道为啥别问我），换别的字符

![](/images/migrated/18250981/05.png)

输入：wertyuiopasdfghjlcbnm1234567890\_

输出：jslcbnmr12u3p4d5ye67i890\_gwtoafh

编写脚本：

```
string1 = 'wertyuiopasdfghjlcbnm1234567890_' # input
string2 = 'jslcbnmr12u3p4d5ye67i890_gwtoafh' # output
challenge = '1o1i_awlaw_aowsay3wa0awa!iJlooHi'
ans = []
anslist = []
for i in range(0, 32):
    ans.append('')
for stri in string2:
    anslist.append(string1.find(stri))
print(anslist)
print(len(anslist))
for i in range(0, len(challenge)):
    strj = challenge[i]
    pos = anslist[i]
    ans[pos] = strj
print('vsctf{'+''.join(ans)+'}')
```

偷鸡成功ヾ(≧▽≦\*)o

**vsctf{J3lly\_0oooosHii11i\_awawawawaawa!}**

比完赛看官方的硬核解法无语了（菜就多练）
