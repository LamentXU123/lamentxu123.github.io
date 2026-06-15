---
title: "Patriot CTF 2024 MISC 部分 wp"
date: 2024-09-24 22:23
updated: 2024-09-24 22:23
categories: "CTF"
tags:
  - "CTF"
  - "Web Security"
  - "Writeup"
  - "Reverse"
  - "Pwn"
description: "User Name Score LamentTyphon 922 Dragonkeep 846 Jerrythepro123 500 sanmu 1312 6s6 200 p3cd0wn 100 我们队web佬的wp：https://dragonkeeep.top/category/PatriotC"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18430083"
---
![](/images/migrated/18430083/01.jpg)

| User Name | Score |
| --- | --- |
| LamentTyphon | 922 |
| Dragonkeep | 846 |
| Jerrythepro123 | 500 |
| sanmu | 1312 |
| 6s6 | 200 |
| p3cd0wn | 100 |

我们队web佬的wp：[https://dragonkeeep.top/category/PatriotCTF-WEB-WP/](https://dragonkeeep.top/category/PatriotCTF-WEB-WP/)

有佬带，我做为web菜狗自然就灵活就业去解misc了（bushi）

**[Misc](https://www.cnblogs.com/LAMENTXU#1)**

-   [Emoji Stack](https://www.cnblogs.com/LAMENTXU#1.1)
-   [Making Baking Pancakes](https://www.cnblogs.com/LAMENTXU#1.2)
-   [RTL Warm up](https://www.cnblogs.com/LAMENTXU#1.3)
-   [Really Only Echo](https://www.cnblogs.com/LAMENTXU#1.4)
-   [RTL Easy](https://www.cnblogs.com/LAMENTXU#1.5)
-   [Emoji Stack V2](https://www.cnblogs.com/LAMENTXU#1.6)

**[写在后面](https://www.cnblogs.com/LAMENTXU#2)**

# Misc

## Emoji Stack

难度：Easy，对我的难度：Easy

```
Welcome to Emoji Stack, the brand new stack based emoji language! Instead of other stack based turing machines that use difficult to read and challenging characters like + - and [], Emoji Stack uses our proprietary patent pending emoji system.

The details of our implentation is below:

👉: Move the stack pointer one cell to the right
👈: Move the stack pointer one cell to the lef
👍: Increment the current cell by one, bounded by 255
👎: Decrement the current cell by one, bounded by 0
💬: Print the ASCII value of the current cell
🔁##: Repeat the previous instruction 0x## times
The Emoji Stack is 256 cells long, with each cell supporting a value between 0 - 255.
```

省流：brainfuck，直接Ctrl+F替换就行

唯一与brainfuck不同的是🔁替代了\[\]，需要在循环结束的时候多写一个\]很麻烦

手搓interpreter：

interpreter.py

```
str=''#换成题目附件
arr=[]

for i in range(len(str)):
    if str[i].isnumeric():
        continue
    elif str[i]=="🔁":
        arr.pop()
        arr.append(str[i-1]+str[i]+str[i+1]+str[i+2])
    else:
        arr.append(str[i])

cell=[0 for i in range(256)]
ptr=0

for i in range(len(arr)):
    if arr[i]=="👉":
        ptr+=1
    if arr[i]=="👈":
        ptr-=1
    if arr[i]=="👍":
        cell[ptr]+=1
    if len(arr[i])==4:
        for j in range(int(arr[i][2]+arr[i][3],16)+1):
            if arr[i][0] == "👉":
                ptr += 1
            if arr[i][0] == "👈":
                ptr -= 1
            if arr[i][0] == "👍":
                cell[ptr] += 1
    if arr[i]=="💬":
        print(chr(cell[ptr]),end="")
```

**CACI{TUR!NG\_!5\_R011!NG\_!N\_H!5\_GR@V3}**

## Making Baking Pancakes

难度：Easy，对我的难度：Beginner

好tm简单的题，不懂为什么这么少解

nc连接，发现challenge内容为：

```
Welcome to the pancake shop!
Pancakes have layers, we need you to get through them all to get our secret pancake mix formula.
This server will require you to complete 1000 challenge-responses.
A response can be created by doing the following:
1. Base64 decoding the challenge once (will output (encoded|n))
2. Decoding the challenge n more times.
3. Send (decoded|current challenge iteration)
Example response for challenge 485/1000: e9208047e544312e6eac685e4e1f7e20|485
Good luck!
```

评：弱智题目

拿到之后先进行一次base64解码，读出base64和解码次数。解码完成之后加上challenge的次数传上去

搓exp，出flag

```
from base64 import b64decode as de
import warnings
from tqdm import tqdm
warnings.defaultaction = "ignore"
from pwn import *
c = remote('chal.pctf.competitivecyber.club', 9001)
c.recvuntil('Good luck!')
for j in tqdm(range(1002)): #这里是因为有两个\n所以跑两个空循环，不是很会用pwntools别骂了
    k = j-2
    a = c.recvline().decode()
    if a == '\n':
        continue
    a = a.split(': ')[1]
    a1 = de(a).decode()
    basestring, times = a1.split('|')
    for i in range(int(times)):
        basestring = de(basestring)
    c.sendline(basestring+b'|'+str(k).encode())
c.interactive()
```

输出

```
(999/1000) >> Wow you did it, you've earned our formula!
DO NOT SHARE:
pctf{store_bought_pancake_batter_fa82370}
```

**pctf{store\_bought\_pancake\_batter\_fa82370}**

## RTL Warm up

难度：Begginer，对我的难度：Begginer

提取所有b开头的内容（即为二进制内容）

```
b01010000
b01000011
b01010100
b01000110
b01111011
b01010010
b01010100
b01001100
b01011111
b01101001
b00100100
b01011111
b01000100
b01000000
b01000100
b01011111
b00110000
b01000110
b01011111
b01001000
b01000000
b01110010
b01100100
b01110111
b01000000
b01110010
b00110011
b01111101
```

二进制序列是8位ASCII码，转化为char（ascii）

```
def binary_to_ascii(binary_string):
    # Remove the 'b' prefix and convert the binary string to decimal
    decimal_value = int(binary_string, 2)
    # Convert decimal to ASCII character
    return chr(decimal_value)

binary_values = [
    "01010000",  # P
    "01000011",  # C
    "01010100",  # T
    "01000110",  # F
    "01111011",  # {
    "01010010",  # R
    "01010100",  # T
    "01001100",  # L
    "01011111",  # _
    "01101001",  # i
    "00100100",  # $
    "01011111",  # _
    "01000100",  # D
    "01000000",  # @
    "01000100",  # D
    "01011111",  # _
    "00110000",  # 0
    "01000110",  # F
    "01011111",  # _
    "01001000",  # H
    "01000000",  # @
    "01110010",  # r
    "01100100",  # d
    "01110111",  # w
    "01000000",  # @
    "01110010",  # r
    "00110011",  # 3
    "01111101"   # }
]

ascii_characters = [binary_to_ascii(bv) for bv in binary_values]

print("".join(ascii_characters)) 
```

**PCTF{RTL\_i$\_D@D\_0F\_H@rdw@r3}**

## Really Only Echo

难度：easy，对我的难度：Beginner

CN CTFER最喜欢的Linux RCE

对老外来说这题可能有easy难度，但是对于天天搞这些的CN CTFER的话太基础了

```
#!/usr/bin/python3

import os,pwd,re
import socketserver, signal
import subprocess

listen = 3333

blacklist = os.popen("ls /bin").read().split("\n")
blacklist.remove("echo")
#print(blacklist)

def filter_check(command):
    user_input = command
    parsed = command.split()
    #Must begin with echo
    if not "echo" in parsed:
        return False
    else:
        if ">" in parsed:
            #print("HEY! No moving things around.")
            req.sendall(b"HEY! No moving things around.\n\n")
            return False
        else:
            parsed = command.replace("$", " ").replace("(", " ").replace(")", " ").replace("|"," ").replace("&", " ").replace(";"," ").replace("<"," ").replace(">"," ").replace("`"," ").split()
            #print(parsed)
            for i in range(len(parsed)):
                if parsed[i] in blacklist:
                    return False
            return True

def backend(req):
    req.sendall(b'This is shell made to use only the echo command.\n')
    while True:
        #print("\nThis is shell made to use only the echo command.")
        req.sendall(b'Please input command: ')
        user_input = req.recv(4096).strip(b'\n').decode()
        print(user_input)
        #Check input
        if user_input:
            if filter_check(user_input):
                output = os.popen(user_input).read()
                req.sendall((output + '\n').encode())
            else:
                #print("Those commands don't work.")
                req.sendall(b"HEY! I said only echo works.\n\n")
        else:
            #print("Why no command?")
            req.sendall(b"Where\'s the command.\n\n")

class incoming(socketserver.BaseRequestHandler):
    def handle(self):
        signal.alarm(1500)
        req = self.request
        backend(req)

class ReusableTCPServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

def main():
    uid = pwd.getpwnam('ctf')[2]
    os.setuid(uid)
    socketserver.TCPServer.allow_reuse_address = True
    server = ReusableTCPServer(("0.0.0.0", listen), incoming)
    server.serve_forever()

if __name__ == '__main__':
    main()
```

很吓人对吧？读完代码之后发现：

-   不能使用所有linux命令
-   必须以echo开头
-   过滤了$, (, ), \`无法内联执行
-   过滤了>, <无法重定向

怎么打都行，解法比我拿的分多（bushi）

一一对应一下过滤：

-   使用''绕过字符串匹配，如：ca''t
-   就以echo开头，但是用%0a可以在执行完echo之后执行别的命令
-   不需要内联执行
-   不需要重定向

首先，先看看flag在不在当前目录下

```
echo *
```

![](/images/migrated/18430083/02.png)

出题人还是太善良了，甚至不用回根目录（不过没有过滤/和.如果要回还是回得去的）

直接用linux下的换行符秒杀（%0a有与;相似的功能，可以另起一行执行命令）

![](/images/migrated/18430083/03.png)

**PCTF{echo\_is\_such\_a\_versatile\_command}**

## RTL Easy

难度：Easy，对我的难度：Easy

不是，这题318分啊？

top.v

```

module top (
    clock,
    din,
    dout
);

  // Module arguments
  input wire clock;
  input wire [7:0] din;
  output reg [7:0] dout;

  // Stub signals
  reg pulser$clock;
  reg pulser$enable;
  wire pulser$pulse;

  // Local signals
  reg [9:0] temp;

  // Sub module instances
  top$pulser pulser (
      .clock (pulser$clock),
      .enable(pulser$enable),
      .pulse (pulser$pulse)
  );

  // Update code
  always @(*) begin
    pulser$enable = 1'b1;
    pulser$clock = clock;
    temp = ((din) & 10'h3ff) << 32'h2 ^ 32'ha;
    dout = ((temp >> 32'h2) & 8'hff);
  end

endmodule  // top

module top$pulser (
    clock,
    enable,
    pulse
);

  // Module arguments
  input wire clock;
  input wire enable;
  output reg pulse;

  // Stub signals
  reg  strobe$enable;
  wire strobe$strobe;
  reg  strobe$clock;
  reg  shot$trigger;
  wire shot$active;
  reg  shot$clock;
  wire shot$fired;

  // Sub module instances
  top$pulser$strobe strobe (
      .enable(strobe$enable),
      .strobe(strobe$strobe),
      .clock (strobe$clock)
  );
  top$pulser$shot shot (
      .trigger(shot$trigger),
      .active (shot$active),
      .clock  (shot$clock),
      .fired  (shot$fired)
  );

  // Update code
  always @(*) begin
    strobe$clock = clock;
    shot$clock = clock;
    strobe$enable = enable;
    shot$trigger = strobe$strobe;
    pulse = shot$active;
  end

endmodule  // top$pulser

module top$pulser$shot (
    trigger,
    active,
    clock,
    fired
);

  // Module arguments
  input wire trigger;
  output reg active;
  input wire clock;
  output reg fired;

  // Constant declarations
  localparam duration = 32'h17d7840;

  // Stub signals
  reg [31:0] counter$d;
  wire [31:0] counter$q;
  reg counter$clock;
  reg state$d;
  wire state$q;
  reg state$clock;

  // Sub module instances
  top$pulser$shot$counter counter (
      .d(counter$d),
      .q(counter$q),
      .clock(counter$clock)
  );
  top$pulser$shot$state state (
      .d(state$d),
      .q(state$q),
      .clock(state$clock)
  );

  // Update code
  always @(*) begin
    counter$clock = clock;
    state$clock = clock;
    counter$d = counter$q;
    state$d = state$q;
    if (state$q) begin
      counter$d = counter$q + 32'h1;
    end
    fired = 1'b0;
    if (state$q && (counter$q == duration)) begin
      state$d = 1'b0;
      fired   = 1'b1;
    end
    active = state$q;
    if (trigger) begin
      state$d   = 1'b1;
      counter$d = 32'h0;
    end
  end

endmodule  // top$pulser$shot

module top$pulser$shot$counter (
    d,
    q,
    clock
);

  // Module arguments
  input wire [31:0] d;
  output reg [31:0] q;
  input wire clock;

  // Update code (custom)
  initial begin
    q = 32'h0;
  end

  always @(posedge clock) begin
    q <= d;
  end

endmodule  // top$pulser$shot$counter

module top$pulser$shot$state (
    d,
    q,
    clock
);

  // Module arguments
  input wire d;
  output reg q;
  input wire clock;

  // Update code (custom)
  initial begin
    q = 1'h0;
  end

  always @(posedge clock) begin
    q <= d;
  end

endmodule  // top$pulser$shot$state

module top$pulser$strobe (
    enable,
    strobe,
    clock
);

  // Module arguments
  input wire enable;
  output reg strobe;
  input wire clock;

  // Constant declarations
  localparam threshold = 32'h5f5e100;

  // Stub signals
  reg [31:0] counter$d;
  wire [31:0] counter$q;
  reg counter$clock;

  // Sub module instances
  top$pulser$strobe$counter counter (
      .d(counter$d),
      .q(counter$q),
      .clock(counter$clock)
  );

  // Update code
  always @(*) begin
    counter$clock = clock;
    counter$d = counter$q;
    if (enable) begin
      counter$d = counter$q + 32'h1;
    end
    strobe = enable & (counter$q == threshold);
    if (strobe) begin
      counter$d = 32'h1;
    end
  end

endmodule  // top$pulser$strobe

module top$pulser$strobe$counter (
    d,
    q,
    clock
);

  // Module arguments
  input wire [31:0] d;
  output reg [31:0] q;
  input wire clock;

  // Update code (custom)
  initial begin
    q = 32'h0;
  end

  always @(posedge clock) begin
    q <= d;
  end

endmodule  // top$pulser$strobe$counter
```

读.v文件，注意到：

```
temp = ((din) & 10'h3ff) << 32'h2 ^ 32'ha;
dout = ((temp >> 32'h2) & 8'hff);
```

看.svg，获取输出

```
0h52,0h41,0h56,0h44,0h79,0h4a,0h42,0h70,0h66,0h5d,0h47,0h6c,0h61,0h70,0h7b,0h72,0h76,0h6b,0h6d,0h6c,0h5d,0h6b,0h71,0h5d,0h31,0h63,0h71,0h7b
```

搓exp直接出

```
def calculate_din(dout_values):
    din_values = []
    
    for dout in dout_values:

        dout_int = int(dout, 16)

        temp = dout_int << 2
        
        din = (temp ^ 0xA) >> 2
        din_values.append(din)  # Store as integer for ASCII conversion

    return din_values

def din_to_ascii(din_values):
    ascii_chars = [chr(din) for din in din_values]
    return ascii_chars

dout_values = [
    '0x52', '0x41', '0x56', '0x44', '0x79', 
    '0x4A', '0x42', '0x70', '0x66', '0x5D', 
    '0x47', '0x6C', '0x61', '0x70', '0x7B', 
    '0x72', '0x76', '0x6B', '0x6D', '0x6C', 
    '0x5D', '0x6B', '0x71', '0x5D', '0x31', 
    '0x63', '0x71', '0x7B'
]

din_values = calculate_din(dout_values)

ascii_chars = din_to_ascii(din_values)

for dout, din, ascii_char in zip(dout_values, din_values, ascii_chars):
    print(f"dout: {dout}, din: {din}, ASCII: '{ascii_char}'")
```

**PCTF{H@rd\_Encryption\_is\_3asy}**

## Emoji Stack v2

难度：Medium，对我的难度：Hard

与v1一致不过多了几个东西

要注意的是，用的是raster scan顺序

![](/images/migrated/18430083/04.png)

ChatGPT改一下秒了(exp是discord上的。我的出了一点问题，开ticket主办方跟我说No Hints! You've got it，一整个无语住了。最后发现是没用raster scan顺序存XD)

```
from PIL import Image 
import cv2
import  numpy as np

class Interpreter:

    def __init__(self, rom):
        self.stack = cv2.imread("initial_state.png", 0)
        self.sp_x = 0 
        self.sp_y = 0
        self.last_jz = 0
        self.ip = 0
        self.prec = ""
        self.rom = rom

    def exec(self,a):
        if a == "👆":
            self.sp_y = (self.sp_y + 1) % 255
        elif a == "👇":
            self.sp_y = (self.sp_y - 1) % 255
        elif a == "👉":
            self.sp_x = (self.sp_x + 1) % 255
        elif a == "👈":
            self.sp_x = (self.sp_x - 1) % 255
        elif a == "👍":
            if self.stack[self.sp_y][self.sp_x] < 255:
                self.stack[self.sp_y, self.sp_x] =  self.stack[self.sp_y, self.sp_x] + 1
        elif a == "👎": 
            if self.stack[self.sp_y][self.sp_x] > 0:
                self.stack[self.sp_y, self.sp_x] =  self.stack[self.sp_y, self.sp_x] - 1
        elif a == '🫸':
            if self.stack[self.sp_y, self.sp_x] == 0:
                depth = 1
                while depth != 0:
                    self.ip += 1
                    if self.rom[self.ip] == '🫸':
                        depth += 1
                    elif self.rom[self.ip] == '🫷':
                        depth -= 1
        elif a == '🫷':
            if self.stack[self.sp_y, self.sp_x] != 0:
                depth = 1
                while depth != 0:
                    self.ip -= 1
                    if self.rom[self.ip] == '🫷':
                        depth += 1
                    elif self.rom[self.ip] == '🫸':
                        depth -= 1
        elif a == "💬":
            print(chr(self.stack[self.sp_y, self.sp_x]),end="")
        elif a == "🔁":
        base12_mapping = {'🕛': 0, '🕐': 1, '🕑': 2, '🕒': 3, '🕓': 4, '🕔': 5, '🕕': 6, '🕖': 7, '🕗': 8, '🕘': 9, '🕙': 'a', '🕚': 'b'}
        a = base12_mapping[self.rom[self.ip + 1]]
        b = base12_mapping[self.rom[self.ip + 2]]
        c = base12_mapping[self.rom[self.ip + 3]]
        times = int(str(a) + str(b) + str(c), 12)
        for _ in range(times):
        self.exec(self.prec)
        self.ip += 3
        else:
            print(">>>", ord(a), "<<<")

    def run(self):
        while self.ip < len(self.rom):
            self.exec(self.rom[self.ip])
            self.prec = self.rom[self.ip]
            self.ip += 1
        return -1
    

file = open("program.txt","r")
rom = file.read()
file.close()
interpreter = Interpreter(rom)

interpreter.run()

cv2.imwrite("flag.png",interpreter.stack)
```

出：

![](/images/migrated/18430083/05.webp)

好恐怖啊（bushi）

**PCTF{3MOJ!==G00D!}**

# 写在后面

这次虽然名次不是很理想，但依然是我印象里最好的一次CTF体验。主要是队友之间真正地开始有了合作，让我有了一种队伍的归属感。说句心里话，CTF作为小众爱好（大学学网安的不算），能找到如此志同道合的队友跟我一起做我喜欢做的事情，我是何其幸运啊。作为高中生，我只能CTF for fun，大部分国内的大赛我都不配参加。我能找到一群人陪我打国外的CTF，跟我交流技术，让我在孤独了几年的兴趣爱好上第一次有了同伴，即使菜我也很开心了（我菜，我队友全tql）。我发自内心地感谢我的队友们，谢谢你们给了我如此的幸福。
