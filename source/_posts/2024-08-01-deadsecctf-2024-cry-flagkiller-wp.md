---
title: "deadsecCTF 2024 cry FLAGKILLER wp"
date: 2024-08-01 16:16
updated: 2024-08-01 16:16
categories: "Notes"
tags:
  - "Web Security"
  - "Writeup"
  - "Reverse"
  - "Crypto"
description: "爆破，简单粗暴却行之有效 记一道DeadsecCTF中cry部分的题目以及其非预期解法 flag killer.py #!/usr/bin/python3 from binascii import hexlify, unhexlify def FLAG_KILLER(value): index = "
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18336836"
---
> 爆破，简单粗暴却行之有效

记一道DeadsecCTF中cry部分的题目以及其非预期解法

flag killer.py

```
#!/usr/bin/python3

from binascii import hexlify, unhexlify

def FLAG_KILLER(value):
    index = 0
    temp = []
    output = 0
    while value > 0:
        temp.append(2 - (value % 4) if value % 2 != 0 else 0)
        value = (value - temp[index]) / 2
        index += 1
    temp = temp[::-1]
    for index in range(len(temp)):
        output += temp[index] * 3 ** (len(temp) - index - 1)
    return output

def encrypt(message):
    flag = hexlify(message.encode()).decode()
    index = 0
    output = ''
    while index < len(flag):
        output += '%05x' % int(FLAG_KILLER(int(flag[index:index+3], 16)))
        index += 3
    return output

message = 'DEAD{test}'
flag = hexlify(message.encode()).decode()
encrypted_output = encrypt(message)
print('Encrypted:', encrypted_output)
```

以及密文部分  
encrypted.txt

```
Encrypted: 0e98b103240e99c71e320dd330dd430de2629ce326a4a2b6b90cd201030926a090cfc5269f904f740cd1001c290cd10002900cd100ee59269a8269a026a4a2d05a269a82aa850d03a2b6b900883
```

# 审计代码

审计encrypt函数，发现其功能为将明文（flag）切成长度为三个字节的小块（转变为16进制），逐个使用FLAG\_KILLER函数进行加密，再把加密结果拼到一个字符串output里输出

审计FLAG\_KILLER函数，发现看不懂（bushi）

审计此函数，发现其使用一个循环来处理输入的值value，条件是value大于0

在每次迭代中，计算value对4取模的结果，根据模的结果来决定temp列表中应添加的值：

-   如果value是奇数（value % 2 != 0），则添加2 - (value % 4)到temp列表
    
-   如果value是偶数，则添加0到temp列表
    

然后，更新value为(value - temp\[index\]) / 2，这相当于将当前位的值减去并右移一位，随后使index递增

将temp列表反转（temp\[::-1\]），以便从最低位开始处理

使用另一个循环遍历temp列表中的每个元素。将temp\[index\]乘以3的相应次方（3 \*\* (len(temp) - index - 1)），然后将结果累加到output

最后返回output

显然，正解为逆向上述操作（不会喵）

# 非预期解

观察代码，发现每一次加密只对三个字节进行。转换为十六进制之后取值在0~0xfff（4096）之间

也就是说，一组密文可能对应4096组明文

使用DEAD{test}作为密文加密出0e98b103240e99c72c7526e940ddd600883长度为35

由此能猜到：一组3位明文对应5位密文（也可以审计代码得到（懒））

观察encrypted.txt长度为155，估计进行了31组加密

可得，每组加密一共4096种情况，进行了31次加密。

也就是说，如果使用爆破手段，运气最差的情况下，我们126976次加密操作之后必定能爆破出明文

单次加密中不涉及到复杂的数学运算，126976次加密操作对于计算机来说用不了多久

由此编写FLAG\_KILLER\_reverse代码

```
def reverse_FLAG_KILLER(encoded_value):
    # 从0爆破到0xfff
    for possible_value in range(0, 0xFFF):
        if FLAG_KILLER(possible_value) == encoded_value:
            return possible_value
    return None
```

这个函数名加上函数内容莫名喜感（））

编写脚本将密文拆开丢进去爆破就行

最终脚本

exp.py

```
def reverse_FLAG_KILLER(encoded_value):
    # 从0爆破到0xfff
    for possible_value in range(0, 0xFFF):
        if FLAG_KILLER(possible_value) == encoded_value:
            return possible_value
    return None

def decrypt(output):
    index = 0
    flag_hex = ''
    
    while index < len(output):
        encoded_segment = output[index:index+5]
        encoded_value = int(encoded_segment, 16)
        original_value = reverse_FLAG_KILLER(encoded_value)
        if original_value is None:
            raise ValueError("Decryption failed for segment: {}".format(encoded_segment))
        flag_hex += '%03x' % original_value
        index += 5
    substr = flag_hex
    while True:
        substr = substr[:-1]
        if substr.endswith('0'):
            substr = substr[:-1]
            break
    flag_hex = substr+flag_hex[len(substr)+1:]
    return unhexlify(flag_hex).decode()
output = '0e98b103240e99c71e320dd330dd430de2629ce326a4a2b6b90cd201030926a090cfc5269f904f740cd1001c290cd10002900cd100ee59269a8269a026a4a2d05a269a82aa850d03a2b6b900883' 
flag = decrypt(output)
print('Decrypted:', flag)

#Decrypted: DEAD{263f871e880e9dc7d2401000304fc60e98c7c588}
```

偷鸡成功ヾ(≧▽≦\*)o

**DEAD{263f871e880e9dc7d2401000304fc60e98c7c588}**
