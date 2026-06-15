---
title: "vsCTF 2024 web spinner wp"
date: 2024-06-19 13:25
updated: 2024-06-19 13:25
categories: "Notes"
tags:
  - "Web Security"
  - "Writeup"
description: "vsCTF里一道很棒的web题~ 本来就菜，加上我的前端安全水平又是入门级别，这种题做起来还是很费劲的。慢慢学吧 题目附件 其中后端代码： const http = require(&#39;http&#39;); const fs = require(&#39;fs&#39;); const pa"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/18256028"
---
vsCTF里一道很棒的web题~

本来就菜，加上我的前端安全水平又是入门级别，这种题做起来还是很费劲的。慢慢学吧

[题目附件](https://files.cnblogs.com/files/blogs/820580/spinner.zip)

其中后端代码：

```
const http = require('http');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');

const server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/') {
        fs.readFile(path.join(__dirname, 'index.html'), (err, data) => {
            if (err) {
                res.writeHead(500);
                res.end();
            } else {
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(data);
            }
        });
    } else {
        res.writeHead(404);
        res.end('Not Found');
    }
});

const wss = new WebSocket.Server({ server });

const clients = new Map();

wss.on('connection', (ws) => {
    const clientData = {
        spins: 0,
        cumulativeAngle: 0,
        lastAngle: null,
        touchedPoints: []
    };

    clients.set(ws, clientData);

    ws.on('message', (message) => {
        const data = JSON.parse(message);
        const client = clients.get(ws);

        if (client) {
            const { x, y, centerX, centerY } = data;

            if (client.touchedPoints.some(point => point.x === x && point.y === y)) {
                return;
            }

            client.touchedPoints.push({ x, y });

            const currentAngle = Math.atan2(y - centerY, x - centerX) * (180 / Math.PI);

            if (client.lastAngle !== null) {
                let delta = currentAngle - client.lastAngle;
                if (delta > 180) delta -= 360;
                if (delta < -180) delta += 360;
                client.cumulativeAngle += delta;

                while (Math.abs(client.cumulativeAngle) >= 360) {
                    client.cumulativeAngle -= 360 * Math.sign(client.cumulativeAngle);
                    client.spins += 1;
                }

                ws.send(JSON.stringify({ spins: client.spins }));

                if (client.spins >= 9999) {
                    ws.send(JSON.stringify({ message: process.env.FLAG ?? "vsctf{test_flag}" }));
                    client.spins = 0;
                }
            }

            client.lastAngle = currentAngle;
        }
    });

    ws.on('close', () => {
        clients.delete(ws);
    });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
```

直接进行一个代码的读

发现其主要功能是建立一个websocket，然后通过传输用户鼠标位置计算用户鼠标转了多少圈，如果圈数>=9999圈就输出flag

最坑的是，每次鼠标位置还要不一样才算数，所以越到后面越慢

因此，手打是不可能手打的，9999圈怕不是要打到比赛结束

接下来看前端代码

```
const centerX = window.innerWidth / 2;
const centerY = window.innerHeight / 2;
const centerPoint = document.getElementById('centerPoint');
const spinCountDiv = document.getElementById('spinCount');
centerPoint.style.left = centerX - 5 + 'px';
centerPoint.style.top = centerY - 5 + 'px';

const socket = new WebSocket(`wss://${window.location.host}/ws`);

socket.addEventListener('open', () => {
    console.log('connected');
});

socket.addEventListener('message', (event) => {
    const data = JSON.parse(event.data);
    if (data.spins !== undefined) {
        spinCountDiv.textContent = `${data.spins}`;
    }
    if (data.message) {
        alert(data.message);
    }
});

document.addEventListener('mousemove', (event) => {
    const { clientX, clientY } = event;
    const message = {
        x: clientX,
        y: clientY,
        centerX: centerX,
        centerY: centerY
    };
    socket.send(JSON.stringify(message));
});
```

注意到每次旋转的centerX和centerY在初始化的时候就是定死的

先写一个函数，能发送正确格式的鼠标位置信息

```
function stimulate(angle) {
    return {
        x: centerX+Math.cos(Math.PI*2*angle/360);,
        y: centerY+Math.sin(Math.PI*2*angle/360);,
        centerX: centerX,
        centerY: centerY
    }
}
```

这样x和y就就可以直接由centerX+angle（旋转角度）算出来，即模拟了一次正常的鼠标位点

接下来重复执行这个代码,使得angle每次转90度，转4次就是一圈（4\*90=360）

```
    for (let angle = 0; angle <= 360.0; angle += 90.0) {
        socket.send(JSON.stringify(stimulate(angle)));
    }
```

这样就模拟了一圈

再套个外循环，循环10000次，这样就能转10000圈

```
    for (let i = 0; i < 10000; i += 1) {
      for (let angle = 0; angle <= 360.0; angle += 90.0) {
          socket.send(JSON.stringify(stimulate(angle)));
      }
  }
```

然而......转了半天只有一圈

回去看后端代码，发现每次鼠标位置还要不一样才算数，而上面的代码一直在转一样的圈

![](/images/migrated/18256028/01.png)

于是，我们可以通过改变圆的半径（如把半径从1逐渐变大）或者改变鼠标每一次的角度（如把单次旋转从90度开始下降或上升）来越过这个限制

这里，我们通过改变圆的半径实现

重写stimulate函数，增加一个参数R控制半径

```
function stimulate(angle, R) {
    return {
        x: centerX+Math.cos(Math.PI*2*angle/360) * R,
        y: centerY+Math.sin(Math.PI*2*angle/360) * R,
        centerX: centerX,
        centerY: centerY
    }
}
```

外循环的时候将R设为循环变量

```
for (let r= 1; r<= 1000; r += 0.1) {
    for (let angle = 0; angle <= 360.0; angle += 90.0) {
        socket.send(JSON.stringify(stimulate(angle, r)));
    }
}
```

这样我们将循环10000次（可以增多个数，避免网络问题丢失几次）即转了10000圈，每次半径增加0.1

最终再控制台运行如下脚本即可：

```
function stimulate(angle, R) {
    return {
        x: centerX+Math.cos(Math.PI*2*angle/360) * R,
        y: centerY+Math.sin(Math.PI*2*angle/360) * R,
        centerX: centerX,
        centerY: centerY
    }
}
for (let r= 1; r<= 1000; r += 0.1) {
    for (let angle = 0; angle <= 360.0; angle += 90.0) {
        socket.send(JSON.stringify(stimulate(angle, r)));
    }
}
```

最终flag：vsctf{i\_ran\_out\_of\_flag\_ideas\_so\_have\_this\_random\_string\_2CSJzbfeWqVBnwU5q8}
