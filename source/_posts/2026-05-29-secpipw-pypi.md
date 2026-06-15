---
title: "secpipw: 轻量，免费，强大，无摩擦的 PyPI 供应链投毒防护利器"
date: 2026-05-29 23:41
updated: 2026-05-29 23:41
categories: "Notes"
tags:
  - "Web Security"
description: "今天，我怀着激动的心情发布 secpipw（以下简称 spip） 的 pre-release，ver 0.7.1。这篇文章，我们来详细介绍一下这个工具。它的官网在：https://spip.lamentxu.top/zh-cn 。文档在：https://spip.lamentxu.top/zh-cn"
original_url: "https://www.cnblogs.com/LAMENTXU/articles/20170020"
---
今天，我怀着激动的心情发布 secpipw（以下简称 spip） 的 pre-release，ver 0.7.1。这篇文章，我们来详细介绍一下这个工具。它的官网在：[https://spip.lamentxu.top/zh-cn](https://spip.lamentxu.top/zh-cn) 。文档在：[https://spip.lamentxu.top/zh-cn/docs](https://spip.lamentxu.top/zh-cn/docs) 。  
源代码在 [https://github.com/LamentXU123/secured\_pip](https://github.com/LamentXU123/secured_pip) 。

这个工具将会在二零二六年六月初进行 stable release。

# spip 简介

spip 是一个 pip 的包装器。它于原版 pip 的行为完全一致，唯独在 install 上略有区别。我可以很自豪地说，**它能在你感受不到它的存在的前提下，防御住目前已知的所有供应链投毒攻击方式**

## 解决了什么问题

供应链投毒一直是网络安全里永恒的话题。现在市面上对此的解决方案，有成熟却性能开销大的 GuardDog，也有完全依赖付费 socket API 的 sfw。它们的问题在于：成熟如 GuardDog 的太笨重，不适合进入 CI 反而适合安全研究员静态解析。若对每一个 pip install 的下载产物（包括各种依赖）都跑一次 GuardDog 无疑会拖慢安装进度；而 sfw 虽然轻量，却是完全依靠付费的 socket API 完成，对于日常开发者而言，无疑又是一次经济负担。

spip 解决了这个问题。它通过给 pip 的安装器上钩子，将安全检查完美地融合到了 pip install 的下载和安装流程中去。同时，你几乎感受不到任何性能损失。spip 完全免费提供给所有人。

当代，很多独立开发者的 CI 服务器被攻击导致 secret key 泄露，造成严重后果。如果安装了 spip，这样的风险会大大降低，同时**不需要付费，不需要额外的性能开支，也不需要学习和配置**。只有一次的 `pip install spip` 再设置一次别名，你就可以接着用 pip，却在无形中获得一层至关重要的保护网

## spip 的优势

-   轻量。你感受不到它的存在。
-   0 迁移或学习成本。你不需要任何配置，开箱即用。
-   免费。spip 在 MIT 协议下开源。任何人都可以使用，修改或再分发。
-   强大。经过测试可以完美防御如 LiteLLM，colorama 等知名攻击事件。

# 技术原理

## 报警机制

secpipw 提供三种不同等级的报警

-   LOW，只输出信息。
-   MEDIUM，会询问开发者是否要继续安装。在 CI 流水线上，这意味着停止安装。
-   HIGH，停止安装。

你可以使用 `--sensitivity <level>` 的形式调整敏感度。目前是最低的敏感度，即为默认配置。  
你可以使用 `--ignore-warning` 这样即使出现通常会暂停、询问或阻断安装的 warning，也继续安装。

更多参数，请参考：[https://spip.lamentxu.top/zh-cn/docs/parameters.html](https://spip.lamentxu.top/zh-cn/docs/parameters.html)

## 检查了什么，以及为什么检查

请参考：[https://spip.lamentxu.top/zh-cn/docs/checks.html](https://spip.lamentxu.top/zh-cn/docs/checks.html)

检查主要分为三类

-   元数据（metadata）检查。例如包的存活时间，发布作者（是否变化）等。
-   安装前检查。这是通过解析下载下来的 wheel 文件，检查该版本于本地记录的（如有）的上个版本的 diff，有没有新增的 .pth 文件，或 setup.py 的入口有没有改变等。
-   安装后检查。例如是否含有以 import 语句开头的 .pth 文件等。

## 实现方式

当你敲下 pip install 时，你实际上做了：

1.  Resolve。这个阶段，pip 将会生成一个下载计划（Install Plan）里面包括了所有此次下载需要下载的内容。相当于梳理了依赖关系并整理出了要下载什么。
2.  Download。下载。
3.  Install。安装。

我们分别在这三个步骤中**插入**检查。这样就不会影响到原来的下载。在第一步之后，我们利用解析下来的元数据，做一次检查。第二步，即下载完成后安装开始前，我们解析 wheel 文件与过去对比。第三步安装落盘之后，我们做一次简单的静态检测。

# 总结

综上，spip 适用于 CI 流水线和个人开发者的主机上，可以低成本地上一个尽可能安全的保护网，防护供应链投毒攻击。

将来，如果本项目有不错的反响，我们会支持 pipx，uv，和 conda 环境。
