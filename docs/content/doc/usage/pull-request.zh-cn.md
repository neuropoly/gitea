---
date: "2018-06-01T19:00:00+02:00"
title: "合并请求"
slug: "pull-request"
weight: 13
toc: false
draft: false
menu:
  sidebar:
    parent: "usage"
    name: "合并请求"
    weight: 13
    identifier: "pull-request"
---

# 合并请求

## 在合并请求中使用“Work In Progress”标记

您可以通过在一个进行中的 pull request 的标题上添加前缀 `WIP:` 或者 `[WIP]`（此处大小写敏感）来防止它被意外合并，具体的前缀设置可以在配置文件 `app.ini` 中找到：

```
[repository.pull-request]
WORK_IN_PROGRESS_PREFIXES=WIP:,[WIP]
```

列表的第一个值将用于 helpers 程序。

## 合并请求模板

有关合并请求模板的更多信息请您移步 : [工单和合并请求模板](issue-pull-request-templates)