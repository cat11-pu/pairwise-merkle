# pairwise-merkle

只依赖 Python 标准库的内存哈希树内核：叶子是字节串，自下而上按相邻两片
成对折叠，落单的节点原样提到上一层，最上面那一个摘要就是根。哈希函数由
调用方注入，默认是带域分离的 SHA-256；内核不读时钟、不取随机数，也不做
任何 I/O。

- `merkle/core.py` — 哈希树内核：叶层与各层折叠、根重建、包含证明的生成与校验。
- `tests/test_core.py` — 验收用例。

## 运行测试

在项目根目录执行：

```
python3 -m unittest discover -s tests -v
```

Windows 上如果没有 `python3`，可用：

```
python -m unittest discover -s tests -v
```
