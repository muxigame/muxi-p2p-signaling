# muxi-p2p-signaling

muxi-p2p 的信令：Python 包 `muxi-p2p-signaling`，提供 FastAPI 路由 `/api/v1/tunnel/*`
（agent 注册、候选过滤、长轮询、打洞会合）和 `MUXI-REFLECT/1` 反射器。

总仓是 [muxi-p2p](https://github.com/muxigame/muxi-p2p)，它把本仓和端侧仓
[muxi-p2p-agent](https://github.com/muxigame/muxi-p2p-agent) 作为 submodule 挂在一起。
只需要信令的服务直接引用本仓。

## 使用

```bash
pip install ./third_party/muxi-p2p-signaling      # 作为 submodule 引用时
```

```python
from muxi_p2p_signaling import router
app.include_router(router)
```

独立部署：`uvicorn muxi_p2p_signaling.main:app --workers 1`（注册表在内存里，只能单进程）。

### 嵌入进别的服务

`configure()` 让宿主接管鉴权：

```python
configure(
    secret_provider=lambda server_id: token_of(server_id),   # 每台 agent 一把 token
    access_guard=require_signed_in_user,                     # async (request, server_id)，不放行就抛 HTTPException
    diagnostics=False,                                       # 关掉不鉴权的 /diag
    relay_host="relay.example.com",                          # 没有内置中转地址
)
```

不调用时行为和独立部署一致：一把共享密钥（`MUXI_TUNNEL_TOKEN` / `BMC_TUNNEL_TOKEN_FILE`），
`/client-token`、`/endpoints`、`/punch` 公开。

### 反射器

`python -m muxi_p2p_signaling.reflector` 监听 UDP 45701–45703 和 TCP 45711–45712，回答
“你的包从哪个地址来”。放在两个不同公网 IP 上效果最好。也可以在宿主进程里
`await Reflector(...).start()`。

## 测试

```bash
pip install -r requirements-dev.txt
python -B -m unittest discover -s tests -v
```

## 来源

从 `muxi-mc-signaling` 拆出，经 muxi-p2p（`86f9c17`）分到本仓；反射器是新写的。文件来源与
拆分时的哈希见总仓的 `SOURCE-PROVENANCE.json`。

Apache-2.0，见 [`LICENSE`](LICENSE)。
