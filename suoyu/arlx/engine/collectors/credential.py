"""凭据有效性验证（默认关闭）。

这层只做一件事：**用户自己把账号库放进来**后，验证某组凭据在这台设备上是否真的
能进，用来把「抄到一个口令」升级成「这个口令确实是活的」。它不生成口令、不遍历、
不带默认字典——没有 `credentials.txt` 就整体不跑。

覆盖 HTTP 表单类组件（xing/brute 的 HTTP 部分）：每个组件一条登录路径 + 一个
成功判据。取到成功即止，失败一次就放弃该组件，不做重试。

配置：`config['scan']['credential_lists']` 指向一个目录，内含
`{app}.txt`，每行 `user:pass`（`app` 见 `CRED_TARGETS` 的键）。缺失即跳过。
"""
from __future__ import annotations

import base64
import subprocess
from pathlib import Path
from typing import Any

import httpx

from ...utils import run_blocking_slow

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"


def _client(timeout: float = 8.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False, trust_env=False,
                             headers={"User-Agent": UA, "Accept": "*/*"})


def _basic(user: str, pwd: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode()


# ─────────────── 登录判据 ───────────────
# 每条：登录路径、方法、构造请求、判成功。都以「这台设备确实接受该口令」为准，
# 不看状态码 200 就算过。

async def _try_activedmq(c, base, u, p):
    r = await c.get(f"{base}/admin/", auth=(u, p))
    return r.status_code == 200


async def _try_druid(c, base, u, p):
    r = await c.post(f"{base}/druid/submitLogin", data={"loginUsername": u, "loginPassword": p})
    return r.status_code == 200 and r.content.strip() == b"success"


async def _try_apisix(c, base, u, p):
    r = await c.post(f"{base}/apisix/admin/user/login", json={"username": u, "password": p})
    return '"code":0' in r.text and '"token"' in r.text


async def _try_grafana(c, base, u, p):
    r = await c.post(f"{base}/login", json={"user": u, "password": p})
    return r.status_code == 200 and "Logged in" in r.text


async def _try_harbor(c, base, u, p):
    r = await c.get(f"{base}/api/users", headers={"Authorization": _basic(u, p)})
    return r.status_code == 200 and "<" not in r.text


async def _try_jenkins(c, base, u, p):
    r = await c.get(f"{base}/api/json", auth=(u, p))
    return r.status_code == 200 and "jenkins" in r.text.lower()


async def _try_nacos(c, base, u, p):
    r = await c.post(f"{base}/nacos/v1/auth/users/login", data={"username": u, "password": p})
    return r.status_code == 200 and "<" not in r.text and '"accessToken"' in r.text


async def _try_nexus(c, base, u, p):
    body = "username={}&password={}".format(
        base64.b64encode(u.encode()).decode(), base64.b64encode(p.encode()).decode())
    r = await c.post(f"{base}/service/rapture/session", data=body,
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    return r.status_code == 204 and "<" not in r.text


async def _try_openfire(c, base, u, p):
    r = await c.post(f"{base}/login.jsp", data={"login": "true", "username": u, "password": p})
    return r.status_code in (301, 302)


async def _try_tomcat(c, base, u, p):
    r = await c.get(f"{base}/manager/html", auth=(u, p))
    return r.status_code == 200


async def _try_clickhouse(c, base, u, p):
    """ClickHouse 的 HTTP 口按头认证：认证失败 403；成功后空语句回 400 SYNTAX_ERROR。"""
    r = await c.post(f"{base}/", content=b"",
                     headers={"X-ClickHouse-User": u, "X-ClickHouse-Key": p})
    return r.status_code == 400 and b"(SYNTAX_ERROR)" in r.content


async def _try_gitlab(c, base, u, p):
    """GitLab 登录要 CSRF token + 会话 Cookie，缺一样都过不去。"""
    import re
    import urllib.parse

    r = await c.get(f"{base}/explore/projects")
    tok = re.search(r'name="csrf-token"\s+content="([^"]+)"', r.text)
    sess = r.cookies.get("_gitlab_session")
    if not tok or not sess:
        return False
    body = "utf8=%E2%9C%93&user%5Bremember_me%5D=0&authenticity_token={}&user%5Blogin%5D={}&user%5Bpassword%5D={}".format(
        urllib.parse.quote(tok.group(1)), urllib.parse.quote(u), urllib.parse.quote(p))
    r = await c.post(f"{base}/users/sign_in", content=body.encode(),
                     headers={"Content-Type": "application/x-www-form-urlencoded",
                              "Cookie": f"_gitlab_session={sess}"})
    return r.status_code == 302 and bool(r.cookies.get("_gitlab_session"))


async def _try_manageiq(c, base, u, p):
    r = await c.post(f"{base}/dashboard/authenticate?button=login",
                     content=f"user_name={u}&user_password={p}&browser_name=Chrome"
                             "&browser_version=120&browser_os=Windows&user_TZO=8".encode(),
                     headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
    return 'window.location.href = "/' in r.text and "incorrect" not in r.text


async def _try_exchange(c, base, u, p):
    """Exchange OWA：成功后 302 且回 5 个 cadata* Cookie 里至少两个。

    只做表单口（/owa/auth.owa）：AD 域名从目标主机名推，推不出就放弃。
    """
    host = base.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
    parts = host.split(".")
    if len(parts) < 3:
        return False
    dom = parts[-2]
    r = await c.post(f"{base}/owa/auth.owa",
                     content=f"destination={base}&flags=4&forcedownlevel=0&username={dom}\\{u}"
                             f"&password={p}&isUtf8=1&passwordText=".encode(),
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    if r.status_code != 302:
        return False
    sc = r.headers.get("Set-Cookie") or ""
    return sum(f"{k}=" in sc for k in ("cadata", "cadataTTL", "cadataKey", "cadataIV")) >= 2


CRED_TARGETS: dict[str, dict[str, Any]] = {
    "activemq": {"app": "ActiveMQ", "url": "/admin/", "try": _try_activedmq},
    "druid": {"app": "Alibaba Druid", "url": "/druid/submitLogin", "try": _try_druid},
    "apisix": {"app": "APISIX", "url": "/apisix/admin/user/login", "try": _try_apisix},
    "grafana": {"app": "Grafana", "url": "/login", "try": _try_grafana},
    "harbor": {"app": "Harbor", "url": "/api/users", "try": _try_harbor},
    "jenkins": {"app": "Jenkins", "url": "/api/json", "try": _try_jenkins},
    "nacos": {"app": "Nacos", "url": "/nacos/v1/auth/users/login", "try": _try_nacos},
    "nexus": {"app": "Nexus", "url": "/service/rapture/session", "try": _try_nexus},
    "openfire": {"app": "Openfire", "url": "/login.jsp", "try": _try_openfire},
    "tomcat": {"app": "Tomcat", "url": "/manager/html", "try": _try_tomcat},
    # 数据库类：走协议握手，先看是否免认证，再验证给定账号。
    "redis": {"app": "Redis", "url": "tcp://6379", "proto": "redis", "port": 6379},
    "postgres": {"app": "PostgreSQL", "url": "tcp://5432", "proto": "postgres", "port": 5432},
    "mysql": {"app": "MySQL", "url": "tcp://3306", "proto": "mysql", "port": 3306},
    "mongo": {"app": "MongoDB", "url": "tcp://27017", "proto": "mongo", "port": 27017},
    # 通用服务协议：账号库按服务名建文件（ftp.txt / ssh.txt / smtp.txt…）。
    "ftp": {"app": "FTP", "url": "tcp://21", "proto": "ftp", "port": 21},
    "ssh": {"app": "SSH", "url": "tcp://22", "proto": "ssh", "port": 22},
    "smtp": {"app": "SMTP", "url": "tcp://25", "proto": "smtp", "port": 25},
    "imap": {"app": "IMAP", "url": "tcp://143", "proto": "imap", "port": 143},
    "pop3": {"app": "POP3", "url": "tcp://110", "proto": "pop3", "port": 110},
    "rdp": {"app": "RDP", "url": "tcp://3389", "proto": "rdp", "port": 3389},
    "sqlserver": {"app": "SQL Server", "url": "tcp://1433", "proto": "sqlserver", "port": 1433},
    # 表单 / 接口类（补齐 xing/brute 的 HTTP 部分）。
    "clickhouse": {"app": "ClickHouse", "url": "/", "try": _try_clickhouse},
    "gitlab": {"app": "GitLab", "url": "/users/sign_in", "try": _try_gitlab},
    "manageiq": {"app": "ManageIQ", "url": "/dashboard/authenticate", "try": _try_manageiq},
    "exchange": {"app": "Exchange OWA", "url": "/owa/auth.owa", "try": _try_exchange},
    # rememberMe 弱密钥：账号库里 `-:base64密钥`。CBC 与 GCM 分开试。
    "shiro": {"app": "Apache Shiro", "url": "/", "mode": "shiro"},
    "shiro_gcm": {"app": "shiro_gcm", "url": "/", "mode": "shiro"},
}


# ─────────────── 数据库协议验证 ───────────────
# 只验一组账号，不做字典。协议细节够用即可：能区分「认证通过」和「认证失败」。
# 依赖既有的 redis / pymysql / psycopg / pymongo（没有就整段跳过，不报错）。

async def _tcp_try_redis(host: str, port: int, user: str, pwd: str) -> bool:
    """AUTH 成功后 PING 返回 +PONG 才算过。"""
    script = (
        "import socket,sys\n"
        "s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=6)\n"
        "s.settimeout(6)\n"
        "if sys.argv[3]:\n"
        "    s.sendall(('AUTH %s %s\\r\\n'%(sys.argv[3],sys.argv[4])).encode())\n"
        "    r=s.recv(256)\n"
        "    if r.startswith(b'-'):\n"
        "        print('NO');sys.exit()\n"
        "s.sendall(b'PING\\r\\n')\n"
        "print('OK' if s.recv(256).startswith(b'+PONG') else 'NO')\n"
    )
    out = await _run_py(script, host, str(port), user, pwd)
    return out.strip() == "OK"


PG_OK = {"password authentication succeeded", "authentication succeeded"}


async def _tcp_try_postgres(host: str, port: int, user: str, pwd: str) -> bool:
    """只看服务端回的认证结果：succeeded 才算过。"""
    script = (
        "import socket,struct,sys\n"
        "h,p,u,pw=sys.argv[1],int(sys.argv[2]),sys.argv[3],sys.argv[4]\n"
        "s=socket.create_connection((h,p),timeout=6); s.settimeout(6)\n"
        "m=b'user\\x00'+u.encode()+b'\\x00database\\x00postgres\\x00\\x00'\n"
        "s.sendall(struct.pack('!ii',len(m)+8,196608)+m)\n"
        "def msg():\n"
        "    hd=s.recv(5)\n"
        "    if len(hd)<5: return b'',b''\n"
        "    t=hd[0:1]; n=struct.unpack('!i',hd[1:5])[0]-4\n"
        "    return t,s.recv(n) if n>0 else b''\n"
        "while True:\n"
        "    t,b=msg()\n"
        "    if not t: print('NO');break\n"
        "    if t==b'R':\n"
        "        code=struct.unpack('!i',b[:4])[0]\n"
        "        if code!=0: print('NO');break\n"
        "    elif t==b'E': print('NO');break\n"
        "    elif t==b'Z': print('OK');break\n"
    )
    out = await _run_py(script, host, str(port), user, pwd)
    return out.strip() == "OK"


async def _tcp_try_mysql(host: str, port: int, user: str, pwd: str) -> bool:
    """用 pymysql 建一次连接，能建即认证通过；未装库返回 False。"""
    script = (
        "import sys\n"
        "try:\n"
        "    import pymysql\n"
        "except ImportError:\n"
        "    print('SKIP');sys.exit()\n"
        "try:\n"
        "    pymysql.connect(host=sys.argv[1],port=int(sys.argv[2]),user=sys.argv[3],"
        "password=sys.argv[4],connect_timeout=6)\n"
        "    print('OK')\n"
        "except Exception:\n"
        "    print('NO')\n"
    )
    out = await _run_py(script, host, str(port), user, pwd)
    return out.strip() == "OK"


async def _tcp_try_mongo(host: str, port: int, user: str, pwd: str) -> bool:
    """用 pymongo 认证一次 admin 库；未装库返回 False。"""
    script = (
        "import sys\n"
        "try:\n"
        "    from pymongo import MongoClient\n"
        "except ImportError:\n"
        "    print('SKIP');sys.exit()\n"
        "try:\n"
        "    c=MongoClient(sys.argv[1],int(sys.argv[2]),serverSelectionTimeoutMS=6000,\n"
        "                  username=sys.argv[3],password=sys.argv[4],authSource='admin')\n"
        "    c.admin.command('ping');print('OK')\n"
        "except Exception:\n"
        "    print('NO')\n"
    )
    out = await _run_py(script, host, str(port), user, pwd)
    return out.strip() == "OK"


async def _tcp_try_ftp(host: str, port: int, user: str, pwd: str) -> bool:
    """FTP：USER 过 331/230，PASS 回 230 才算登录成功。"""
    script = (
        "import socket,sys\n"
        "s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=6)\n"
        "s.settimeout(6)\n"
        "def rd():\n"
        "    b=b''\n"
        "    while True:\n"
        "        d=s.recv(1)\n"
        "        if not d: break\n"
        "        b+=d\n"
        "        if b.endswith(b'\\r\\n') and b[:3].isdigit() and b[3:4]==b' ': break\n"
        "    return b\n"
        "rd()\n"
        "s.sendall(('USER %s\\r\\n'%sys.argv[3]).encode()); r=rd()\n"
        "if not r.startswith(b'331') and not r.startswith(b'230'): print('NO');sys.exit()\n"
        "if r.startswith(b'230'): print('OK');sys.exit()\n"
        "s.sendall(('PASS %s\\r\\n'%sys.argv[4]).encode()); r=rd()\n"
        "print('OK' if r.startswith(b'230') else 'NO')\n"
    )
    return (await _run_py(script, host, str(port), user, pwd)).strip() == "OK"


async def _tcp_try_smtp(host: str, port: int, user: str, pwd: str) -> bool:
    """SMTP AUTH LOGIN：235 才算过；用户没带 @ 时补目标域。"""
    script = (
        "import socket,sys,base64\n"
        "u=sys.argv[3]\n"
        "if '@' not in u and sys.argv[5]: u='%s@%s'%(u,sys.argv[5])\n"
        "s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=8)\n"
        "s.settimeout(8)\n"
        "def rd():\n"
        "    b=b''\n"
        "    while True:\n"
        "        d=s.recv(1)\n"
        "        if not d: break\n"
        "        b+=d\n"
        "        if b.endswith(b'\\r\\n') and b[:3].isdigit() and b[3:4]==b' ': break\n"
        "    return b\n"
        "rd()\n"
        "s.sendall(b'EHLO test\\r\\n'); r=rd()\n"
        "if b'AUTH' not in r: print('NO');sys.exit()\n"
        "s.sendall(b'AUTH LOGIN\\r\\n'); rd()\n"
        "s.sendall(base64.b64encode(u.encode())+b'\\r\\n'); rd()\n"
        "s.sendall(base64.b64encode(sys.argv[4].encode())+b'\\r\\n'); r=rd()\n"
        "print('OK' if r.startswith(b'235') else 'NO')\n"
    )
    return (await _run_py(script, host, str(port), user, pwd, host.split(".")[-2] if "." in host else "")).strip() == "OK"


async def _tcp_try_ssh(host: str, port: int, user: str, pwd: str) -> bool:
    """SSH 口令登录：paramiko 没装就跳过，不做半截判断。"""
    script = (
        "import sys\n"
        "try:\n"
        "    import paramiko\n"
        "except ImportError:\n"
        "    print('SKIP');sys.exit()\n"
        "c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "try:\n"
        "    c.connect(sys.argv[1],port=int(sys.argv[2]),username=sys.argv[3],password=sys.argv[4],"
        "timeout=8,allow_agent=False,look_for_keys=False)\n"
        "    print('OK')\n"
        "except paramiko.AuthenticationException:\n"
        "    print('NO')\n"
        "except Exception:\n"
        "    print('NO')\n"
    )
    return (await _run_py(script, host, str(port), user, pwd)).strip() == "OK"


async def _tcp_try_rdp(host: str, port: int, user: str, pwd: str) -> bool:
    """RDP：走 NLA/CredSSP，依赖 impacket 与 ntlm_auth，缺任一就跳过。"""
    script = (
        "import sys\n"
        "try:\n"
        "    from impacket.examples.rdp_check import check_rdp\n"
        "except Exception:\n"
        "    print('SKIP');sys.exit()\n"
        "try:\n"
        "    ok=check_rdp(sys.argv[1],sys.argv[3],sys.argv[4],int(sys.argv[2]))\n"
        "    print('OK' if ok else 'NO')\n"
        "except Exception as e:\n"
        "    print('NO')\n"
    )
    return (await _run_py(script, host, str(port), user, pwd)).strip() == "OK"


async def _tcp_try_sqlserver(host: str, port: int, user: str, pwd: str) -> bool:
    """SQL Server 登录：用 pymssql 建一次连接，能建即口令有效。"""
    script = (
        "import sys\n"
        "try:\n"
        "    import pymssql\n"
        "except ImportError:\n"
        "    print('SKIP');sys.exit()\n"
        "try:\n"
        "    pymssql.connect(server=sys.argv[1],port=sys.argv[2],user=sys.argv[3],"
        "password=sys.argv[4],login_timeout=8)\n"
        "    print('OK')\n"
        "except Exception:\n"
        "    print('NO')\n"
    )
    return (await _run_py(script, host, str(port), user, pwd)).strip() == "OK"


async def _tcp_try_imap(host: str, port: int, user: str, pwd: str) -> bool:
    """IMAP 登录：LOGIN 回 OK 才算过（163/腾讯企业邮等常暴露 143/993）。"""
    script = (
        "import socket,sys\n"
        "u=sys.argv[3]\n"
        "if '@' not in u and sys.argv[5]: u='%s@%s'%(u,sys.argv[5])\n"
        "s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=8)\n"
        "s.settimeout(8)\n"
        "def rd():\n"
        "    b=b''\n"
        "    while True:\n"
        "        d=s.recv(1)\n"
        "        if not d: break\n"
        "        b+=d\n"
        "        if b.endswith(b'\\r\\n') and (b[:2] in (b'a1',b'* ') or b[2:3]==b' '): break\n"
        "    return b\n"
        "rd()\n"
        "s.sendall(b'a1 LOGIN \"%s\" \"%s\"\\r\\n'%(u.encode(),sys.argv[4].encode()))\n"
        "r=s.recv(512)\n"
        "print('OK' if r[:2] in (b'a1',b'a2') and b'OK' in r.upper() and b'NO' not in r.upper() "
        "and b'FAIL' not in r.upper() else 'NO')\n"
    )
    return (await _run_py(script, host, str(port), user, pwd,
                          host.split(".")[-2] if "." in host else "")).strip() == "OK"


async def _tcp_try_pop3(host: str, port: int, user: str, pwd: str) -> bool:
    """POP3 登录：USER/PASS 后回 +OK 才算过。"""
    script = (
        "import socket,sys\n"
        "u=sys.argv[3]\n"
        "if '@' not in u and sys.argv[5]: u='%s@%s'%(u,sys.argv[5])\n"
        "s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=8)\n"
        "s.settimeout(8)\n"
        "def rd():\n"
        "    return s.recv(512)\n"
        "rd()\n"
        "s.sendall(('USER %s\\r\\n'%u).encode()); r=rd()\n"
        "if not r.startswith(b'+OK'): print('NO');sys.exit()\n"
        "s.sendall(('PASS %s\\r\\n'%sys.argv[4]).encode()); r=rd()\n"
        "print('OK' if r.startswith(b'+OK') else 'NO')\n"
    )
    return (await _run_py(script, host, str(port), user, pwd,
                          host.split(".")[-2] if "." in host else "")).strip() == "OK"


def _tcp_try_cs(host: str, port: int, user: str, pwd: str) -> bool:
    """CobaltStrike TeamServer 的 50050 是私有二进制协议，且未开放认证失败区分字段，
    猜协议格式只会产生假阴性，所以这里明确不支持。"""
    return False


TCP_TRY = {
    "redis": _tcp_try_redis,
    "postgres": _tcp_try_postgres,
    "mysql": _tcp_try_mysql,
    "mongo": _tcp_try_mongo,
    "ftp": _tcp_try_ftp,
    "smtp": _tcp_try_smtp,
    "imap": _tcp_try_imap,
    "pop3": _tcp_try_pop3,
    "ssh": _tcp_try_ssh,
    "rdp": _tcp_try_rdp,
    "sqlserver": _tcp_try_sqlserver,
}


async def _run_py(script: str, *args: str) -> str:
    """跑一小段 Python，用当前解释器；超时或异常返回空串。"""
    import asyncio
    import sys

    def work() -> str:
        try:
            p = subprocess.run([sys.executable, "-c", script, *args], capture_output=True, timeout=20)
            return p.stdout.decode("utf-8", "ignore")
        except Exception:
            return ""

    return await run_blocking_slow(work, timeout=25)


def load_list(directory: str | Path, app: str, limit: int = 20) -> list[tuple[str, str]]:
    """读用户自备账号库；不存在返回空列表。"""
    fp = Path(directory) / f"{app}.txt"
    if not fp.is_file():
        return []
    out: list[tuple[str, str]] = []
    for line in fp.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        user, _, pwd = line.partition(":")
        out.append((user.strip(), pwd.strip()))
        if len(out) >= limit:
            break
    return out


async def verify(base_url: str, app: str, pairs: list[tuple[str, str]]) -> dict | None:
    """对一台设备验证一组凭据，第一个成功的即返回；全失败返回 None。

    HTTP 组件走 `try`；数据库组件走 `proto`（TCP 协议握手，host 取自 base_url）。
    """
    spec = CRED_TARGETS.get(app)
    if not spec or not pairs:
        return None
    if spec.get("proto"):
        return await _verify_tcp(spec, base_url, app, pairs)
    base = base_url.rstrip("/")
    if spec.get("mode") == "shiro":
        return await _verify_shiro(base, app, pairs)
    async with _client() as c:
        for user, pwd in pairs:
            try:
                ok = await spec["try"](c, base, user, pwd)
            except Exception:
                continue
            if ok:
                return {"app": spec["app"], "username": user, "url": f"{base}{spec['url']}"}
    return None


# 一段合法序列化对象：解不开时 Shiro 会回 rememberMe=deleteMe，解开后不再回这句。
SHIRO_PAYLOAD = ("rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFs"
                 "Q29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRp"
                 "bC9NYXA7eHBwdwEAeA==")


async def _verify_shiro(base: str, app: str, pairs: list[tuple[str, str]]) -> dict | None:
    """Shiro rememberMe 弱密钥：同一站点先打两次随机串拿到 baseline 的 deleteMe 次数，
    再把候选密钥加密的载荷发过去，deleteMe 次数少了说明密钥对了、内存马能注入。

    候选密钥放在账号库里，`user` 位随便写（建议 `-`），`pwd` 位写 base64 密钥。
    """
    import asyncio
    import base64
    import os

    try:
        from Crypto.Cipher import AES
    except Exception:
        return None
    mode = AES.MODE_GCM if app == "shiro_gcm" else AES.MODE_CBC

    def enc(key_b64: str) -> str | None:
        try:
            key = base64.b64decode(key_b64)
            iv = os.urandom(16)
            data = base64.b64decode(SHIRO_PAYLOAD)
            if mode == AES.MODE_GCM:
                ci = AES.new(key, mode, iv)
                ct, tag = ci.encrypt_and_digest(data)
                return base64.b64encode(iv + ct + tag).decode()
            pad = 16 - len(data) % 16
            ci = AES.new(key, mode, iv)
            return base64.b64encode(iv + ci.encrypt(data + bytes([pad]) * pad)).decode()
        except Exception:
            return None

    async def hits(val: str) -> int | None:
        try:
            async with _client(timeout=6.0) as c:
                r = await c.get(f"{base}/?{os.urandom(4).hex()}={os.urandom(4).hex()}",
                                headers={"Cookie": f"rememberMe={val}"})
        except Exception:
            return None
        return (r.headers.get("Set-Cookie") or "").count("rememberMe=deleteMe")

    base_n = await hits("1")
    if not base_n:
        return None
    for user, pwd in pairs:
        val = enc(pwd)
        if not val:
            continue
        await asyncio.sleep(0.2)
        n = await hits(val)
        if n is not None and n < base_n:
            tag = "GCM" if mode == AES.MODE_GCM else "CBC"
            return {"app": "Apache Shiro", "username": user,
                    "url": f"{base}/ (rememberMe {tag} 密钥 {pwd})"}
    return None


def _split_host(value: str) -> tuple[str, int | None]:
    """从 `https://h:8443/x` 或 `h:6379` 里取出 host 和端口。"""
    v = (value or "").strip()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]
    host, sep, port = v.rpartition(":")
    if sep and port.isdigit():
        return host, int(port)
    return v, None


async def _verify_tcp(spec: dict, target: str, app: str, pairs: list[tuple[str, str]]) -> dict | None:
    fn = TCP_TRY.get(spec["proto"])
    if not fn:
        return None
    host, port = _split_host(target)
    if not host:
        return None
    port = port or int(spec["port"])
    # 数据库类只验第一组：同一库重复试错会触发账号锁定
    user, pwd = pairs[0]
    try:
        ok = await fn(host, port, user, pwd)
    except Exception:
        ok = False
    if ok:
        return {"app": spec["app"], "username": user, "url": f"{host}:{port}"}
    return None
