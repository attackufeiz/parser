"""
white_checker.py — реальная проверка «белого списка» через xray.

Логика:
  1. По vpn_uri генерируем временный конфиг xray с локальным SOCKS5-прокси.
  2. Запускаем xray как subprocess.
  3. Через прокси делаем HTTP-запросы к WHITE_TEST_DOMAINS.
  4. Если >= WHITE_THRESHOLD из доменов ответили (200/30x/403/404) — WHITE.
  5. В любом случае xray-процесс корректно завершается.
"""

import json
import os
import socket
import subprocess
import tempfile
import time
from base64 import b64decode
from typing import Optional
from urllib.parse import unquote, parse_qs

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Конфигурация
# ---------------------------------------------------------------------------

# Якорные домены белого списка РФ
WHITE_TEST_DOMAINS = ["alfabank.ru", "mironline.ru", "vkusvill.ru"]

# Сколько доменов должны ответить, чтобы ключ считался WHITE
WHITE_THRESHOLD = 2

# Таймаут одного HTTP-запроса через прокси (секунды)
HTTP_TIMEOUT = 5

# Пауза после запуска xray перед первым запросом (секунды)
XRAY_STARTUP_WAIT = 3.0

# Путь к бинарнику xray (ENV > рядом со скриптом > PATH)
XRAY_BIN = os.environ.get(
    "XRAY_BIN",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "xray"),
)

# ---------------------------------------------------------------------------
# Поиск бинарника
# ---------------------------------------------------------------------------

def _xray_binary() -> Optional[str]:
    """Возвращает путь к xray или None."""
    if os.path.isfile(XRAY_BIN) and os.access(XRAY_BIN, os.X_OK):
        return XRAY_BIN
    base = os.path.dirname(os.path.abspath(__file__))
    for name in ("xray", "xray-linux-64", "xray.exe"):
        cand = os.path.join(base, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    import shutil
    return shutil.which("xray")


# ---------------------------------------------------------------------------
# Свободный порт
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Парсинг URI → xray outbound
# ---------------------------------------------------------------------------

def _p(params: dict, key: str, default: str = "") -> str:
    return params.get(key, [default])[0]


def _parse_vless(uri: str) -> Optional[dict]:
    try:
        body = uri[len("vless://"):]
        user_id, rest = body.split("@", 1)
        host_port, qs = (rest.split("?", 1) + [""])[:2]
        qs = qs.split("#")[0]
        host, port = host_port.rsplit(":", 1)
        port = int(port)
        params = parse_qs(qs)

        security = _p(params, "security", "none")
        net = _p(params, "type", "tcp")
        sni = _p(params, "sni", host)
        fp = _p(params, "fp", "chrome")
        flow = _p(params, "flow", "")
        path = unquote(_p(params, "path", "/"))
        h_host = unquote(_p(params, "host", host))
        pbk = _p(params, "pbk", "")
        sid = _p(params, "sid", "")

        ss: dict = {"network": net}
        if security == "tls":
            ss["security"] = "tls"
            ss["tlsSettings"] = {"allowInsecure": True, "serverName": sni, "fingerprint": fp}
        elif security == "reality":
            ss["security"] = "reality"
            ss["realitySettings"] = {"serverName": sni, "fingerprint": fp, "publicKey": pbk, "shortId": sid}
        else:
            ss["security"] = "none"

        if net == "ws":
            ss["wsSettings"] = {"path": path, "headers": {"Host": h_host}}
        elif net == "grpc":
            ss["grpcSettings"] = {"serviceName": _p(params, "serviceName", "")}

        user: dict = {"id": user_id, "encryption": "none"}
        if flow:
            user["flow"] = flow

        return {
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_trojan(uri: str) -> Optional[dict]:
    try:
        body = uri[len("trojan://"):]
        password, rest = body.split("@", 1)
        host_port, qs = (rest.split("?", 1) + [""])[:2]
        qs = qs.split("#")[0]
        host, port = host_port.rsplit(":", 1)
        port = int(port)
        params = parse_qs(qs)

        security = _p(params, "security", "tls")
        net = _p(params, "type", "tcp")
        sni = _p(params, "sni", host)
        fp = _p(params, "fp", "chrome")
        path = unquote(_p(params, "path", "/"))
        h_host = unquote(_p(params, "host", host))
        pbk = _p(params, "pbk", "")
        sid = _p(params, "sid", "")

        ss: dict = {"network": net}
        if security == "reality":
            ss["security"] = "reality"
            ss["realitySettings"] = {"serverName": sni, "fingerprint": fp, "publicKey": pbk, "shortId": sid}
        else:
            ss["security"] = "tls"
            ss["tlsSettings"] = {"allowInsecure": True, "serverName": sni, "fingerprint": fp}

        if net == "ws":
            ss["wsSettings"] = {"path": path, "headers": {"Host": h_host}}

        return {
            "protocol": "trojan",
            "settings": {"servers": [{"address": host, "port": port, "password": password}]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_vmess(uri: str) -> Optional[dict]:
    try:
        enc = uri[len("vmess://"):]
        enc += "=" * (-len(enc) % 4)
        data = json.loads(b64decode(enc).decode("utf-8", errors="ignore"))

        host = data.get("add", "")
        port = int(data.get("port", 443))
        uid = data.get("id", "")
        aid = int(data.get("aid", 0))
        net = data.get("net", "tcp")
        tls = data.get("tls", "")
        sni = data.get("sni", host)
        path = data.get("path", "/")
        h_host = data.get("host", host)
        fp = data.get("fp", "chrome")

        ss: dict = {"network": net}
        if tls == "tls":
            ss["security"] = "tls"
            ss["tlsSettings"] = {"allowInsecure": True, "serverName": sni, "fingerprint": fp}
        else:
            ss["security"] = "none"

        if net == "ws":
            ss["wsSettings"] = {"path": path, "headers": {"Host": h_host}}
        elif net == "grpc":
            ss["grpcSettings"] = {"serviceName": path}

        return {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": host, "port": port,
                                     "users": [{"id": uid, "alterId": aid, "security": "auto"}]}]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_ss(uri: str) -> Optional[dict]:
    try:
        body = uri[len("ss://"):].split("#")[0]
        if "@" in body:
            cred_b64, host_port = body.rsplit("@", 1)
            try:
                cred_b64 += "=" * (-len(cred_b64) % 4)
                cred = b64decode(cred_b64).decode("utf-8")
            except Exception:
                cred = cred_b64
            method, password = cred.split(":", 1)
        else:
            body += "=" * (-len(body) % 4)
            decoded = b64decode(body).decode("utf-8")
            if "@" not in decoded:
                return None
            cred, host_port = decoded.rsplit("@", 1)
            method, password = cred.split(":", 1)

        host, port = host_port.rsplit(":", 1)
        port = int(port)

        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": host, "port": port,
                                       "method": method, "password": password}]},
            "streamSettings": {"network": "tcp"},
        }
    except Exception:
        return None


def _build_outbound(vpn_uri: str) -> Optional[dict]:
    uri = vpn_uri.split("#")[0].strip()
    if uri.startswith("vless://"):
        return _parse_vless(uri)
    if uri.startswith("trojan://"):
        return _parse_trojan(uri)
    if uri.startswith("vmess://"):
        return _parse_vmess(uri)
    if uri.startswith("ss://"):
        return _parse_ss(uri)
    return None


def _build_config(outbound: dict, socks_port: int) -> dict:
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
            "sniffing": {"enabled": False},
        }],
        "outbounds": [
            {**outbound, "tag": "proxy"},
            {"protocol": "freedom", "tag": "direct"},
        ],
        "routing": {
            "rules": [{"type": "field", "outboundTag": "proxy", "port": "0-65535"}]
        },
    }


# ---------------------------------------------------------------------------
# Основная функция
# ---------------------------------------------------------------------------

def is_white_key(vpn_uri: str, timeout: float = 20.0) -> bool:
    """
    Проверяет, является ли vpn_uri «белым» ключом.

    Returns:
        True  — WHITE (>= WHITE_THRESHOLD доменов из WHITE_TEST_DOMAINS доступны).
        False — BLACK или ошибка.
    """
    xray_bin = _xray_binary()
    if not xray_bin:
        return False  # Нет бинарника — нельзя проверить

    outbound = _build_outbound(vpn_uri)
    if outbound is None:
        return False

    socks_port = _free_port()
    config = _build_config(outbound, socks_port)

    proc: Optional[subprocess.Popen] = None
    tmp_cfg: Optional[str] = None

    try:
        # Сохраняем временный конфиг
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tf:
            json.dump(config, tf)
            tmp_cfg = tf.name

        # Запускаем xray
        proc = subprocess.Popen(
            [xray_bin, "run", "-config", tmp_cfg],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Ждём поднятия туннеля
        time.sleep(XRAY_STARTUP_WAIT)

        # xray уже завершился — ключ нерабочий
        if proc.poll() is not None:
            return False

        proxies = {
            "http":  f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }

        # Равномерно распределяем оставшееся время по доменам
        remaining = timeout - XRAY_STARTUP_WAIT
        per_req = min(HTTP_TIMEOUT, max(2.0, remaining / len(WHITE_TEST_DOMAINS)))

        success = 0
        for domain in WHITE_TEST_DOMAINS:
            try:
                resp = requests.get(
                    f"https://{domain}/",
                    proxies=proxies,
                    timeout=per_req,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 (compatible)"},
                )
                # Любой HTTP-ответ = сервер доступен
                if resp.status_code < 600:
                    success += 1
            except Exception:
                pass

        return success >= WHITE_THRESHOLD

    except Exception:
        return False

    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if tmp_cfg and os.path.exists(tmp_cfg):
            try:
                os.unlink(tmp_cfg)
            except Exception:
                pass


































































































































