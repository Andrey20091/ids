# =============================================================================
# Модуль: минимальный HTTP-прокси (GET/… с абсолютным URI и метод CONNECT).
# =============================================================================
"""Логирование метаданных потоков в NDJSON без расшифровки TLS (CONNECT — туннель)."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def _parse_connect_target(first_line: str) -> tuple[str, int] | None:
    """``CONNECT host:port HTTP/1.x`` → (host, port)."""
    parts = first_line.split()
    if len(parts) < 2:
        return None
    if parts[0].upper() != "CONNECT":
        return None
    target = parts[1]
    if ":" in target:
        host, port_s = target.rsplit(":", 1)
        try:
            return host.strip("[]"), int(port_s)
        except ValueError:
            return None
    return target, 443


async def _drain_headers(reader: asyncio.StreamReader) -> bytes:
    """Читает заголовки до пустой строки CRLF."""
    buf = b""
    while True:
        line = await reader.readline()
        if not line:
            break
        buf += line
        if line in (b"\r\n", b"\n"):
            break
    return buf


async def _relay_counting(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    counter: list[int],
    idx: int,
) -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            counter[idx] += len(chunk)
            writer.write(chunk)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def _host_allowed(host: str, host_filter: str) -> bool:
    if not host_filter:
        return True
    return host_filter.lower() in host.lower()


def rotate_log_files(log_path: Path, max_log_backups: int = 5) -> None:
    """Rotate <log>, <log>.1, ... keeping up to max_log_backups copies."""
    max_log_backups = max(1, int(max_log_backups or 1))
    oldest = log_path.with_name(f"{log_path.name}.{max_log_backups}")
    if oldest.exists():
        oldest.unlink()
    for idx in range(max_log_backups - 1, 0, -1):
        src = log_path.with_name(f"{log_path.name}.{idx}")
        dst = log_path.with_name(f"{log_path.name}.{idx + 1}")
        if src.exists():
            src.replace(dst)
    if log_path.exists():
        log_path.replace(log_path.with_name(f"{log_path.name}.1"))


async def _log_line(
    log_path: Path,
    lock: asyncio.Lock,
    record: dict[str, Any],
    rotate_cb: Any | None = None,
) -> None:
    line = json.dumps(record, ensure_ascii=False) + "\n"
    async with lock:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if callable(rotate_cb):
            rotate_cb()
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line)


def _client_ip(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    if peer and len(peer) >= 1:
        return str(peer[0])
    return "0.0.0.0"


async def _handle_connect(
    first_line: str,
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    log_path: Path,
    log_lock: asyncio.Lock,
    host_filter: str,
    rotate_cb: Any | None = None,
) -> None:
    t0 = time.perf_counter()
    client_ip = _client_ip(client_writer)
    parsed = _parse_connect_target(first_line)
    if not parsed:
        client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await client_writer.drain()
        client_writer.close()
        await client_writer.wait_closed()
        return
    host, port = parsed
    if not _host_allowed(host, host_filter):
        client_writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        await client_writer.drain()
        client_writer.close()
        await client_writer.wait_closed()
        await _log_line(
            log_path,
            log_lock,
            {
                "ts": time.time(),
                "client_ip": client_ip,
                "method": "CONNECT",
                "host": host,
                "port": port,
                "path": "",
                "scheme": "https",
                "status": 403,
                "bytes_up": 0,
                "bytes_down": 0,
                "duration_ms": (time.perf_counter() - t0) * 1000,
                "error": "host_filter",
            },
            rotate_cb=rotate_cb,
        )
        return

    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=30.0,
        )
    except Exception as e:
        client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await client_writer.drain()
        client_writer.close()
        await client_writer.wait_closed()
        await _log_line(
            log_path,
            log_lock,
            {
                "ts": time.time(),
                "client_ip": client_ip,
                "method": "CONNECT",
                "host": host,
                "port": port,
                "path": "",
                "scheme": "https",
                "status": 502,
                "bytes_up": 0,
                "bytes_down": 0,
                "duration_ms": (time.perf_counter() - t0) * 1000,
                "error": str(e),
            },
            rotate_cb=rotate_cb,
        )
        return

    client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await client_writer.drain()

    counts = [0, 0]
    t_relay = time.perf_counter()
    try:
        await asyncio.gather(
            _relay_counting(client_reader, upstream_writer, counts, 0),
            _relay_counting(upstream_reader, client_writer, counts, 1),
        )
    finally:
        dur_ms = (time.perf_counter() - t_relay) * 1000
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except Exception:
            pass
        try:
            upstream_writer.close()
            await upstream_writer.wait_closed()
        except Exception:
            pass
        await _log_line(
            log_path,
            log_lock,
            {
                "ts": time.time(),
                "client_ip": client_ip,
                "method": "CONNECT",
                "host": host,
                "port": port,
                "path": "",
                "scheme": "https",
                "status": 200,
                "bytes_up": counts[0],
                "bytes_down": counts[1],
                "duration_ms": dur_ms,
            },
            rotate_cb=rotate_cb,
        )


def _rewrite_request_line_abs_uri(first_line: str) -> tuple[str, str, int] | None:
    """``GET http://host/path HTTP/1.1`` → (new_first_line, host, port)."""
    parts = first_line.split(None, 2)
    if len(parts) < 2:
        return None
    method, url = parts[0], parts[1]
    if not url.startswith(("http://", "https://")):
        return None
    u = urlparse(url)
    if not u.hostname:
        return None
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path = f"{path}?{u.query}"
    ver = parts[2] if len(parts) > 2 else "HTTP/1.1"
    new_line = f"{method} {path} {ver}"
    return new_line, u.hostname, port


async def _handle_plain_http(
    first_line: str,
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    rest_headers: bytes,
    log_path: Path,
    log_lock: asyncio.Lock,
    host_filter: str,
    rotate_cb: Any | None = None,
) -> None:
    t0 = time.perf_counter()
    client_ip = _client_ip(client_writer)
    rewritten = _rewrite_request_line_abs_uri(first_line.strip())
    if not rewritten:
        client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await client_writer.drain()
        client_writer.close()
        await client_writer.wait_closed()
        return
    new_first, host, port = rewritten
    scheme = "https" if port == 443 else "http"
    path = new_first.split(None, 2)[1] if len(new_first.split(None, 2)) > 1 else "/"

    if not _host_allowed(host, host_filter):
        client_writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        await client_writer.drain()
        client_writer.close()
        await client_writer.wait_closed()
        return

    if port == 443:
        # Без TLS к апстриму не подключиться — клиент должен использовать CONNECT
        client_writer.write(b"HTTP/1.1 501 HTTPS via GET not supported; use CONNECT\r\n\r\n")
        await client_writer.drain()
        client_writer.close()
        await client_writer.wait_closed()
        return

    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=30.0,
        )
    except Exception as e:
        client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await client_writer.drain()
        client_writer.close()
        await client_writer.wait_closed()
        await _log_line(
            log_path,
            log_lock,
            {
                "ts": time.time(),
                "client_ip": client_ip,
                "method": first_line.split(None, 1)[0] if first_line else "GET",
                "host": host,
                "port": port,
                "path": path,
                "scheme": scheme,
                "status": 502,
                "bytes_up": 0,
                "bytes_down": 0,
                "duration_ms": (time.perf_counter() - t0) * 1000,
                "error": str(e),
            },
            rotate_cb=rotate_cb,
        )
        return

    req_head = (new_first + "\r\n").encode("utf-8", errors="replace") + rest_headers
    upstream_writer.write(req_head)
    await upstream_writer.drain()

    counts = [len(req_head), 0]
    status_code = 0
    buf = b""
    while True:
        line = await upstream_reader.readline()
        if not line:
            break
        buf += line
        counts[1] += len(line)
        if line.startswith(b"HTTP/"):
            try:
                status_code = int(line.split(None, 2)[1])
            except (IndexError, ValueError):
                status_code = 0
        if line in (b"\r\n", b"\n"):
            break

    client_writer.write(buf)
    await client_writer.drain()

    async def up_to_client() -> None:
        try:
            while True:
                chunk = await upstream_reader.read(65536)
                if not chunk:
                    break
                counts[1] += len(chunk)
                client_writer.write(chunk)
                await client_writer.drain()
        finally:
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass

    async def client_to_up() -> None:
        try:
            while True:
                chunk = await client_reader.read(65536)
                if not chunk:
                    break
                counts[0] += len(chunk)
                upstream_writer.write(chunk)
                await upstream_writer.drain()
        finally:
            try:
                upstream_writer.close()
                await upstream_writer.wait_closed()
            except Exception:
                pass

    try:
        await asyncio.gather(up_to_client(), client_to_up())
    finally:
        await _log_line(
            log_path,
            log_lock,
            {
                "ts": time.time(),
                "client_ip": client_ip,
                "method": first_line.split(None, 1)[0].strip() if first_line else "GET",
                "host": host,
                "port": port,
                "path": path,
                "scheme": "http",
                "status": status_code,
                "bytes_up": counts[0],
                "bytes_down": counts[1],
                "duration_ms": (time.perf_counter() - t0) * 1000,
            },
            rotate_cb=rotate_cb,
        )


async def _handle_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    log_path: Path,
    log_lock: asyncio.Lock,
    host_filter: str,
    rotate_cb: Any | None = None,
) -> None:
    first_line_b = await client_reader.readline()
    if not first_line_b:
        client_writer.close()
        await client_writer.wait_closed()
        return
    first_line = first_line_b.decode("utf-8", errors="replace").strip()
    rest = await _drain_headers(client_reader)

    if first_line.upper().startswith("CONNECT "):
        await _handle_connect(
            first_line, client_reader, client_writer, log_path, log_lock, host_filter, rotate_cb
        )
        return

    if first_line and " " in first_line:
        parts = first_line.split(None, 2)
        if len(parts) >= 2 and parts[1].startswith(("http://", "https://")):
            await _handle_plain_http(
                first_line, client_reader, client_writer, rest, log_path, log_lock, host_filter, rotate_cb
            )
            return

    client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
    await client_writer.drain()
    client_writer.close()
    await client_writer.wait_closed()


async def run_proxy_server(
    bind_host: str,
    port: int,
    log_path: Path,
    host_filter: str = "",
    max_log_bytes: int = 0,
    max_log_backups: int = 5,
) -> None:
    """
    Запускает TCP-сервер прокси до отмены (Ctrl+C).

    Параметры
    ----------
    bind_host, port
        Адрес прослушивания (обычно 127.0.0.1:8899).
    log_path
        Файл NDJSON (одна JSON-строка на событие).
    host_filter
        Непустая строка: разрешены только хосты, содержащие подстроку (без учёта регистра).
    max_log_bytes
        Если >0, включается ротация NDJSON при превышении размера.
    max_log_backups
        Число ротационных копий proxy_traffic.ndjson.N (по умолчанию 5).
    """
    log_lock = asyncio.Lock()
    log_path = Path(log_path)
    max_log_bytes = max(0, int(max_log_bytes or 0))
    max_log_backups = max(1, int(max_log_backups or 1))

    def _rotate_logs_unlocked() -> None:
        if max_log_bytes <= 0 or not log_path.exists():
            return
        try:
            cur_size = log_path.stat().st_size
        except OSError:
            return
        if cur_size < max_log_bytes:
            return
        try:
            rotate_log_files(log_path, max_log_backups=max_log_backups)
        except OSError:
            # Rotation errors should not break proxy serving path.
            return

    async def on_client(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        try:
            await _handle_client(r, w, log_path, log_lock, host_filter, _rotate_logs_unlocked)
        except Exception:
            try:
                w.close()
                await w.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(on_client, bind_host, port)
    host_str = ", ".join(str(s.getsockname()) for s in server.sockets or [])
    print(f"Прокси слушает {host_str}; лог: {log_path}")
    print("Укажите в системе/браузере HTTP-прокси с этим хостом и портом (HTTPS — через тот же прокси).")
    if host_filter:
        print(f"Фильтр хоста: только совпадения с «{host_filter}».")
    if max_log_bytes > 0:
        print(
            f"Ротация лога включена: max_log_bytes={max_log_bytes}, backups={max_log_backups}."
        )
    async with server:
        await server.serve_forever()
