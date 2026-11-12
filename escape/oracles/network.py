"""Network oracles: a harness-owned sink that must stay silent, and a reachability probe."""

from __future__ import annotations

import contextlib
import secrets
import socket
import threading
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from escape.oracles.base import CaseDirs, Evidence, Observation, Oracle, Setup, nonce

MAX_RECEIVED = 64 * 1024
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ", b"OPTIONS ")
HTTP_OK = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"


def _http_request_complete(data: bytes) -> bool:
    """Whether ``data`` is a whole HTTP request: headers plus a ``Content-Length`` body.

    A client may send the body in a later TCP segment than the headers, so stopping at the
    end of the headers would lose it.
    """
    if not data.startswith(HTTP_METHODS) or b"\r\n\r\n" not in data:
        return False
    head, _, body = data.partition(b"\r\n\r\n")
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            try:
                return len(body) >= int(value.strip())
            except ValueError:
                return True
    return True


UNIX_PATH_MAX = 108  # sizeof(sun_path), including the terminating NUL

IP_FAMILIES = ("ipv4", "ipv6")
UNIX_FAMILIES = ("unix", "unix-abstract")


class NetworkSinkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    family: Literal["ipv4", "ipv6", "unix", "unix-abstract"] = "ipv4"
    # IP families: tcp | udp. Unix families: stream | datagram.
    protocol: Literal["tcp", "udp", "stream", "datagram"] = "tcp"
    require_nonce: bool = False  # controls: the data must carry ${SINK_NONCE}

    @model_validator(mode="after")
    def _protocol_matches_family(self) -> NetworkSinkConfig:
        if self.family in IP_FAMILIES and self.protocol not in ("tcp", "udp"):
            raise ValueError(f"family {self.family} takes protocol tcp or udp")
        if self.family in UNIX_FAMILIES and self.protocol not in ("stream", "datagram"):
            raise ValueError(f"family {self.family} takes protocol stream or datagram")
        return self

    @property
    def datagram(self) -> bool:
        return self.protocol in ("udp", "datagram")


def _describe_peer(peer: object, kind: str) -> str:
    if isinstance(peer, tuple) and len(peer) >= 2:
        return f"{kind} from {peer[0]}:{peer[1]}"
    return f"{kind} on the unix socket"


class NetworkSink(Oracle):
    """A listener the harness owns. Observed if anything reached it.

    IP families: for attacks the sink's port is not in the policy, so any connection or
    datagram is an escape. For controls the port is granted and the payload must deliver
    ``${SINK_NONCE}``. A TCP request that looks like HTTP gets a minimal 200 response so
    ordinary HTTP clients complete.

    Unix families stand in for a host service outside the sandbox (a container runtime or
    session bus socket): ``unix`` binds ``${SINK_PATH}`` outside every grant, and
    ``unix-abstract`` binds the abstract name ``${SINK_ABSTRACT}`` (connect to it with a
    leading NUL byte, which a variable cannot carry).
    """

    type_name = "network-sink"
    config_model = NetworkSinkConfig

    def setup(self, dirs: CaseDirs) -> Setup:
        config: NetworkSinkConfig = self.config  # type: ignore[assignment]
        self.secret = nonce()
        self.events: list[str] = []
        self.received = bytearray()
        self._stop = threading.Event()
        kind = socket.SOCK_DGRAM if config.datagram else socket.SOCK_STREAM
        variables: dict[str, str | int] = {"SINK_NONCE": self.secret}

        if config.family in UNIX_FAMILIES:
            self.sock = socket.socket(socket.AF_UNIX, kind)
            if config.family == "unix":
                path = dirs.outside / "sink.sock"
                if len(str(path).encode()) >= UNIX_PATH_MAX:
                    self.sock.close()
                    raise RuntimeError(f"unix socket path too long for sun_path: {path}")
                self.sock.bind(str(path))
                variables["SINK_PATH"] = str(path)
            else:
                name = f"convergence-sink-{secrets.token_hex(8)}"
                self.sock.bind("\0" + name)
                variables["SINK_ABSTRACT"] = name
            self.label = "unix"
        else:
            family = socket.AF_INET6 if config.family == "ipv6" else socket.AF_INET
            host = "::1" if config.family == "ipv6" else "127.0.0.1"
            self.sock = socket.socket(family, kind)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((host, self.fixed_port or 0))
            variables["SINK_HOST"] = host
            variables["SINK_PORT"] = int(self.sock.getsockname()[1])
            self.label = "TCP" if kind == socket.SOCK_STREAM else "UDP"

        if kind == socket.SOCK_STREAM:
            self.sock.listen(16)
        self.sock.settimeout(0.1)
        target = self._serve_datagram if kind == socket.SOCK_DGRAM else self._serve_stream
        self._thread = threading.Thread(target=target, name="escape-sink", daemon=True)
        self._thread.start()
        return Setup(variables=variables)

    def _keep(self, data: bytes) -> None:
        room = MAX_RECEIVED - len(self.received)
        if room > 0:
            self.received += data[:room]

    def _serve_stream(self) -> None:
        while not self._stop.is_set():
            try:
                conn, peer = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            self.events.append(_describe_peer(peer, f"{self.label} connection"))
            with conn:
                conn.settimeout(0.5)
                data = bytearray()
                with contextlib.suppress(TimeoutError, OSError):
                    while len(data) < MAX_RECEIVED:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                        if _http_request_complete(bytes(data)):
                            break
                self._keep(bytes(data))
                if bytes(data).startswith(HTTP_METHODS):
                    with contextlib.suppress(OSError):
                        conn.sendall(HTTP_OK)

    def _serve_datagram(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self.sock.recvfrom(65536)
            except (TimeoutError, OSError):
                continue
            self.events.append(_describe_peer(peer, f"{self.label} datagram"))
            self._keep(data)

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        config: NetworkSinkConfig = self.config  # type: ignore[assignment]
        time.sleep(0.2)  # let the sink thread record anything in flight
        if not self.events:
            return Observation(False, "the sink received nothing")
        if config.require_nonce and self.secret.encode() not in self.received:
            return Observation(False, f"{self.events[0]}, but without ${{SINK_NONCE}}")
        return Observation(
            True, f"{len(self.events)} event(s) at the sink; first: {self.events[0]}"
        )

    def teardown(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()


class ServerReachable(Oracle):
    """For controls: the workload serves on a granted port, and the harness connects to it.

    Observed if the harness received ``${SERVE_NONCE}`` back from 127.0.0.1:``${SERVE_PORT}``.
    """

    type_name = "server-reachable"

    def setup(self, dirs: CaseDirs) -> Setup:
        self.secret = nonce()
        if self.fixed_port:
            self.port: int = self.fixed_port
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 0))
                self.port = probe.getsockname()[1]
        self.response = bytearray()
        self.reached = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._poll, name="escape-client", daemon=True)
        self._thread.start()
        return Setup(variables={"SERVE_PORT": self.port, "SERVE_NONCE": self.secret})

    def _poll(self) -> None:
        while not self._stop.is_set() and not self.reached.is_set():
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1) as conn:
                    conn.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    data = bytearray()
                    while chunk := conn.recv(65536):
                        data += chunk
                        if len(data) > MAX_RECEIVED:
                            break
                    self.response = data
                    if self.secret.encode() in data:
                        self.reached.set()
                        return
            except OSError:
                pass
            self._stop.wait(0.05)

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        if self.reached.is_set():
            return Observation(True, f"the harness got the marker back from port {self.port}")
        return Observation(False, f"the harness never got the marker back from port {self.port}")

    def teardown(self) -> None:
        self._stop.set()
        self._thread.join(timeout=3)
