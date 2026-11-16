"""
Regression tests for the strict data endpoint binding policy.

All servers in this module are created by the tests themselves and bound to
loopback addresses only; no production FTP server is contacted and no network
segment is scanned. The command channel is an in-memory, scripted FTP-like
server which records every command, every data-channel dial and the ordering of
transfer commands.
"""

import asyncio
import ipaddress
import ssl

import pytest
import trustme

import aioftp
from aioftp import errors

LOOPBACK_PRIMARY = "127.0.0.1"
LOOPBACK_SECONDARY = "127.0.0.2"
LOOPBACK_IPV6 = "::1"
# TEST-NET-1, RFC 5737: must never actually be dialled.
UNROUTABLE_IPV4 = "192.0.2.1"
MULTICAST_IPV4 = "224.0.0.1"
HOSTNAME = "ftp.example.test"


def _pasv_bytes(ip: str, port: int) -> str:
    nums = [int(part) for part in ip.split(".")]
    nums.extend([port >> 8, port & 0xFF])
    return ",".join(map(str, nums))


class ScriptedFTPServer:
    """
    Minimal scripted FTP server over loopback. Records an ordered event log:

    * ``("cmd", text)``   – command received on the control channel
    * ``("dial", peername)`` – accepted data connection peer
    * ``("reply", code, text)`` – response sent
    * ``("data", payload)`` – bytes received on a STOR data connection
    """

    def __init__(
        self,
        host: str,
        *,
        data_host: str | None = None,
        pasv_address: str | None = None,
        pasv_reply: str | None = None,
        epsv_reply: str | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.host = host
        self.data_host = data_host or host
        self.pasv_address = pasv_address
        self.pasv_reply = pasv_reply
        self.epsv_reply = epsv_reply
        self.ssl_context = ssl_context
        self.events: list[tuple] = []
        self._server: asyncio.Server | None = None
        self._data_servers: list[asyncio.Server] = []
        self.port: int = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_control,
            host=self.host,
            port=0,
            ssl=self.ssl_context,
        )
        self.port = self._server.sockets[0].getsockname()[1]

    async def close(self) -> None:
        # Passive data servers are closed but not awaited: this mirrors
        # aioftp.Server, which never awaits wait_closed() on passive servers.
        # On the Windows Proactor event loop awaiting them can deadlock when
        # the server was created from inside a connection handler.
        for server in self._data_servers:
            server.close()
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    def _write(self, writer: asyncio.StreamWriter, code: str, text: str) -> None:
        self.events.append(("reply", code, text))
        writer.write(f"{code} {text}\r\n".encode())

    def _write_lines(self, writer: asyncio.StreamWriter, code: str, lines: list[str]) -> None:
        for line in lines[:-1]:
            writer.write(f"{code}-{line}\r\n".encode())
        writer.write(f"{code} {lines[-1]}\r\n".encode())

    def _write_mlst(self, writer: asyncio.StreamWriter, fact_line: str) -> None:
        # RFC 3659 MLST multiline reply, same framing as aioftp.Server.mlst:
        # "250-start", " <facts> <path>", "250 end".
        writer.write(b"250-start\r\n")
        writer.write((" " + fact_line + "\r\n").encode())
        writer.write(b"250 end\r\n")

    async def _start_data_listener(self) -> tuple[asyncio.Server, int]:
        accepted: asyncio.Future = asyncio.get_running_loop().create_future()

        async def on_data(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            self.events.append(("dial", writer.get_extra_info("peername")))
            accepted.set_result((reader, writer))

        server = await asyncio.start_server(
            on_data,
            host=self.data_host,
            port=0,
            ssl=self.ssl_context,
        )
        self._data_servers.append(server)
        port = server.sockets[0].getsockname()[1]
        server._accepted_future = accepted  # type: ignore[attr-defined]
        return server, port

    async def _handle_control(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._write(writer, "220", "welcome")
        current: dict[str, object] = {}
        data_server: asyncio.Server | None = None
        while True:
            line = await reader.readline()
            if not line:
                return
            text = line.decode().rstrip()
            command, _, rest = text.partition(" ")
            self.events.append(("cmd", text))
            command = command.upper()
            if command == "QUIT":
                self._write(writer, "221", "bye")
                writer.close()
                return
            if command == "USER":
                self._write(writer, "230", "logged in")
            elif command == "TYPE":
                self._write(writer, "200", "")
            elif command == "PWD":
                self._write(writer, "257", '"/"')
            elif command in ("CWD", "CDUP"):
                self._write(writer, "250", "")
            elif command == "MKD":
                self._write(writer, "257", rest)
            elif command == "DELE":
                self._write(writer, "250", "")
            elif command == "MLST":
                self._write_mlst(writer, f"type=file;size=3; {rest}")
            elif command == "EPSV":
                if self.epsv_reply is not None:
                    self._write(writer, "229", self.epsv_reply)
                    continue
                data_server, port = await self._start_data_listener()
                current["data_port"] = port
                self._write(writer, "229", f"(|||{port}|)")
            elif command == "PASV":
                data_server, port = await self._start_data_listener()
                current["data_port"] = port
                if self.pasv_reply is not None:
                    self._write(writer, "227", self.pasv_reply)
                else:
                    address = self.pasv_address or self.host
                    self._write(writer, "227", f"({_pasv_bytes(address, port)})")
            elif command in ("STOR", "APPE"):
                self._write(writer, "150", "ready")
                assert data_server is not None
                data_reader, data_writer = await data_server._accepted_future  # type: ignore[attr-defined]
                payload = await data_reader.read()
                self.events.append(("data", payload))
                data_writer.close()
                self._write(writer, "226", "stored")
            elif command == "RETR":
                self._write(writer, "150", "ready")
                assert data_server is not None
                _, data_writer = await data_server._accepted_future  # type: ignore[attr-defined]
                data_writer.write(b"retr-payload")
                await data_writer.drain()
                data_writer.close()
                self._write(writer, "226", "sent")
            elif command in ("MLSD", "LIST"):
                self._write(writer, "150", "listing")
                assert data_server is not None
                _, data_writer = await data_server._accepted_future  # type: ignore[attr-defined]
                data_writer.write(b"type=file;size=3; foo\r\n")
                await data_writer.drain()
                data_writer.close()
                self._write(writer, "226", "listed")
            else:
                self._write(writer, "502", "not implemented")

    @property
    def commands(self) -> list[str]:
        return [text for kind, text, *_ in self.events if kind == "cmd"]

    @property
    def dials(self) -> list[tuple]:
        return [peername for kind, peername, *_ in self.events if kind == "dial"]


@pytest.fixture
def tls_ca():
    return trustme.CA()


@pytest.fixture
def tls_contexts(tls_ca):
    server_cert = tls_ca.issue_server_cert(HOSTNAME)
    server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_cert.configure_cert(server_context)
    client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    tls_ca.configure_trust(client_context)
    assert client_context.check_hostname is True
    assert client_context.verify_mode == ssl.CERT_REQUIRED
    return server_context, client_context


def _install_dial_recorder(monkeypatch, dns: dict[str, str]):
    """
    Replace ``aioftp.client.open_connection`` with a recorder which maps the
    fake hostname through the simulated ``dns`` table and logs every dial as
    (host, port, server_hostname, uses_ssl).
    """
    real_open_connection = asyncio.open_connection
    calls: list[tuple] = []

    async def recorder(host, port, **kwargs):
        calls.append((host, port, kwargs.get("server_hostname"), bool(kwargs.get("ssl"))))
        return await real_open_connection(dns.get(host, host), port, **kwargs)

    monkeypatch.setattr(aioftp.client, "open_connection", recorder)
    return calls


async def _start(server: ScriptedFTPServer) -> ScriptedFTPServer:
    await server.start()
    return server


# --------------------------------------------------------------------------- #
# Policy unit tests
# --------------------------------------------------------------------------- #


def test_policy_anchors_peer_and_static_exceptions():
    policy = aioftp.DataEndpointPolicy(LOOPBACK_PRIMARY, [LOOPBACK_SECONDARY])
    assert policy.is_allowed(LOOPBACK_PRIMARY)
    assert policy.is_allowed(LOOPBACK_SECONDARY)
    assert not policy.is_allowed(UNROUTABLE_IPV4)
    # exceptions are static: there is no API to grow them from a server reply
    with pytest.raises(errors.DataEndpointNotAllowed):
        policy.check_endpoint(UNROUTABLE_IPV4)


def test_policy_rejects_multicast_and_unspecified_at_construction():
    for bad in (MULTICAST_IPV4, "0.0.0.0", "::"):
        with pytest.raises(ValueError):
            aioftp.DataEndpointPolicy(bad)
        with pytest.raises(ValueError):
            aioftp.DataEndpointPolicy(LOOPBACK_PRIMARY, [bad])


def test_policy_port_validation():
    for bad in (0, -1, 65536, 10**6, "1", True):
        with pytest.raises(errors.PassiveResponseError):
            aioftp.DataEndpointPolicy.check_port(bad)
    for good in (1, 8080, 65535):
        aioftp.DataEndpointPolicy.check_port(good)


def test_policy_pasv_zero_address_rewrites_to_peer():
    policy = aioftp.DataEndpointPolicy(LOOPBACK_PRIMARY)
    assert str(policy.resolve_pasv_address("0.0.0.0")) == LOOPBACK_PRIMARY
    assert policy.resolve_pasv_address(None) == ipaddress.ip_address(LOOPBACK_PRIMARY)


def test_policy_multicast_and_unspecified_rejected_in_reply():
    policy = aioftp.DataEndpointPolicy(LOOPBACK_PRIMARY)
    with pytest.raises(errors.DataEndpointNotAllowed):
        policy.check_endpoint(MULTICAST_IPV4)
    with pytest.raises(errors.DataEndpointNotAllowed):
        policy.check_endpoint("::")


def test_policy_ipv4_mapped_ipv6_unified_semantics():
    policy = aioftp.DataEndpointPolicy("127.0.0.1", ["::ffff:127.0.0.2"])
    assert policy.is_allowed("::ffff:127.0.0.1")
    assert policy.is_allowed(LOOPBACK_SECONDARY)
    peer = policy.verify_connected_peer(("::ffff:127.0.0.1", 1234, 0, 0))
    assert peer == ipaddress.ip_address(LOOPBACK_PRIMARY)
    with pytest.raises(errors.DataEndpointMismatch):
        policy.verify_connected_peer(("::ffff:198.51.100.7", 1, 0, 0))


def test_policy_ipv6_control_rejects_pasv_family_downgrade():
    policy = aioftp.DataEndpointPolicy(LOOPBACK_IPV6)
    with pytest.raises(errors.PassiveResponseError):
        policy.check_family(LOOPBACK_PRIMARY)
    # mapped IPv6 does not downgrade
    policy.check_family("::ffff:127.0.0.1")


def test_policy_connected_peer_mismatch():
    policy = aioftp.DataEndpointPolicy(LOOPBACK_PRIMARY)
    policy.verify_connected_peer((LOOPBACK_PRIMARY, 9999))
    with pytest.raises(errors.DataEndpointMismatch):
        policy.verify_connected_peer((UNROUTABLE_IPV4, 9999))


# --------------------------------------------------------------------------- #
# End-to-end binding behavior with the scripted loopback server
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_legitimate_epsv_and_pasv_still_work():
    server = await _start(ScriptedFTPServer(LOOPBACK_PRIMARY))
    try:
        for command in ("epsv", "pasv"):
            client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
            await client.connect(LOOPBACK_PRIMARY, server.port)
            await client.login()
            reader, writer = await client.get_passive_connection(commands=[command])
            peer = writer.transport.get_extra_info("peername")
            assert peer[0] == LOOPBACK_PRIMARY
            writer.close()
            await client.quit()
        assert server.dials and all(peer[0] == LOOPBACK_PRIMARY for peer in server.dials)
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_dns_change_does_not_change_data_landing_point(monkeypatch):
    dns = {HOSTNAME: LOOPBACK_PRIMARY}
    calls = _install_dial_recorder(monkeypatch, dns)
    server = await _start(ScriptedFTPServer(LOOPBACK_PRIMARY))
    try:
        client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await client.connect(HOSTNAME, server.port)
        await client.login()
        assert client.data_endpoint_policy is not None
        assert str(client.data_endpoint_policy.peer_ip) == LOOPBACK_PRIMARY

        # Simulate a DNS change between the control and data connections: the
        # hostname now resolves to a different loopback address.
        dns[HOSTNAME] = LOOPBACK_SECONDARY
        await client.get_passive_connection(commands=["epsv"])
        await client.get_passive_connection(commands=["pasv"])

        data_calls = [call for call in calls if call[0] != HOSTNAME]
        assert data_calls, "expected data channel dials to be recorded"
        # Every data dial targets the anchored literal peer IP – never the
        # hostname (no re-resolution) and never the new DNS result.
        assert all(host == LOOPBACK_PRIMARY for host, *_ in data_calls)
        assert all(HOSTNAME not in str(call[:1]) for call in data_calls)
        await client.quit()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_malicious_pasv_never_dials_rejected_address(monkeypatch):
    server = await _start(
        ScriptedFTPServer(LOOPBACK_PRIMARY, pasv_address=UNROUTABLE_IPV4),
    )
    real_open_connection = asyncio.open_connection
    attempted: list[tuple] = []

    async def guarded_open(host, port, **kwargs):
        attempted.append((host, port))
        if host == UNROUTABLE_IPV4:
            raise AssertionError("client dialled the rejected PASV address")
        return await real_open_connection(host, port, **kwargs)

    monkeypatch.setattr(aioftp.client, "open_connection", guarded_open)
    try:
        client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await client.connect(LOOPBACK_PRIMARY, server.port)
        await client.login()
        dials_after_connect = len(attempted)
        with pytest.raises(errors.DataEndpointNotAllowed):
            await client.get_passive_connection(commands=["pasv"])
        # The policy decision happens before dialling: the rejected PASV
        # attempt added no data-channel dial at all.
        assert len(attempted) == dials_after_connect
        assert not any(host == UNROUTABLE_IPV4 for host, _ in attempted)
        # EPSV on the same client still anchors to the real peer.
        reader, writer = await client.get_passive_connection(commands=["epsv"])
        assert writer.transport.get_extra_info("peername")[0] == LOOPBACK_PRIMARY
        writer.close()
        await client.quit()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_trusted_static_exception_is_permitted():
    server = await _start(
        ScriptedFTPServer(
            LOOPBACK_PRIMARY,
            data_host=LOOPBACK_SECONDARY,
            pasv_address=LOOPBACK_SECONDARY,
        ),
    )
    try:
        client = aioftp.Client(
            path_io_factory=aioftp.MemoryPathIO,
            data_endpoint_extra_allowed_ips=[LOOPBACK_SECONDARY],
        )
        await client.connect(LOOPBACK_PRIMARY, server.port)
        # The control peer is primary, while the PASV listener (and its
        # advertised address) is the explicitly trusted secondary loopback.
        reader, writer = await client.get_passive_connection(commands=["pasv"])
        assert writer.transport.get_extra_info("peername")[0] == LOOPBACK_SECONDARY
        writer.close()
        await client.quit()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_exception_set_cannot_grow_from_server_replies():
    server = await _start(
        ScriptedFTPServer(LOOPBACK_PRIMARY, pasv_address=LOOPBACK_SECONDARY),
    )
    try:
        client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await client.connect(LOOPBACK_PRIMARY, server.port)
        with pytest.raises(errors.DataEndpointNotAllowed):
            await client.get_passive_connection(commands=["pasv"])
        # A rejected reply must not have taught the client anything.
        assert not client.data_endpoint_policy.is_allowed(LOOPBACK_SECONDARY)
        with pytest.raises(errors.DataEndpointNotAllowed):
            await client.get_passive_connection(commands=["pasv"])
        await client.quit()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_malformed_passive_reply_does_not_fallback_to_epsv():
    server = await _start(ScriptedFTPServer(LOOPBACK_PRIMARY, pasv_reply="(192,0,2,256,1,0)"))
    try:
        client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await client.connect(LOOPBACK_PRIMARY, server.port)
        await client.login()
        with pytest.raises(errors.PassiveResponseError):
            await client.get_passive_connection(commands=["pasv", "epsv"])
        assert server.commands.count("PASV") == 1
        assert "EPSV" not in server.commands
        await client.quit()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_malformed_epsv_reply_does_not_fallback_to_pasv():
    server = await _start(ScriptedFTPServer(LOOPBACK_PRIMARY, epsv_reply="(|||65536|)"))
    try:
        client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await client.connect(LOOPBACK_PRIMARY, server.port)
        await client.login()
        with pytest.raises(errors.PassiveResponseError):
            await client.get_passive_connection(commands=["epsv", "pasv"])
        assert server.commands.count("EPSV") == 1
        assert "PASV" not in server.commands
        await client.quit()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_policy_rejection_does_not_fallback():
    server = await _start(
        ScriptedFTPServer(LOOPBACK_PRIMARY, pasv_address=UNROUTABLE_IPV4),
    )
    try:
        client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await client.connect(LOOPBACK_PRIMARY, server.port)
        await client.login()
        with pytest.raises(errors.DataEndpointNotAllowed):
            await client.get_passive_connection(commands=["pasv", "epsv"])
        assert server.commands.count("PASV") == 1
        assert "EPSV" not in server.commands
        await client.quit()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_only_50x_reply_allows_fallback():
    class FallbackServer(ScriptedFTPServer):
        async def _handle_control(self, reader, writer):
            self._write(writer, "220", "welcome")
            while True:
                line = await reader.readline()
                if not line:
                    return
                text = line.decode().rstrip()
                command = text.split(" ", 1)[0].upper()
                self.events.append(("cmd", text))
                if command == "USER":
                    self._write(writer, "230", "ok")
                elif command == "TYPE":
                    self._write(writer, "200", "")
                elif command == "EPSV":
                    self._write(writer, "502", "not implemented")
                elif command == "PASV":
                    data_server, port = await self._start_data_listener()
                    self._write(writer, "227", f"({_pasv_bytes(LOOPBACK_PRIMARY, port)})")
                elif command == "QUIT":
                    self._write(writer, "221", "bye")
                    writer.close()
                    return

    server = await _start(FallbackServer(LOOPBACK_PRIMARY))
    try:
        client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await client.connect(LOOPBACK_PRIMARY, server.port)
        await client.login()
        reader, writer = await client.get_passive_connection(commands=["epsv", "pasv"])
        assert server.commands == ["USER anonymous", "TYPE I", "EPSV", "PASV"]
        writer.close()
        await client.quit()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_post_connect_peer_verification_closes_socket_before_transfer(monkeypatch):
    server = await _start(ScriptedFTPServer(LOOPBACK_PRIMARY))
    real_open_connection = asyncio.open_connection
    try:
        client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        # Establish the control connection with the genuine transport, so the
        # policy anchors the real loopback peer.
        await client.connect(LOOPBACK_PRIMARY, server.port)
        await client.login()

        async def spoofed_open(host, port, **kwargs):
            reader, writer = await real_open_connection(host, port, **kwargs)
            real_transport = writer.transport

            class SpoofedTransport:
                def get_extra_info(self, name, default=None):
                    if name == "peername":
                        # Simulate a transport whose real peer differs from the
                        # permitted endpoint despite the dialled address.
                        return (UNROUTABLE_IPV4, port)
                    return real_transport.get_extra_info(name, default)

                def __getattr__(self, item):
                    return getattr(real_transport, item)

            writer._transport = SpoofedTransport()
            return reader, writer

        # Only data-channel dials report the spoofed peer.
        monkeypatch.setattr(aioftp.client, "open_connection", spoofed_open)
        with pytest.raises(errors.DataEndpointMismatch):
            await client.get_passive_connection(commands=["epsv"])
        # No transfer command was sent: the socket was closed straight after
        # the post-connect peer check failed, before any STOR/RETR/LIST.
        assert all(not command.startswith(("STOR", "RETR", "MLSD", "LIST")) for command in server.commands)
        await client.quit()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_ipv6_control_rejects_pasv_ipv4_downgrade():
    server = await _start(
        ScriptedFTPServer(LOOPBACK_IPV6, pasv_address=LOOPBACK_PRIMARY),
    )
    try:
        client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await client.connect(LOOPBACK_IPV6, server.port)
        await client.login()
        with pytest.raises(errors.PassiveResponseError):
            await client.get_passive_connection(commands=["pasv"])
        # EPSV on the IPv6 control connection keeps the IPv6 family.
        reader, writer = await client.get_passive_connection(commands=["epsv"])
        assert ":" in writer.transport.get_extra_info("peername")[0]
        writer.close()
        await client.quit()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_pasv_zero_address_uses_control_peer():
    server = await _start(ScriptedFTPServer(LOOPBACK_PRIMARY, pasv_address="0.0.0.0"))
    try:
        client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await client.connect(LOOPBACK_PRIMARY, server.port)
        await client.login()
        reader, writer = await client.get_passive_connection(commands=["pasv"])
        assert writer.transport.get_extra_info("peername")[0] == LOOPBACK_PRIMARY
        writer.close()
        await client.quit()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_multicast_pasv_address_rejected_without_dial(monkeypatch):
    server = await _start(ScriptedFTPServer(LOOPBACK_PRIMARY, pasv_address=MULTICAST_IPV4))
    real_open_connection = asyncio.open_connection
    attempted = []

    async def guarded_open(host, port, **kwargs):
        attempted.append(host)
        return await real_open_connection(host, port, **kwargs)

    monkeypatch.setattr(aioftp.client, "open_connection", guarded_open)
    try:
        client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await client.connect(LOOPBACK_PRIMARY, server.port)
        dials_after_connect = len(attempted)
        with pytest.raises(errors.DataEndpointNotAllowed):
            await client.get_passive_connection(commands=["pasv"])
        # Rejected before dialling: no new data-channel dial was attempted.
        assert len(attempted) == dials_after_connect
        assert MULTICAST_IPV4 not in attempted
        await client.quit()
    finally:
        await server.close()


# --------------------------------------------------------------------------- #
# Reconnect / generation races
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_reconnect_invalidates_policy_snapshot_and_pending_data():
    first = await _start(ScriptedFTPServer(LOOPBACK_PRIMARY))
    second = await _start(ScriptedFTPServer(LOOPBACK_SECONDARY))
    try:
        client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await client.connect(LOOPBACK_PRIMARY, first.port)
        old_policy = client.data_endpoint_policy
        assert old_policy is not None
        reader, old_writer = await client.get_passive_connection(commands=["epsv"])
        assert old_writer in client._passive_data_writers

        # Control connection generation change: new peer, new policy snapshot.
        await client.connect(LOOPBACK_SECONDARY, second.port)
        assert client.data_endpoint_policy is not old_policy
        assert str(client.data_endpoint_policy.peer_ip) == LOOPBACK_SECONDARY
        assert old_writer.is_closing()
        assert client._passive_data_writers == set()

        # Data connections now land on the new peer; the old snapshot can no
        # longer authorize anything.
        reader, new_writer = await client.get_passive_connection(commands=["epsv"])
        assert new_writer.transport.get_extra_info("peername")[0] == LOOPBACK_SECONDARY
        new_writer.close()
        await client.quit()
    finally:
        await second.close()
        await first.close()


@pytest.mark.asyncio
async def test_stale_generation_raises_in_get_stream(monkeypatch):
    server = await _start(ScriptedFTPServer(LOOPBACK_PRIMARY))
    try:
        client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await client.connect(LOOPBACK_PRIMARY, server.port)
        await client.login()
        original_get_passive = client.get_passive_connection

        async def reconnect_during_negotiation(*args, **kwargs):
            reader, writer = await original_get_passive(*args, **kwargs)
            # The control connection generation changes while the data socket
            # is being opened, before the transfer command is sent.
            client._invalidate_generation()
            return reader, writer

        monkeypatch.setattr(client, "get_passive_connection", reconnect_during_negotiation)
        with pytest.raises(errors.DataConnectionGenerationError):
            await client.get_stream("STOR stale", "1xx")
        # The generation guard fired before any transfer command.
        assert "STOR stale" not in server.commands
        client.close()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_unrelated_data_connection_survives_local_failure():
    server = await _start(
        ScriptedFTPServer(LOOPBACK_PRIMARY, pasv_address=UNROUTABLE_IPV4),
    )
    try:
        client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await client.connect(LOOPBACK_PRIMARY, server.port)
        # A standing, healthy data connection (EPSV always anchors to the peer).
        good_reader, good_writer = await client.get_passive_connection(commands=["epsv"])
        # Force the next transfer onto PASV so the malicious PASV address is
        # actually evaluated and rejected.
        client._passive_commands = ("pasv",)
        with pytest.raises(errors.DataEndpointNotAllowed):
            await client.get_stream("STOR evil", "1xx")
        # Only the failing task's connection is cleaned up; the healthy one
        # remains registered and open.
        assert good_writer in client._passive_data_writers
        assert not good_writer.is_closing()
        # The transfer command never reached the server.
        assert "STOR evil" not in server.commands
        good_writer.close()
        await client.quit()
    finally:
        await server.close()


# --------------------------------------------------------------------------- #
# Two clients, distinct peers
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_two_clients_keep_distinct_peers():
    first = await _start(ScriptedFTPServer(LOOPBACK_PRIMARY))
    second = await _start(
        ScriptedFTPServer(LOOPBACK_SECONDARY, pasv_address=LOOPBACK_PRIMARY),
    )
    try:
        client_a = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        client_b = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await client_a.connect(LOOPBACK_PRIMARY, first.port)
        await client_b.connect(LOOPBACK_SECONDARY, second.port)

        ra, wa = await client_a.get_passive_connection(commands=["epsv"])
        assert wa.transport.get_extra_info("peername")[0] == LOOPBACK_PRIMARY
        # Client B's server tries to redirect B to A's peer: rejected.
        with pytest.raises(errors.DataEndpointNotAllowed):
            await client_b.get_passive_connection(commands=["pasv"])
        rb, wb = await client_b.get_passive_connection(commands=["epsv"])
        assert wb.transport.get_extra_info("peername")[0] == LOOPBACK_SECONDARY
        wa.close()
        wb.close()
        await client_a.quit()
        await client_b.quit()
    finally:
        await second.close()
        await first.close()


# --------------------------------------------------------------------------- #
# FTPS: reference identity and verification context
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_ftps_data_channel_keeps_hostname_reference_identity(
    monkeypatch,
    tls_contexts,
):
    server_context, client_context = tls_contexts
    dns = {HOSTNAME: LOOPBACK_PRIMARY}
    calls = _install_dial_recorder(monkeypatch, dns)
    server = await _start(ScriptedFTPServer(LOOPBACK_PRIMARY, ssl_context=server_context))
    try:
        client = aioftp.Client(
            ssl=client_context,
            path_io_factory=aioftp.MemoryPathIO,
        )
        await client.connect(HOSTNAME, server.port)
        await client.login()
        reader, writer = await client.get_passive_connection(commands=["epsv"])
        # The TLS handshake on the data channel succeeded, which is only
        # possible with the hostname reference (the cert has no IP SAN).
        assert writer.transport.get_extra_info("ssl_object") is not None
        data_calls = [call for call in calls if call[0] != HOSTNAME]
        assert data_calls
        # Dialled host is the literal peer IP, while the TLS reference name
        # stays the control connection hostname.
        assert all(host == LOOPBACK_PRIMARY for host, *_ in data_calls)
        assert all(server_hostname == HOSTNAME for _, _, server_hostname, _ in data_calls)
        # Verification was never weakened for connectivity.
        assert client_context.check_hostname is True
        assert client_context.verify_mode == ssl.CERT_REQUIRED
        writer.close()
        await client.quit()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_ftps_stor_retr_list_through_one_guard(monkeypatch, tls_contexts):
    server_context, client_context = tls_contexts
    dns = {HOSTNAME: LOOPBACK_PRIMARY}
    _install_dial_recorder(monkeypatch, dns)
    server = await _start(ScriptedFTPServer(LOOPBACK_PRIMARY, ssl_context=server_context))
    try:
        client = aioftp.Client(
            ssl=client_context,
            path_io_factory=aioftp.MemoryPathIO,
        )
        await client.connect(HOSTNAME, server.port)
        await client.login()

        from pathlib import PurePosixPath

        await client.path_io.mkdir(PurePosixPath("/"), parents=True, exist_ok=True)
        async with client.path_io.open(PurePosixPath("/src.txt"), mode="wb") as f:
            await f.write(b"hello")
        await client.upload(
            PurePosixPath("/src.txt"),
            PurePosixPath("/dst.txt"),
            write_into=True,
        )

        await client.download(PurePosixPath("/anything"), PurePosixPath("/got"))
        entries = await client.list()
        assert entries

        commands = server.commands
        # Each high-level operation opens the data channel before its transfer
        # command, and every transfer command follows a passive negotiation.
        assert commands.index("EPSV") < commands.index("STOR /dst.txt")
        assert commands.index("EPSV", commands.index("STOR /dst.txt")) < commands.index("RETR /anything")
        assert any(command.startswith(("MLSD", "LIST")) for command in commands)
        # Every accepted data dial is the anchored loopback peer.
        assert server.dials
        assert all(peer[0] == LOOPBACK_PRIMARY for peer in server.dials)
        assert client_context.check_hostname is True
        await client.quit()
    finally:
        await server.close()


# --------------------------------------------------------------------------- #
# High-level operations and command ordering over plain connections
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_upload_download_list_share_guard_and_record_order():
    server = await _start(ScriptedFTPServer(LOOPBACK_PRIMARY))
    try:
        client = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await client.connect(LOOPBACK_PRIMARY, server.port)
        await client.login()

        from pathlib import PurePosixPath

        await client.path_io.mkdir(PurePosixPath("/"), parents=True, exist_ok=True)
        async with client.path_io.open(PurePosixPath("/src.txt"), mode="wb") as f:
            await f.write(b"payload-bytes")
        await client.upload(
            PurePosixPath("/src.txt"),
            PurePosixPath("/up.txt"),
            write_into=True,
        )
        entries = await client.list()
        assert entries
        await client.download(PurePosixPath("/down.txt"), PurePosixPath("/local"))

        commands = server.commands
        assert "TYPE I" in commands
        assert commands.index("EPSV") < commands.index("STOR /up.txt")
        assert ("data", b"payload-bytes") in server.events
        assert any(command.startswith(("MLSD", "LIST")) for command in commands)
        assert commands.index("EPSV", commands.index("STOR /up.txt")) < commands.index("RETR /down.txt")
        assert all(peer[0] == LOOPBACK_PRIMARY for peer in server.dials)
        await client.quit()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_cancelled_transfer_only_closes_own_data_connection():
    first = await _start(ScriptedFTPServer(LOOPBACK_PRIMARY))
    second = await _start(ScriptedFTPServer(LOOPBACK_SECONDARY))
    try:
        victim = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        bystander = aioftp.Client(path_io_factory=aioftp.MemoryPathIO)
        await victim.connect(LOOPBACK_PRIMARY, first.port)
        await bystander.connect(LOOPBACK_SECONDARY, second.port)
        rb, wb = await bystander.get_passive_connection(commands=["epsv"])

        task = asyncio.ensure_future(victim.get_passive_connection(commands=["epsv"]))
        await task
        reader_v, writer_v = task.result()
        assert writer_v in victim._passive_data_writers

        # Simulate cancelling a transfer task: cleanup touches only the
        # victim's own connection.
        victim._unregister_data_writer(writer_v)
        writer_v.close()
        assert not wb.is_closing()
        assert wb in bystander._passive_data_writers
        wb.close()
        await victim.quit()
        await bystander.quit()
    finally:
        await second.close()
        await first.close()


@pytest.mark.asyncio
async def test_legacy_non_strict_mode_remains_available(monkeypatch):
    dns = {HOSTNAME: LOOPBACK_PRIMARY}
    calls = _install_dial_recorder(monkeypatch, dns)
    server = await _start(
        ScriptedFTPServer(LOOPBACK_PRIMARY, pasv_address=UNROUTABLE_IPV4),
    )
    try:
        client = aioftp.Client(
            path_io_factory=aioftp.MemoryPathIO,
            strict_data_endpoints=False,
            trust_server_pasv_ipv4_address=False,
        )
        await client.connect(HOSTNAME, server.port)
        assert client.data_endpoint_policy is None
        # Legacy behavior: the PASV address is ignored and the original
        # hostname is re-used (re-resolved through the simulated DNS table).
        dials_before = len(calls)
        reader, writer = await client.get_passive_connection(commands=["pasv"])
        new_calls = calls[dials_before:]
        assert len(new_calls) == 1
        assert new_calls[0][0] == HOSTNAME
        assert UNROUTABLE_IPV4 not in [call[0] for call in new_calls]
        writer.close()
        await client.quit()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_default_construction_is_strict():
    client = aioftp.Client()
    assert client.strict_data_endpoints is True
    assert client.data_endpoint_policy is None  # populated on connect


@pytest.mark.asyncio
async def test_explicit_policy_is_reanchored_and_carries_exceptions():
    # The template policy names an unrelated peer; only its static exceptions
    # are carried over and the real control peer becomes the anchor.
    template = aioftp.DataEndpointPolicy(
        "203.0.113.10",
        extra_allowed_ips=[LOOPBACK_SECONDARY],
    )
    server = await _start(
        ScriptedFTPServer(
            LOOPBACK_PRIMARY,
            data_host=LOOPBACK_SECONDARY,
            pasv_address=LOOPBACK_SECONDARY,
        ),
    )
    try:
        client = aioftp.Client(
            path_io_factory=aioftp.MemoryPathIO,
            data_endpoint_policy=template,
        )
        await client.connect(LOOPBACK_PRIMARY, server.port)
        policy = client.data_endpoint_policy
        assert policy is not None
        assert str(policy.peer_ip) == LOOPBACK_PRIMARY
        assert policy.is_allowed(LOOPBACK_SECONDARY)
        # The template's stale peer is not carried over as an exception.
        assert not policy.is_allowed("203.0.113.10")
        reader, writer = await client.get_passive_connection(commands=["pasv"])
        assert writer.transport.get_extra_info("peername")[0] == LOOPBACK_SECONDARY
        writer.close()
        await client.quit()
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_legacy_trust_server_pasv_address_dials_advertised_ip(monkeypatch):
    real_open_connection = asyncio.open_connection
    seen: list[str] = []

    async def recorder(host, port, **kwargs):
        seen.append(host)
        return await real_open_connection(host, port, **kwargs)

    monkeypatch.setattr(aioftp.client, "open_connection", recorder)
    server = await _start(ScriptedFTPServer(LOOPBACK_PRIMARY, pasv_address=LOOPBACK_PRIMARY))
    try:
        client = aioftp.Client(
            path_io_factory=aioftp.MemoryPathIO,
            strict_data_endpoints=False,
            trust_server_pasv_ipv4_address=True,
        )
        await client.connect(LOOPBACK_PRIMARY, server.port)
        dials_before = len(seen)
        reader, writer = await client.get_passive_connection(commands=["pasv"])
        assert seen[dials_before:] == [LOOPBACK_PRIMARY]
        writer.close()
        await client.quit()
    finally:
        await server.close()


def test_invalid_exception_address_rejected_at_construction():
    for bad in (MULTICAST_IPV4, "0.0.0.0", "::", "not-an-ip"):
        with pytest.raises(ValueError):
            aioftp.Client(
                path_io_factory=aioftp.MemoryPathIO,
                data_endpoint_extra_allowed_ips=[bad],
            )
