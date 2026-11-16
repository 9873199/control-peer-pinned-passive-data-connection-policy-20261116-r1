"""
Strict data endpoint binding policy.

The control connection is established to a concrete socket peer. A passive
data connection, however, is driven by the server's PASV/EPSV reply, which may
name a different address than the one the control connection actually reached.
Re-resolving the original hostname for the data connection does not help when
DNS changes between the two connections, and blindly trusting the PASV address
allows a malicious or compromised server (or an on-path attacker tampering with
the cleartext control channel) to make the client dial arbitrary hosts.

The :py:class:`DataEndpointPolicy` anchors every data connection to the
*canonical IP address of the actual control-connection socket peer*. The
hostname is never re-resolved to decide where data bytes land. Deployers may
add an explicit, static set of extra IP exceptions; the set can never be
extended from server replies.

Address binding is not authentication: it cannot replace TLS certificate
validation. See the module documentation of :py:mod:`aioftp` client docs.
"""

import ipaddress
from collections.abc import Iterable

from . import errors

__all__ = ("DataEndpointPolicy", "IpAddressInput")

#: Accepted representation of an IP address in the public API.
IpAddressInput = str | ipaddress.IPv4Address | ipaddress.IPv6Address

#: A concrete, parsed IP address of either family.
AnyIpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class DataEndpointPolicy:
    """
    Immutable snapshot of the rules which decide where passive data
    connections may be opened.

    A policy is bound to one control-connection generation: it records the
    canonical IP address of the control socket's actual peer. When the control
    connection is replaced (reconnect), a new policy is created and both the
    old snapshot and any pending data connections are invalidated.

    :param peer_ip: IP address of the control-connection socket peer, as
        returned by the transport's ``peername``. This is always the primary
        permitted data endpoint.
    :type peer_ip: :py:class:`str` or :py:class:`ipaddress._BaseAddress`

    :param extra_allowed_ips: explicit, static extra IP addresses permitted for
        data connections. These can never be extended from PASV/EPSV replies.
    :type extra_allowed_ips: iterable of :py:class:`str` or
        :py:class:`ipaddress._BaseAddress`

    :param generation: monotonic identifier of the control-connection
        generation this snapshot belongs to.
    :type generation: :py:class:`int`

    :raises ValueError: if any address (including ``peer_ip``) is unspecified
        (``0.0.0.0``/``::``), multicast, reserved in a way unsuitable for a
        unicast peer, or otherwise not a valid unicast IP address.
    """

    def __init__(
        self,
        peer_ip: IpAddressInput,
        extra_allowed_ips: Iterable[IpAddressInput] = (),
        generation: int = 0,
    ) -> None:
        self.generation = generation
        self.peer_ip = self._validate_unicast(peer_ip, "control peer")
        allowed: set[AnyIpAddress] = {self.peer_ip}
        for raw in extra_allowed_ips:
            allowed.add(self._validate_unicast(raw, "allowed data endpoint"))
        # IPv4-mapped IPv6 addresses compare by unified address semantics:
        # ::ffff:127.0.0.1 and 127.0.0.1 are the same endpoint.
        self._allowed: frozenset[AnyIpAddress] = frozenset(self._canonical(ip) for ip in allowed)

    @property
    def allowed_ips(self) -> frozenset[AnyIpAddress]:
        """
        All permitted data endpoints (the canonical peer plus the explicit
        exceptions), using unified address semantics.
        """
        return self._allowed

    @property
    def extra_allowed_ips(self) -> tuple[AnyIpAddress, ...]:
        """
        The explicitly configured exception addresses, excluding the peer.
        """
        return tuple(ip for ip in self._allowed if ip != self._canonical(self.peer_ip))

    @staticmethod
    def validate_unicast(
        value: IpAddressInput,
        role: str,
    ) -> AnyIpAddress:
        """
        Validate that ``value`` is a usable unicast IP address.

        :raises ValueError: if the value is not an IP, is unspecified
            (``0.0.0.0``/``::``) or is multicast
        """
        try:
            ip = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"invalid IP address for {role}: {value!r}") from exc
        if ip.is_unspecified:
            raise ValueError(f"unspecified address is not a valid {role}: {value!r}")
        if ip.is_multicast:
            raise ValueError(f"multicast address is not a valid {role}: {value!r}")
        return ip

    @classmethod
    def _validate_unicast(
        cls,
        value: IpAddressInput,
        role: str,
    ) -> AnyIpAddress:
        return cls.validate_unicast(value, role)

    @staticmethod
    def _canonical(ip: AnyIpAddress) -> AnyIpAddress:
        """
        Return a canonical representation so that an IPv4-mapped IPv6 address
        (``::ffff:127.0.0.1``) and the plain IPv4 address (``127.0.0.1``)
        compare equal.
        """
        mapped: AnyIpAddress | None = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
        if mapped is not None:
            return mapped
        return ip

    def _as_canonical(self, value: IpAddressInput) -> AnyIpAddress:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError as exc:
            raise errors.PassiveResponseError(f"invalid IP address in passive reply: {value!r}") from exc
        return self._canonical(ip)

    def is_allowed(self, ip: IpAddressInput) -> bool:
        """
        Return :py:class:`True` if ``ip`` matches the control peer or one of the
        explicitly configured exceptions, using unified address semantics.

        :param ip: address to check
        :type ip: :py:class:`str` or :py:class:`ipaddress._BaseAddress`
        """
        return self._as_canonical(ip) in self._allowed

    def check_endpoint(self, ip: IpAddressInput) -> None:
        """
        Validate the address found in a PASV reply against this policy.

        Multicast and unspecified addresses are always rejected, even if
        somehow listed as exceptions. ``0.0.0.0`` is handled explicitly as the
        established compatibility spelling of "use the current control peer":
        it is rewritten to the peer address rather than accepted literally.

        :param ip: the IPv4 address from the PASV reply
        :type ip: :py:class:`str` or :py:class:`ipaddress.IPv4Address`

        :raises aioftp.PassiveResponseError: if the address is not a valid IP
        :raises aioftp.DataEndpointNotAllowed: if the address is not permitted
        """
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise errors.PassiveResponseError(f"invalid IP address in passive reply: {ip!r}") from exc
        if parsed.is_multicast:
            raise errors.DataEndpointNotAllowed(f"multicast data endpoint rejected: {ip}")
        if parsed.is_unspecified:
            # 0.0.0.0 (and ::) mean "the same host the control connection uses"
            # in common PASV implementations. Never dial the unspecified
            # address: rewrite to the anchored control peer.
            if isinstance(parsed, ipaddress.IPv4Address) and str(parsed) == "0.0.0.0":
                return
            raise errors.DataEndpointNotAllowed(f"unspecified data endpoint rejected: {ip}")
        if not self.is_allowed(parsed):
            raise errors.DataEndpointNotAllowed(
                f"data endpoint {ip} is neither the control peer {self.peer_ip} nor an explicitly allowed exception",
            )

    def resolve_pasv_address(self, ip: str | None) -> AnyIpAddress:
        """
        Resolve the IP from a PASV reply to the concrete address that will be
        dialled, enforcing the policy.

        :param ip: IPv4 address from the PASV reply, or :py:class:`None`
        :type ip: :py:class:`str` or :py:class:`None`

        :return: the permitted address to dial (always a concrete unicast IP)
        :rtype: :py:class:`ipaddress._BaseAddress`

        :raises aioftp.DataEndpointNotAllowed: if the address is not permitted
        """
        if ip is None or ip == "0.0.0.0":
            return self.peer_ip
        self.check_endpoint(ip)
        return self._as_canonical(ip)

    @staticmethod
    def check_port(port: int) -> None:
        """
        Reject invalid data-channel ports.

        :raises aioftp.PassiveResponseError: if ``port`` is not in 1..65535
        """
        if not isinstance(port, int) or isinstance(port, bool) or not 0 < port <= 65535:
            raise errors.PassiveResponseError(f"invalid data port: {port!r}")

    def check_family(self, pasv_ip: IpAddressInput) -> None:
        """
        Ensure a PASV reply does not downgrade the address family of an IPv6
        control connection.

        :raises aioftp.PassiveResponseError: if the control peer is IPv6 and the
            PASV reply carries a plain (non-mapped) IPv4 address
        """
        if isinstance(self.peer_ip, ipaddress.IPv6Address):
            try:
                parsed = ipaddress.ip_address(pasv_ip)
            except ValueError as exc:
                raise errors.PassiveResponseError(f"invalid IP address in passive reply: {pasv_ip!r}") from exc
            if isinstance(parsed, ipaddress.IPv4Address):
                raise errors.PassiveResponseError(
                    f"PASV IPv4 address {pasv_ip} would downgrade an IPv6 control connection",
                )

    def verify_connected_peer(
        self,
        peername: tuple[object, ...] | str,
    ) -> AnyIpAddress:
        """
        Verify the actual peer of an established data transport against the
        permitted set. To be called *after* the connection completes, before
        any STOR/RETR command or file payload is sent.

        :param peername: transport ``peername`` extra info, e.g.
            ``('127.0.0.1', 1234)`` or ``('::1', 1234, 0, 0)``
        :type peername: :py:class:`tuple` or :py:class:`str`

        :raises aioftp.DataEndpointMismatch: if the connected peer is not
            permitted by this policy
        """
        if not peername:
            raise errors.DataEndpointMismatch("data transport reports no peername")
        if isinstance(peername, str):
            host: object = peername
        else:
            host = peername[0]
        canonical = self._as_canonical(str(host))
        if canonical not in self._allowed:
            raise errors.DataEndpointMismatch(
                f"data connection established to {host}, which is outside the "
                f"permitted endpoints (control peer {self.peer_ip})",
            )
        return canonical
