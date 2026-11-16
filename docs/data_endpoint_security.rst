.. data_endpoint_security:

Data endpoint binding (strict passive connections)
===================================================

The problem
-----------

An FTP client opens *two* connections:

1. a **control connection**, used to log in and send commands;
2. a **data connection**, opened per transfer for ``STOR``, ``RETR``,
   ``LIST``/``MLSD`` and friends.

For passive transfers the server tells the client, inside a ``PASV`` or
``EPSV`` reply, where to open the data connection. ``EPSV`` only carries a
port, while ``PASV`` carries an IPv4 address *and* a port. Historically
aioftp re-resolved the original hostname when the reply did not name an
address, and when ``trust_server_pasv_ipv4_address`` was enabled it dialled
whatever address the server put in the ``PASV`` reply.

Both behaviors are unsafe:

* If DNS changes between the control and data connections, re-resolving the
  hostname can send file bytes to a different host than the one the control
  connection actually reached — the control peer is the only identity the
  client has actually observed.
* A malicious or compromised server, or an attacker tampering with the
  cleartext FTP control channel, can place an arbitrary address in a ``PASV``
  reply and make the client dial it.

Strict policy
-------------

Since the version introduced in this change, :py:class:`aioftp.Client`
defaults to **strict data endpoint binding**:

* The policy is anchored to the *canonical IP address of the actual
  control-connection socket peer* (taken from the connected transport's
  ``peername``, never from a DNS lookup).
* The data connection may only be opened to that address, or to an explicit,
  static set of exception IPs configured when the client is constructed.
* The original hostname is **never re-resolved** to choose where data lands.
* The exception set is fixed at construction time and can never be grown from
  a server reply.
* ``EPSV`` supplies only a port, so the peer address is always used.
* A ``PASV`` address is validated against the policy in strict mode too; the
  legacy ``0.0.0.0`` spelling is treated as "use the current control peer".
* Multicast and unspecified (``0.0.0.0``/``::``) addresses are rejected, as
  are ports outside ``1..65535``.
* An IPv6 control connection cannot be downgraded to IPv4 by a ``PASV``
  reply. IPv4-mapped IPv6 addresses (``::ffff:127.0.0.1``) compare by unified
  address semantics, i.e. as the same endpoint as ``127.0.0.1``.

Permission is checked **before dialling**. After the data socket connects, the
transport's *real* peer is checked again; if it differs from the permitted
endpoint the socket is closed immediately, before any ``STOR``/``RETR`` command
or file payload is sent (see :py:class:`aioftp.DataEndpointMismatch`).

Ambiguous replies are rejected
------------------------------

The passive parsers are strict:

* ``PASV`` must contain exactly one parenthesized candidate with six integers,
  each in ``0..255``.
* ``EPSV`` must use a legal delimiter and the documented field layout, with a
  numeric port in range.
* Multiple conflicting parenthesized candidates are an error — the client
  never silently picks "the last one".

Malformed replies raise :py:class:`aioftp.PassiveResponseError` and policy
rejections raise :py:class:`aioftp.DataEndpointNotAllowed`. Neither triggers
the passive-command fallback: only a genuine "command not implemented" style
``50x`` response allows trying the next mechanism (e.g. ``EPSV`` then
``PASV``).

Reconnects
----------

The policy is a snapshot bound to one control-connection **generation**. When
the control connection is replaced (a new :py:meth:`aioftp.Client.connect`),
the previous snapshot is discarded and every pending passive data connection
is closed. A data connection that outlives its generation raises
:py:class:`aioftp.DataConnectionGenerationError` rather than being reused.

FTPS and TLS identity
---------------------

Binding the data dial to a fixed IP does **not** change the TLS reference
identity. The data channel keeps the explicit TLS parameters of the control
connection and passes the original hostname as the ``server_hostname`` for
certificate verification. Certificate verification is never disabled to make a
connection succeed; address binding is not authentication and cannot replace
TLS.

Usage
-----

Default — strict, anchored to the control peer::

    import aioftp

    client = aioftp.Client()  # strict_data_endpoints=True by default
    await client.connect("ftp.example.com", 21)

Add static, trusted exception addresses (for example an FTP server whose
passive data listeners legitimately live on a second, fixed IP)::

    client = aioftp.Client(
        data_endpoint_extra_allowed_ips=["203.0.113.7", "2001:db8::7"],
    )

A pre-built policy can also be supplied; it is re-anchored to the actual
control peer on every connect, carrying only its static exceptions::

    policy = aioftp.DataEndpointPolicy("203.0.113.10", extra_allowed_ips=["203.0.113.11"])
    client = aioftp.Client(data_endpoint_policy=policy)

The legacy, non-strict behavior is still available when explicitly requested::

    client = aioftp.Client(strict_data_endpoints=False)

In that case the policy snapshot is :py:class:`None` and the historical
hostname-based behavior is used.

High-level operations — :py:meth:`aioftp.Client.upload`,
:py:meth:`aioftp.Client.download` and :py:meth:`aioftp.Client.list` — all go
through the same guard via :py:meth:`aioftp.Client.get_stream`. A failure or
cancellation only cleans up that task's own data connection; unrelated clients
and connections are not affected.

.. warning::

    Address binding pins *where* data is sent, but does not authenticate the
    peer. For authenticated, confidential FTP use FTPS with a properly
    configured :py:class:`ssl.SSLContext`; strict binding is defense in depth,
    not a replacement for TLS certificate validation.

API
---

.. autoclass:: aioftp.DataEndpointPolicy
    :members:
    :show-inheritance:

.. autoclass:: aioftp.PassiveResponseError
.. autoclass:: aioftp.DataEndpointNotAllowed
.. autoclass:: aioftp.DataEndpointMismatch
.. autoclass:: aioftp.DataConnectionGenerationError
