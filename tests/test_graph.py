"""Tests for the dnsviz-style chain graph."""

from datetime import datetime, timedelta

from rich.console import Console

from dnsviz_tui.models.chain import (
    AdditionalRecord,
    DNSKeyInfo,
    DSInfo,
    RRSIGInfo,
    TrustChain,
    ValidationStatus,
    ZoneInfo,
)
from dnsviz_tui.views.graph import build_diagram


def _key(flags: int, alg: int, tag: int, bits: int) -> DNSKeyInfo:
    return DNSKeyInfo(
        flags=flags, protocol=3, algorithm=alg, algorithm_name="x",
        key_tag=tag, key_data="AAAA", key_length=bits,
    )


def _ds(tag: int, alg: int, digest_type: int) -> DSInfo:
    return DSInfo(
        key_tag=tag, algorithm=alg, algorithm_name="x",
        digest_type=digest_type, digest_type_name="SHA-256",
        digest="AB" * 16, validates_key=tag,
    )


def _sig(covered: str, tag: int) -> RRSIGInfo:
    now = datetime.utcnow()
    return RRSIGInfo(
        type_covered=covered, algorithm=13, algorithm_name="x", labels=2,
        original_ttl=300, expiration=now + timedelta(days=10),
        inception=now - timedelta(days=1), key_tag=tag, signer_name="x",
        signature="sig", is_valid=True,
    )


def _secure_chain() -> TrustChain:
    """Replicates the dnsviz.net reference graph for shawyer.net."""
    root = ZoneInfo(name=".", status=ValidationStatus.SECURE)
    root.dnskeys = [
        _key(257, 8, 20326, 2048), _key(256, 8, 54393, 2048),
        _key(257, 8, 38696, 2048),
    ]
    root.rrsigs = [_sig("DNSKEY", 20326)]

    net = ZoneInfo(name="net.", parent=".", status=ValidationStatus.SECURE)
    net.dnskeys = [_key(257, 13, 37331, 512), _key(256, 13, 1560, 512)]
    net.ds_records = [_ds(37331, 13, 2)]
    net.ds_validated = True
    net.rrsigs = [_sig("DNSKEY", 37331)]

    tgt = ZoneInfo(name="shawyer.net.", parent="net.", status=ValidationStatus.SECURE)
    tgt.dnskeys = [
        _key(257, 13, 6737, 512), _key(256, 13, 36912, 512),
        _key(256, 13, 32267, 512),
    ]
    tgt.ds_records = [_ds(6737, 13, 2)]
    tgt.ds_validated = True
    tgt.rrsigs = [_sig("DNSKEY", 6737)]
    tgt.additional_records = [
        AdditionalRecord("MX", "shawyer.net.", "10 mail", 300, True, _sig("MX", 32267)),
        AdditionalRecord("TXT", "shawyer.net.", "v=spf1", 300, True, _sig("TXT", 32267)),
        AdditionalRecord("SOA", "shawyer.net.", "serial=1", 300, True, _sig("SOA", 32267)),
        AdditionalRecord("NS", "shawyer.net.", "ns1", 300, True, _sig("NS", 32267)),
    ]

    return TrustChain(
        target_domain="shawyer.net", zones=[root, net, tgt],
        overall_status=ValidationStatus.SECURE,
        overall_reason="Complete chain of trust validated",
    )


def _render(chain: TrustChain, width: int = 110) -> str:
    console = Console(width=width, force_terminal=False, legacy_windows=False)
    with console.capture() as capture:
        console.print(build_diagram(chain, max_width=width - 6))
    return capture.get()


def test_keys_listed_individually_with_alg_id_bits():
    out = _render(_secure_chain())
    for label in [
        "alg=8, id=20326", "alg=8, id=54393", "alg=8, id=38696",
        "alg=13, id=37331", "alg=13, id=1560",
        "alg=13, id=6737", "alg=13, id=36912", "alg=13, id=32267",
    ]:
        assert label in out
    assert "2048 bits" in out
    assert "512 bits" in out


def test_full_chain_structure():
    out = _render(_secure_chain())
    # DS delegation nodes in both parent zones
    assert out.count("digest alg=2") == 2
    # Zone footers
    for name in [" .", " net", " shawyer.net"]:
        assert name in out
    assert "UTC)" in out
    # RRset leaves hang off the target zone
    for leaf in ["shawyer.net/MX", "shawyer.net/TXT", "shawyer.net/SOA", "shawyer.net/NS"]:
        assert leaf in out
    # Trust anchor is double-bordered; other nodes rounded
    assert "╔" in out and "╭" in out
    # Self-signature loops and signing arrows exist
    assert "◀" in out and "▼" in out


def test_insecure_delegation_renders():
    chain = _secure_chain()
    tail = ZoneInfo(name="unsigned.shawyer.net.", status=ValidationStatus.INSECURE,
                    status_reason="No DNSSEC (unsigned delegation)")
    chain.zones.append(tail)
    chain.overall_status = ValidationStatus.INSECURE
    out = _render(chain)
    assert "unsigned delegation" in out


def test_empty_chain():
    chain = TrustChain(target_domain="example.com")
    out = _render(chain)
    assert "No data" in out


def test_diagram_view_renders_unmounted():
    """DiagramView.render() must not require an active Textual app."""
    from dnsviz_tui.views.diagram_view import DiagramView

    view = DiagramView()
    empty = view.render()
    assert empty is not None

    view = DiagramView(chain=_secure_chain())
    console = Console(width=120, force_terminal=False)
    with console.capture() as capture:
        console.print(view.render())
    out = capture.get()
    assert "alg=13, id=6737" in out
    assert "Chain of Trust" in out
