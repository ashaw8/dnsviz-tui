"""JSON export functionality."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from dnsviz_tui.models.chain import TrustChain, ZoneInfo, ValidationStatus


def _serialize_datetime(dt: datetime) -> str:
    """Serialize datetime to ISO format."""
    return dt.isoformat() + "Z"


def _serialize_status(status: ValidationStatus) -> dict[str, Any]:
    """Serialize validation status."""
    return {
        "value": status.value,
        "symbol": status.symbol,
        "color": status.color,
    }


def _serialize_zone(zone: ZoneInfo) -> dict[str, Any]:
    """Serialize a zone to dict."""
    return {
        "name": zone.name,
        "parent": zone.parent,
        "status": _serialize_status(zone.status),
        "status_reason": zone.status_reason,
        "has_dnssec": zone.has_dnssec,
        "ds_validated": zone.ds_validated,
        "dnskey_validated": zone.dnskey_validated,
        "chain_complete": zone.chain_complete,
        "dnskeys": [
            {
                "flags": key.flags,
                "protocol": key.protocol,
                "algorithm": key.algorithm,
                "algorithm_name": key.algorithm_name,
                "key_tag": key.key_tag,
                "key_length": key.key_length,
                "is_ksk": key.is_ksk,
                "is_zsk": key.is_zsk,
                "key_data": key.key_data,
            }
            for key in zone.dnskeys
        ],
        "ds_records": [
            {
                "key_tag": ds.key_tag,
                "algorithm": ds.algorithm,
                "algorithm_name": ds.algorithm_name,
                "digest_type": ds.digest_type,
                "digest_type_name": ds.digest_type_name,
                "digest": ds.digest,
                "validates_key": ds.validates_key,
            }
            for ds in zone.ds_records
        ],
        "rrsigs": [
            {
                "type_covered": rrsig.type_covered,
                "algorithm": rrsig.algorithm,
                "algorithm_name": rrsig.algorithm_name,
                "labels": rrsig.labels,
                "original_ttl": rrsig.original_ttl,
                "expiration": _serialize_datetime(rrsig.expiration),
                "inception": _serialize_datetime(rrsig.inception),
                "key_tag": rrsig.key_tag,
                "signer_name": rrsig.signer_name,
                "is_valid": rrsig.is_valid,
                "is_expired": rrsig.is_expired,
                "days_until_expiry": rrsig.days_until_expiry,
            }
            for rrsig in zone.rrsigs
        ],
        "additional_records": [
            {
                "record_type": rec.record_type,
                "name": rec.name,
                "value": rec.value,
                "ttl": rec.ttl,
                "is_signed": rec.is_signed,
            }
            for rec in zone.additional_records
        ],
    }


def chain_to_dict(chain: TrustChain) -> dict[str, Any]:
    """Convert a TrustChain to a dictionary."""
    return {
        "metadata": {
            "target_domain": chain.target_domain,
            "query_time": _serialize_datetime(chain.query_time),
            "query_duration_ms": chain.query_duration_ms,
            "resolver_used": chain.resolver_used,
            "zone_count": chain.zone_count,
        },
        "overall_status": _serialize_status(chain.overall_status),
        "overall_reason": chain.overall_reason,
        "chain_path": chain.chain_path(),
        "zones": [_serialize_zone(zone) for zone in chain.zones],
    }


def export_json(chain: TrustChain, path: Path | str | None = None) -> str:
    """Export trust chain to JSON.

    Args:
        chain: The trust chain to export
        path: Optional file path to write to

    Returns:
        JSON string
    """
    data = chain_to_dict(chain)
    json_str = json.dumps(data, indent=2)

    if path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json_str)

    return json_str
