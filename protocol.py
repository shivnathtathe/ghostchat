"""Minimal DNS wire helpers and the offline chat protocol."""

from __future__ import annotations

import base64
import json
import secrets
import struct
from dataclasses import dataclass
from typing import Any


QTYPE_TXT = 16
QCLASS_IN = 1
MAX_LABEL_LENGTH = 63
CHAT_SUFFIX = ("offlinechat", "local")


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class DnsQuestion:
    transaction_id: int
    labels: tuple[str, ...]
    question_wire: bytes


def b32encode(data: bytes) -> str:
    return base64.b32encode(data).decode("ascii").rstrip("=").lower()


def b32decode(value: str) -> bytes:
    try:
        padding = "=" * ((8 - len(value) % 8) % 8)
        return base64.b32decode((value.upper() + padding), casefold=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ProtocolError("invalid Base32 data") from exc


def encode_text(value: str) -> str:
    return b32encode(value.encode("utf-8"))


def decode_text(value: str) -> str:
    try:
        return b32decode(value).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("invalid UTF-8 data") from exc


def make_query(labels: list[str] | tuple[str, ...], transaction_id: int | None = None) -> tuple[int, bytes]:
    transaction_id = secrets.randbelow(65536) if transaction_id is None else transaction_id
    all_labels = tuple(labels) + CHAT_SUFFIX
    qname = _encode_name(all_labels)
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return transaction_id, header + qname + struct.pack("!HH", QTYPE_TXT, QCLASS_IN)


def parse_query(packet: bytes) -> DnsQuestion:
    if len(packet) < 12:
        raise ProtocolError("truncated DNS header")
    transaction_id, _, question_count, _, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if question_count != 1:
        raise ProtocolError("exactly one DNS question is required")
    labels, offset = _decode_name(packet, 12)
    if offset + 4 > len(packet):
        raise ProtocolError("truncated DNS question")
    qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
    if qtype != QTYPE_TXT or qclass != QCLASS_IN:
        raise ProtocolError("only IN TXT questions are supported")
    if tuple(labels[-2:]) != CHAT_SUFFIX:
        raise ProtocolError("unknown DNS zone")
    return DnsQuestion(transaction_id, tuple(labels[:-2]), packet[12 : offset + 4])


def make_response(question: DnsQuestion, payload: dict[str, Any]) -> bytes:
    encoded = b32encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
    strings = [encoded[index : index + 255] for index in range(0, len(encoded), 255)] or [""]
    rdata = b"".join(bytes([len(part)]) + part.encode("ascii") for part in strings)
    header = struct.pack("!HHHHHH", question.transaction_id, 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", QTYPE_TXT, QCLASS_IN, 0, len(rdata)) + rdata
    return header + question.question_wire + answer


def parse_response(packet: bytes, expected_id: int) -> dict[str, Any]:
    if len(packet) < 12:
        raise ProtocolError("truncated DNS response")
    transaction_id, flags, question_count, answer_count, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if transaction_id != expected_id:
        raise ProtocolError("DNS transaction ID mismatch")
    if not flags & 0x8000 or flags & 0x000F:
        raise ProtocolError("DNS server returned an error")
    offset = 12
    for _ in range(question_count):
        _, offset = _decode_name(packet, offset)
        offset += 4
    if answer_count < 1:
        raise ProtocolError("DNS response has no answer")
    _, offset = _decode_name(packet, offset)
    if offset + 10 > len(packet):
        raise ProtocolError("truncated DNS answer")
    record_type, record_class, _, data_length = struct.unpack("!HHIH", packet[offset : offset + 10])
    offset += 10
    if record_type != QTYPE_TXT or record_class != QCLASS_IN or offset + data_length > len(packet):
        raise ProtocolError("invalid DNS TXT answer")
    end = offset + data_length
    parts: list[bytes] = []
    while offset < end:
        length = packet[offset]
        offset += 1
        if offset + length > end:
            raise ProtocolError("truncated DNS TXT string")
        parts.append(packet[offset : offset + length])
        offset += length
    try:
        result = json.loads(b32decode(b"".join(parts).decode("ascii")).decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid response envelope") from exc
    if not isinstance(result, dict):
        raise ProtocolError("invalid response envelope")
    return result


def chunk_labels(value: str, size: int = 50) -> list[str]:
    return [value[index : index + size] for index in range(0, len(value), size)]


def _encode_name(labels: tuple[str, ...]) -> bytes:
    output = bytearray()
    for label in labels:
        encoded = label.encode("ascii")
        if not encoded or len(encoded) > MAX_LABEL_LENGTH:
            raise ProtocolError("DNS labels must contain 1 to 63 ASCII bytes")
        output.append(len(encoded))
        output.extend(encoded)
    output.append(0)
    if len(output) > 255:
        raise ProtocolError("DNS name exceeds 255 bytes")
    return bytes(output)


def _decode_name(packet: bytes, offset: int) -> tuple[list[str], int]:
    labels: list[str] = []
    return_offset: int | None = None
    seen: set[int] = set()
    while True:
        if offset >= len(packet):
            raise ProtocolError("truncated DNS name")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ProtocolError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen or pointer >= len(packet):
                raise ProtocolError("invalid DNS pointer")
            seen.add(pointer)
            return_offset = offset + 2 if return_offset is None else return_offset
            offset = pointer
            continue
        if length & 0xC0:
            raise ProtocolError("invalid DNS label")
        offset += 1
        if length == 0:
            return labels, return_offset if return_offset is not None else offset
        if length > MAX_LABEL_LENGTH or offset + length > len(packet):
            raise ProtocolError("truncated DNS label")
        try:
            labels.append(packet[offset : offset + length].decode("ascii").lower())
        except UnicodeDecodeError as exc:
            raise ProtocolError("non-ASCII DNS label") from exc
        offset += length
