"""Deterministic JSON, CSV, TXT and XML snapshot serialization."""

from __future__ import annotations

import csv
import io
import json
from typing import Any
from xml.etree import ElementTree

from publicvpnlist.validation import ValidationFailure, csv_cell_is_dangerous

INTEGER_FIELDS = {"port", "sessions", "technical_quality_score"}
NUMBER_FIELDS = {
    "speed_mbps",
    "latency_ms",
    "jitter_ms",
    "packet_loss_percent",
    "upload_mbps",
    "uptime_percent_24h",
    "uptime_percent_7d",
    "uptime_percent_30d",
    "uptime_hours",
}
BOOLEAN_FIELDS = {"redistribution_allowed"}
ARRAY_FIELDS = {"risk_flags"}


def json_bytes(dataset: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            dataset,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()


def csv_bytes(records: list[dict[str, Any]], fields: tuple[str, ...]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(fields)
    for record in records:
        row = [_encode_cell(record.get(field)) for field in fields]
        for value in row:
            if csv_cell_is_dangerous(value):
                raise ValidationFailure("CSV serialization: dangerous cell rejected")
        writer.writerow(row)
    return stream.getvalue().encode()


def txt_bytes(records: list[dict[str, Any]], fields: tuple[str, ...]) -> bytes:
    lines = [
        "# PublicVPNList OpenVPN dataset schema 1.0 (UTF-8 TSV)",
        "\t".join(fields),
    ]
    for record in records:
        values = [_encode_cell(record.get(field)) for field in fields]
        if any("\t" in value or "\r" in value or "\n" in value for value in values):
            raise ValidationFailure("TXT serialization: unsafe tab or newline")
        lines.append("\t".join(values))
    return ("\n".join(lines) + "\n").encode()


def xml_bytes(
    dataset: dict[str, Any],
    fields: tuple[str, ...],
) -> bytes:
    root = ElementTree.Element(
        "publicvpnlist_dataset",
        {"schema_version": str(dataset["metadata"]["schema_version"])},
    )
    metadata = ElementTree.SubElement(root, "metadata")
    for field, value in dataset["metadata"].items():
        node = ElementTree.SubElement(metadata, field)
        _set_xml_value(node, value)
    records_node = ElementTree.SubElement(root, "records")
    for record in dataset["records"]:
        server = ElementTree.SubElement(records_node, "server")
        for field in fields:
            node = ElementTree.SubElement(server, field)
            _set_xml_value(node, record.get(field))
    ElementTree.indent(root, space="  ")
    body = ElementTree.tostring(root, encoding="unicode", short_empty_elements=True)
    if "<!DOCTYPE" in body.upper() or "<!ENTITY" in body.upper():
        raise ValidationFailure("XML serialization: DTD or entity rejected")
    ElementTree.fromstring(body)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n' + body + "\n").encode()


def parse_csv(content: bytes, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(content.decode("utf-8"), newline=""))
    if tuple(reader.fieldnames or ()) != fields:
        raise ValidationFailure("CSV parse: column order mismatch")
    return [_decode_mapping(dict(row), fields) for row in reader]


def parse_txt(content: bytes, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    lines = content.decode("utf-8").splitlines()
    if len(lines) < 2 or lines[0] != ("# PublicVPNList OpenVPN dataset schema 1.0 (UTF-8 TSV)"):
        raise ValidationFailure("TXT parse: invalid header")
    if tuple(lines[1].split("\t")) != fields:
        raise ValidationFailure("TXT parse: column order mismatch")
    records = []
    for line in lines[2:]:
        values = line.split("\t")
        if len(values) != len(fields):
            raise ValidationFailure("TXT parse: column count mismatch")
        records.append(_decode_mapping(dict(zip(fields, values, strict=True)), fields))
    return records


def parse_xml(content: bytes, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    upper = content.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValidationFailure("XML parse: DTD or entity rejected")
    root = ElementTree.fromstring(content)
    if root.tag != "publicvpnlist_dataset":
        raise ValidationFailure("XML parse: invalid root")
    records_node = root.find("records")
    if records_node is None:
        raise ValidationFailure("XML parse: records missing")
    records = []
    for server in records_node.findall("server"):
        values: dict[str, str] = {}
        for field in fields:
            node = server.find(field)
            if node is None:
                raise ValidationFailure("XML parse: field missing")
            if field in ARRAY_FIELDS:
                values[field] = json.dumps(
                    [item.text or "" for item in node.findall("item")],
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            elif node.get("nil") == "true":
                values[field] = ""
            else:
                values[field] = node.text or ""
        records.append(_decode_mapping(values, fields))
    return records


def _set_xml_value(node: ElementTree.Element, value: Any) -> None:
    if value is None:
        node.set("nil", "true")
    elif isinstance(value, list):
        for item in value:
            child = ElementTree.SubElement(node, "item")
            child.text = str(item)
    elif isinstance(value, bool):
        node.text = "true" if value else "false"
    else:
        node.text = str(value)


def _encode_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)


def _decode_mapping(values: dict[str, str], fields: tuple[str, ...]) -> dict[str, Any]:
    record: dict[str, Any] = {}
    for field in fields:
        value = values.get(field, "")
        if value == "":
            record[field] = None
        elif field in ARRAY_FIELDS:
            decoded = json.loads(value)
            if not isinstance(decoded, list):
                raise ValidationFailure("format parse: array field is invalid")
            record[field] = decoded
        elif field in BOOLEAN_FIELDS:
            if value not in {"true", "false"}:
                raise ValidationFailure("format parse: boolean field is invalid")
            record[field] = value == "true"
        elif field in INTEGER_FIELDS:
            record[field] = int(value)
        elif field in NUMBER_FIELDS:
            record[field] = float(value)
        else:
            record[field] = value
    return record
