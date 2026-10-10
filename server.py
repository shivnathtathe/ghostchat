"""Local UDP DNS server for encrypted offline chat messages."""

from __future__ import annotations

import argparse
import re
import signal
import socket
import sqlite3
import time
from pathlib import Path
from typing import Any

from crypto_utils import load_key
from protocol import DnsQuestion, ProtocolError, b32decode, decode_text, make_response, parse_query


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5353
DATABASE = Path(__file__).with_name("chat.db")
MAX_PARTS = 100
PUBLIC_KEY_BYTES = 32
PUBLIC_USERNAME_PATTERN = re.compile(r"^[a-z0-9]{1,20}$")


class MessageStore:
    def __init__(self, path: Path) -> None:
        self.connection = sqlite3.connect(path)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS message_parts (
                message_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                part_index INTEGER NOT NULL,
                part_count INTEGER NOT NULL,
                payload TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (message_id, sender, recipient, part_index)
            );
            CREATE TABLE IF NOT EXISTS messages (
                message_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (message_id, sender, recipient)
            );
            CREATE INDEX IF NOT EXISTS messages_recipient_created
                ON messages (recipient, created_at);
            CREATE TABLE IF NOT EXISTS public_keys (
                username TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )

    def register_public_key(self, username: str, public_key: str) -> bool:
        existing = self.connection.execute(
            "SELECT public_key FROM public_keys WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            if existing[0] != public_key:
                raise ProtocolError("username is already registered to another key")
            return False
        self.connection.execute(
            "INSERT INTO public_keys (username, public_key, created_at) VALUES (?, ?, ?)",
            (username, public_key, int(time.time())),
        )
        self.connection.commit()
        return True

    def public_key(self, username: str) -> str | None:
        row = self.connection.execute(
            "SELECT public_key FROM public_keys WHERE username = ?", (username,)
        ).fetchone()
        return row[0] if row else None

    def add_part(
        self,
        sender: str,
        recipient: str,
        message_id: str,
        part_index: int,
        part_count: int,
        payload: str,
    ) -> bool:
        existing = self.connection.execute(
            "SELECT part_count FROM message_parts WHERE message_id = ? AND sender = ? AND recipient = ? LIMIT 1",
            (message_id, sender, recipient),
        ).fetchone()
        if existing and existing[0] != part_count:
            raise ProtocolError("part count does not match earlier chunks")

        now = int(time.time())
        self.connection.execute(
            """INSERT OR IGNORE INTO message_parts
               (message_id, sender, recipient, part_index, part_count, payload, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (message_id, sender, recipient, part_index, part_count, payload, now),
        )
        rows = self.connection.execute(
            """SELECT part_index, payload FROM message_parts
               WHERE message_id = ? AND sender = ? AND recipient = ? ORDER BY part_index""",
            (message_id, sender, recipient),
        ).fetchall()
        complete = len(rows) == part_count and [row[0] for row in rows] == list(range(part_count))
        if complete:
            encrypted_payload = "".join(row[1] for row in rows)
            b32decode(encrypted_payload)
            self.connection.execute(
                """INSERT OR IGNORE INTO messages
                   (message_id, sender, recipient, payload, created_at) VALUES (?, ?, ?, ?, ?)""",
                (message_id, sender, recipient, encrypted_payload, now),
            )
            self.connection.execute(
                "DELETE FROM message_parts WHERE message_id = ? AND sender = ? AND recipient = ?",
                (message_id, sender, recipient),
            )
        self.connection.execute("DELETE FROM message_parts WHERE created_at < ?", (now - 3600,))
        self.connection.commit()
        return complete

    def pending(self, recipient: str) -> dict[str, str] | None:
        row = self.connection.execute(
            """SELECT message_id, sender, payload FROM messages
               WHERE recipient = ? ORDER BY created_at, rowid LIMIT 1""",
            (recipient,),
        ).fetchone()
        if not row:
            return None
        return {"id": row[0], "sender": row[1], "payload": row[2]}

    def acknowledge(self, recipient: str, sender: str, message_id: str) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM messages WHERE recipient = ? AND sender = ? AND message_id = ?",
            (recipient, sender, message_id),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def close(self) -> None:
        self.connection.close()


def handle_question(store: MessageStore, question: DnsQuestion) -> dict[str, Any]:
    labels = question.labels
    if len(labels) < 3 or labels[0] != "v1":
        raise ProtocolError("unsupported chat protocol")

    action = labels[1]
    if action == "r" and len(labels) >= 4:
        username = decode_text(labels[2])
        if not PUBLIC_USERNAME_PATTERN.fullmatch(username):
            raise ProtocolError("public-key usernames must be 1-20 lowercase letters or numbers")
        public_key = "".join(labels[3:])
        if len(b32decode(public_key)) != PUBLIC_KEY_BYTES:
            raise ProtocolError("public key must be exactly 32 bytes")
        created = store.register_public_key(username, public_key)
        return {"status": "ok", "created": created}

    if action == "k" and len(labels) == 3:
        username = decode_text(labels[2])
        if not PUBLIC_USERNAME_PATTERN.fullmatch(username):
            raise ProtocolError("public-key usernames must be 1-20 lowercase letters or numbers")
        public_key = store.public_key(username)
        return {"status": "not_found"} if public_key is None else {
            "status": "key",
            "public_key": public_key,
        }

    if action == "p" and len(labels) == 3:
        recipient = decode_text(labels[2])
        message = store.pending(recipient)
        return {"status": "empty"} if message is None else {"status": "message", **message}

    if action == "a" and len(labels) == 5:
        recipient = decode_text(labels[2])
        sender = decode_text(labels[3])
        return {"status": "ok", "removed": store.acknowledge(recipient, sender, labels[4])}

    if action == "s" and len(labels) >= 8:
        sender = decode_text(labels[2])
        recipient = decode_text(labels[3])
        message_id = labels[4]
        try:
            part_index = int(labels[5])
            part_count = int(labels[6])
        except ValueError as exc:
            raise ProtocolError("invalid message part number") from exc
        if not message_id.isalnum() or len(message_id) > 40:
            raise ProtocolError("invalid message ID")
        if not 1 <= part_count <= MAX_PARTS or not 0 <= part_index < part_count:
            raise ProtocolError("invalid message part range")
        payload = "".join(labels[7:])
        if not payload or any(character not in "abcdefghijklmnopqrstuvwxyz234567" for character in payload):
            raise ProtocolError("invalid message payload")
        complete = store.add_part(sender, recipient, message_id, part_index, part_count, payload)
        return {"status": "ok", "complete": complete}

    raise ProtocolError("invalid chat command")


def serve(host: str, port: int, database: Path) -> None:
    load_key(create=True)
    store = MessageStore(database)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(0.5)
    running = True

    def stop_server(_signum: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop_server)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop_server)
    print(f"Offline chat DNS server listening on udp://{host}:{port}")
    print(f"Message database: {database}")
    try:
        while running:
            try:
                packet, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                question = parse_query(packet)
            except ProtocolError:
                continue
            try:
                payload = handle_question(store, question)
            except (ProtocolError, UnicodeError, ValueError) as exc:
                payload = {"status": "error", "error": str(exc)}
            sock.sendto(make_response(question, payload), address)
    finally:
        sock.close()
        store.close()
        print("Server stopped")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local DNS offline chat server")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--database", type=Path, default=DATABASE)
    args = parser.parse_args()
    serve(args.host, args.port, args.database)


if __name__ == "__main__":
    main()
