"""Instructor-only generator for the R4178 reverse engineering workshop."""

from pathlib import Path

MESSAGE = b"reverse_engineering_needs_evidence"
MAGIC = b"R4178"


def main() -> None:
    encoded = bytes(byte ^ (0x23 + i % 5) for i, byte in enumerate(MESSAGE[::-1]))
    content = MAGIC + bytes([len(MESSAGE)]) + encoded + bytes([sum(encoded) & 0xFF])
    here = Path(__file__).resolve().parent
    (here / "note.r17").write_bytes(content)
    (here / "bad_checksum.r17").write_bytes(content[:-1] + bytes([content[-1] ^ 1]))
    assert sum(MESSAGE) == 3574
    assert len(MESSAGE) == 34


if __name__ == "__main__":
    main()
