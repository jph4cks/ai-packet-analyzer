from __future__ import annotations

from pathlib import Path

from ai_packet_analyzer.cli import _write_report_output


def test_write_report_output_creates_parent_dirs(tmp_path: Path):
    out_path = tmp_path / "nested" / "report.txt"
    _write_report_output(str(out_path), "hello\n")

    assert out_path.exists()
    assert out_path.read_text(encoding="utf-8") == "hello\n"
