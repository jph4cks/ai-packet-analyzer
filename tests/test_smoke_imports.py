"""Smoke tests.

These tests ensure the package imports cleanly.

The repository also includes a more comprehensive black-box test harness:
`python3 tests/run_comprehensive_tests.py`.
"""


def test_imports() -> None:
    import ai_packet_analyzer  # noqa: F401
    from ai_packet_analyzer import cli  # noqa: F401
