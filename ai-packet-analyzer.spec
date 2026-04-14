# -*- mode: python ; coding: utf-8 -*-

import sys
import os

block_cipher = None

a = Analysis(
    ['build_entry.py'],
    pathex=['src'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'ai_packet_analyzer',
        'ai_packet_analyzer.cli',
        'ai_packet_analyzer.packet_parser',
        'ai_packet_analyzer.ai_engine',
        'ai_packet_analyzer.report_renderer',
        'scapy',
        'scapy.all',
        'scapy.layers',
        'scapy.layers.inet',
        'scapy.layers.dns',
        'scapy.layers.l2',
        'rich',
        'rich.console',
        'rich.panel',
        'rich.table',
        'rich.text',
        'rich.prompt',
        'rich.box',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas', 'PIL', 'cv2'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ai-packet-analyzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
