"""Entry point for PyInstaller builds."""
import sys
import os

# Add src to path for the bundled app
if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS
else:
    base_path = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(base_path, 'src'))

from ai_packet_analyzer.cli import main

if __name__ == "__main__":
    main()
