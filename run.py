#!/usr/bin/env python3
"""
Social-Recon v2.0 — Advanced OSINT Reconnaissance Framework
Usage: python run.py <target> [light|full|hawk]
Examples:
    python run.py erfix404
    python run.py user@email.com full
    python run.py 09123456789 hawk
"""
import sys
import asyncio
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from social_recon.core.input_classifier import classify
from social_recon.core.pipeline import Pipeline, run_pipeline
from social_recon.core.config import SCAN_MODES


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║           Social-Recon v2.0 — OSINT Framework           ║
║     Advanced Social Media & Digital Footprint Recon      ║
║                                                          ║
║  Modules: 30+  |  Iranian Platforms: 25+  |  Async       ║
╚══════════════════════════════════════════════════════════╝
""")


def main():
    if len(sys.argv) < 2:
        print_banner()
        print("Usage: python run.py <target> [light|full|hawk]")
        print()
        print("Targets:")
        print("  username    — e.g., erfix404")
        print("  email       — e.g., user@example.com")
        print("  phone       — e.g., 09123456789")
        print("  domain      — e.g., example.com")
        print()
        print("Modes:")
        for mode, conf in SCAN_MODES.items():
            print(f"  {mode:8s} — {conf['description']}")
        sys.exit(1)

    target = sys.argv[1]
    mode = sys.argv[2].lower() if len(sys.argv) > 2 else "full"

    if mode not in SCAN_MODES:
        print(f"[!] Unknown mode: {mode}. Use: light, full, hawk")
        sys.exit(1)

    target_type, clean = classify(target)

    print_banner()
    print(f"  Target: {target}")
    print(f"  Type:   {target_type}")
    print(f"  Clean:  {clean}")
    print(f"  Mode:   {mode}")
    print()

    result = asyncio.run(run_pipeline(target, mode))

    print(f"\n  [+] Total findings: {result['total_findings']}")
    print(f"  [+] Duration: {result['duration']:.1f}s")


if __name__ == "__main__":
    main()
