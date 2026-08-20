"""Maigret bridge — integrates Maigret CLI into the async pipeline.

Maigret checks 3000+ sites for username presence. This module bridges
the CLI tool into our pipeline architecture.
"""
import asyncio
import json
import os
from pathlib import Path

from .base import BaseModule, ModuleResult, Finding, ModuleCategory
from ..core.config import OUTPUT_DIR


class MaigretBridge(BaseModule):
    """Bridge to Maigret CLI — username enumeration across 3000+ sites."""

    name = "maigret"
    category = ModuleCategory.USERNAME
    description = "Username enumeration across 3000+ platforms via Maigret"
    supported_input_types = ["username"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []
        target = target.replace("@", "").strip()

        output_dir = Path((context or {}).get("output_dir", str(OUTPUT_DIR / target)))
        out_json = output_dir / "maigret_results.json"

        try:
            proc = await asyncio.create_subprocess_exec(
                "maigret", target,
                "--timeout", "8",
                "--no-progressbar",
                "--json", "simple",
                "--output", str(out_json),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)

            if out_json.exists():
                data = json.loads(out_json.read_text(encoding="utf-8"))
                claimed = 0

                for site, info in data.items():
                    if not isinstance(info, dict):
                        continue
                    status = info.get("status", {})
                    if isinstance(status, dict) and status.get("status") == "Claimed":
                        claimed += 1
                        ids = status.get("ids", {})
                        findings.append(Finding(
                            source=f"maigret:{site}",
                            data_type="profile",
                            value={
                                "platform": site,
                                "url": info.get("url_user", ""),
                                "username": target,
                                "fullname": ids.get("fullname"),
                                "id": ids.get("id"),
                                "bio": ids.get("bio"),
                                "image": ids.get("image") or ids.get("avatar"),
                                "followers": ids.get("follower_count"),
                                "verified": ids.get("is_verified"),
                                "location": ids.get("location") or ids.get("country"),
                                "private": ids.get("is_private"),
                            },
                            confidence=0.8,
                            metadata={"site": site, "method": "maigret"},
                        ))

                        # Extract emails from profiles
                        if ids.get("fullname") and "@" in str(ids.get("fullname", "")):
                            import re
                            for em in re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', str(ids["fullname"])):
                                findings.append(Finding(
                                    source=f"maigret:{site}",
                                    data_type="email",
                                    value=em,
                                    confidence=0.7,
                                    metadata={"source": f"maigret:{site}"},
                                ))

                findings.append(Finding(
                    source="maigret",
                    data_type="profile",
                    value={
                        "type": "summary",
                        "target": target,
                        "total_sites_checked": len(data),
                        "claimed": claimed,
                    },
                    confidence=0.95,
                    metadata={"source": "maigret", "type": "summary"},
                ))
            else:
                errors.append("Maigret produced no output file")

        except FileNotFoundError:
            errors.append("Maigret not installed. Run: pip install maigret")
        except asyncio.TimeoutError:
            errors.append("Maigret timed out after 180s")
        except Exception as e:
            errors.append(f"Maigret error: {str(e)[:200]}")

        return ModuleResult(
            module_name=self.name,
            success=bool(findings),
            findings=findings,
            errors=errors,
        )
