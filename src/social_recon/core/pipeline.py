"""Async pipeline orchestrator — runs OSINT modules concurrently."""
import asyncio
import time
import json
from pathlib import Path
from typing import Any

from ..modules.base import BaseModule, ModuleResult, ModuleCategory
from .config import OUTPUT_DIR, MAX_CONCURRENT_MODULES, SCAN_MODES


class Pipeline:
    """Orchestrates OSINT module execution with concurrency control."""

    def __init__(
        self,
        target: str,
        target_type: str,
        mode: str = "full",
        output_dir: Path | None = None,
        config: dict | None = None,
    ):
        self.target = target
        self.target_type = target_type
        self.mode = mode
        self.output_dir = output_dir or (OUTPUT_DIR / target.replace("@", "").replace(" ", "_"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "images").mkdir(exist_ok=True)
        self.config = config or {}

        self.results: dict[str, ModuleResult] = {}
        self.all_findings: list = []
        self.context: dict[str, Any] = {
            "target": target,
            "target_type": target_type,
            "output_dir": str(self.output_dir),
            "mode": mode,
            "emails": [],
            "phones": [],
            "usernames": [target.replace("@", "")],
            "profiles": {},
        }
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_MODULES)
        self._modules: list[BaseModule] = []

    def register_module(self, module: BaseModule):
        """Add a module to the pipeline."""
        if module.is_applicable(self.target_type):
            self._modules.append(module)

    def register_modules(self, modules: list[BaseModule]):
        """Add multiple modules."""
        for m in modules:
            self.register_module(m)

    async def _run_module(self, module: BaseModule) -> ModuleResult:
        """Run a single module with semaphore control."""
        async with self._semaphore:
            print(f"  [*] Running: {module.name}")
            start = time.time()
            try:
                result = await asyncio.wait_for(
                    module.run(self.target, self.target_type, self.context),
                    timeout=self.config.get("module_timeout", 120),
                )
                result.duration = time.time() - start
                print(f"  [+] {module.name}: {len(result.findings)} findings ({result.duration:.1f}s)")
                return result
            except asyncio.TimeoutError:
                duration = time.time() - start
                print(f"  [-] {module.name}: TIMEOUT ({duration:.1f}s)")
                return ModuleResult(
                    module_name=module.name, success=False,
                    errors=["Module timed out"], duration=duration,
                )
            except Exception as e:
                duration = time.time() - start
                print(f"  [-] {module.name}: ERROR — {e}")
                return ModuleResult(
                    module_name=module.name, success=False,
                    errors=[str(e)], duration=duration,
                )

    async def _run_phase(self, modules: list[BaseModule], phase_name: str):
        """Run a group of modules concurrently."""
        if not modules:
            return
        print(f"\n{'='*50}")
        print(f"  Phase: {phase_name} ({len(modules)} modules)")
        print(f"{'='*50}")

        tasks = [self._run_module(m) for m in modules]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for module, result in zip(modules, results):
            if isinstance(result, Exception):
                result = ModuleResult(
                    module_name=module.name, success=False,
                    errors=[str(result)],
                )
            self.results[module.name] = result
            self._update_context(result)

    def _update_context(self, result: ModuleResult):
        """Update shared context with new findings for chaining."""
        for finding in result.findings:
            if finding.data_type == "email" and finding.value not in self.context["emails"]:
                self.context["emails"].append(finding.value)
            elif finding.data_type == "phone" and finding.value not in self.context["phones"]:
                self.context["phones"].append(finding.value)
            elif finding.data_type == "username" and finding.value not in self.context["usernames"]:
                self.context["usernames"].append(finding.value)
            elif finding.data_type == "profile":
                site = finding.metadata.get("site", "unknown")
                self.context["profiles"][site] = finding.value
            self.all_findings.append(finding)

    def _group_modules_by_phase(self) -> list[tuple[str, list[BaseModule]]]:
        """Group modules into execution phases for optimal ordering."""
        phases = []

        # Phase 1: Core enumeration (runs first, feeds data to others)
        core = [m for m in self._modules if m.category in (
            ModuleCategory.USERNAME, ModuleCategory.EMAIL, ModuleCategory.PHONE,
        )]
        if core:
            phases.append(("Core Enumeration", core))

        # Phase 2: Platform-specific (uses data from Phase 1)
        platform = [m for m in self._modules if m.category in (
            ModuleCategory.SOCIAL, ModuleCategory.IRANIAN,
        )]
        if platform:
            phases.append(("Platform Recon", platform))

        # Phase 3: Enrichment (uses all discovered data)
        enrichment = [m for m in self._modules if m.category == ModuleCategory.ENRICHMENT]
        if enrichment:
            phases.append(("Data Enrichment", enrichment))

        # Phase 4: Infrastructure & Breach (independent, heavy)
        infra = [m for m in self._modules if m.category in (
            ModuleCategory.INFRASTRUCTURE, ModuleCategory.BREACH, ModuleCategory.DOMAIN,
        )]
        if infra:
            phases.append(("Infrastructure & Breach", infra))

        return phases

    async def execute(self) -> dict:
        """Execute the full pipeline."""
        start = time.time()

        print(f"\n{'#'*60}")
        print(f"  Social-Recon v2.0 — Target: {self.target}")
        print(f"  Type: {self.target_type} | Mode: {self.mode}")
        print(f"  Modules: {len(self._modules)}")
        print(f"{'#'*60}")

        phases = self._group_modules_by_phase()

        for phase_name, modules in phases:
            await self._run_phase(modules, phase_name)

        total_time = time.time() - start
        total_findings = len(self.all_findings)
        successful = sum(1 for r in self.results.values() if r.success)

        print(f"\n{'#'*60}")
        print(f"  COMPLETE — {total_findings} findings from {successful}/{len(self.results)} modules")
        print(f"  Time: {total_time:.1f}s")
        print(f"  Output: {self.output_dir}")
        print(f"{'#'*60}")

        # Save results
        await self._save_results(total_time)

        return {
            "target": self.target,
            "target_type": self.target_type,
            "mode": self.mode,
            "total_findings": total_findings,
            "modules_run": len(self.results),
            "modules_successful": successful,
            "duration": total_time,
            "context": self.context,
            "results": {name: {"success": r.success, "findings": len(r.findings), "errors": r.errors, "duration": r.duration}
                       for name, r in self.results.items()},
        }

    async def _save_results(self, total_time: float):
        """Save all results to files."""
        # Save master JSON
        output = {
            "target": self.target,
            "target_type": self.target_type,
            "mode": self.mode,
            "timestamp": time.time(),
            "duration": total_time,
            "context": {
                "emails": self.context["emails"],
                "phones": self.context["phones"],
                "usernames": self.context["usernames"],
                "profiles": list(self.context["profiles"].keys()),
            },
            "findings": [f.to_dict() for f in self.all_findings],
            "modules": {
                name: {
                    "success": r.success,
                    "findings_count": len(r.findings),
                    "errors": r.errors,
                    "duration": r.duration,
                }
                for name, r in self.results.items()
            },
        }

        out_file = self.output_dir / "recon_results.json"
        out_file.write_text(json.dumps(output, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        print(f"\n  [+] Results saved: {out_file}")


async def run_pipeline(target: str, mode: str = "full") -> dict:
    """Convenience function to run the full pipeline."""
    from .input_classifier import classify
    from ..modules.iranian_platforms import get_iranian_modules
    from ..modules.breach_checker import BreachChecker
    from ..modules.phone_intel import PhoneIntel
    from ..modules.email_enricher import EmailEnricher
    from ..modules.cert_transparency import CertTransparency
    from ..modules.telegram_eagle import TelegramEagleEye
    from ..modules.google_dorking import GoogleDorking
    from ..modules.image_osint import ImageOSINT
    from ..modules.secret_scanner import SecretScanner
    from ..utils.report import generate_report

    target_type, clean = classify(target)
    pipeline = Pipeline(target=target, target_type=target_type, mode=mode)

    all_modules = []

    # Always include: Iranian platforms (our competitive advantage)
    all_modules.extend(get_iranian_modules(pipeline.config))

    # Always include: Telegram Eagle Eye (huge in Iran)
    all_modules.append(TelegramEagleEye(pipeline.config))

    if mode in ("full", "hawk"):
        all_modules.append(EmailEnricher(pipeline.config))
        all_modules.append(PhoneIntel(pipeline.config))
        all_modules.append(BreachChecker(pipeline.config))
        all_modules.append(GoogleDorking(pipeline.config))
        all_modules.append(ImageOSINT(pipeline.config))

    if mode == "hawk":
        all_modules.append(CertTransparency(pipeline.config))
        all_modules.append(SecretScanner(pipeline.config))

    pipeline.register_modules(all_modules)
    result = await pipeline.execute()

    # Generate reports (Markdown + HTML)
    try:
        reports = generate_report(pipeline.output_dir, result)
        result["reports"] = reports
    except Exception as e:
        print(f"  [-] Report generation error: {e}")

    return result
