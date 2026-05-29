"""repository_safety_check.py — gate a high-impact action behind a code check.

The written walkthrough lives in
``docs/integrations/repository_safety_check.md``. This script is the runnable
companion. It shows the Weaver-ecosystem pattern for running a deterministic
repository check *as a policy-controlled capability* before an agent performs a
high-impact action (publishing an artifact):

  1. ``repo.code_safety_check`` is a capability backed by a driver that *shells
     out* to a local command. agent-kernel records the command result in an
     audit trace, exactly like any other capability.
  2. ``repo.publish_artifact`` is the high-impact WRITE action. The host refuses
     to grant it until a fresh safety check has passed.
  3. A clean change passes the check and publishes.
  4. A risky change produces findings; the host blocks the publish and the
     check result is still auditable.

The checker here is a tiny embedded scanner run via ``sys.executable`` so the
demo is deterministic, offline, and dependency-free. In production you would
point ``RepositoryCheckDriver`` at a real command such as ``vibeguard`` (e.g.
``["vibeguard", "scan", "--json"]``); agent-kernel does not depend on any
specific checker.

Run with: ``python examples/repository_safety_check.py``
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

os.environ.setdefault("AGENT_KERNEL_SECRET", "example-secret-do-not-use-in-prod")

from agent_kernel import (
    Capability,
    CapabilityRegistry,
    HMACTokenProvider,
    InMemoryDriver,
    Kernel,
    Principal,
    SafetyClass,
    StaticRouter,
)
from agent_kernel.drivers.base import ExecutionContext
from agent_kernel.errors import DriverError
from agent_kernel.models import CapabilityRequest, ImplementationRef, RawResult

_SECRET = "example-secret-do-not-use-in-prod"

# Embedded stand-in for a real checker (e.g. VibeGuard). Reads a file path from
# argv[1], scans for a few banned patterns, prints findings as a JSON array on
# stdout, and exits 1 when it finds anything (0 when clean) — the exit-code
# convention most repo scanners follow. Kept deliberately small and
# deterministic so this example runs in CI without a real scanner installed.
_CHECKER_SOURCE = r"""
import json
import sys

BANNED = {
    "os.system(": "use of os.system — prefer a sandboxed driver",
    "eval(": "use of eval on untrusted input",
    "subprocess.call(": "unchecked subprocess call",
    "AKIA": "hardcoded AWS access key id",
}

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    lines = handle.readlines()

findings = []
for number, text in enumerate(lines, start=1):
    for needle, message in BANNED.items():
        if needle in text:
            findings.append(
                {"rule": needle.rstrip("("), "severity": "high", "line": number, "message": message}
            )

json.dump(findings, sys.stdout)
sys.exit(1 if findings else 0)
"""

# Two synthetic, in-repo "staged changes". One is clean; one trips the scanner.
_CLEAN_SNIPPET = '''\
def total_price(items):
    """Sum the price of every item."""
    return sum(item["price"] for item in items)
'''

_RISKY_SNIPPET = """\
import os

def purge_cache():
    os.system("rm -rf /tmp/build-cache")  # blocking finding

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # blocking finding
"""


class RepositoryCheckDriver:
    """Driver that runs a repository safety check by shelling out to a command.

    The command is invoked as ``[*command, path]`` and is expected to print a
    JSON array of findings to stdout and exit non-zero when findings exist
    (exit ``0`` = clean, ``1`` = findings). Any other exit code is treated as
    the checker itself failing and surfaces as a :class:`DriverError`.
    """

    def __init__(self, command: list[str], *, driver_id: str = "repo_safety") -> None:
        self._command = list(command)
        self._driver_id = driver_id

    @property
    def driver_id(self) -> str:
        """Unique identifier for this driver."""
        return self._driver_id

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        """Run the configured checker against ``ctx.args['path']``."""
        path = ctx.args.get("path")
        if not path:
            raise DriverError(
                "repository check requires a 'path' argument naming the file to scan"
            )
        proc = await asyncio.create_subprocess_exec(
            *self._command,
            str(path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode not in (0, 1):
            detail = stderr.decode(errors="replace").strip()
            raise DriverError(
                f"repository check command exited {proc.returncode}: {detail or '<no stderr>'}"
            )
        try:
            findings = json.loads(stdout or b"[]")
        except json.JSONDecodeError as exc:
            raise DriverError(f"repository check produced non-JSON output: {stdout!r}") from exc
        return RawResult(
            capability_id=ctx.capability_id,
            data=findings,
            metadata={"exit_code": proc.returncode},
        )


def build_kernel() -> Kernel:
    """Wire a kernel with the check capability and the gated publish action."""
    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id="repo.code_safety_check",
            name="Repository Safety Check",
            description="Run a deterministic safety scan over staged changes",
            safety_class=SafetyClass.READ,
            tags=["repo", "safety", "check", "scan"],
            impl=ImplementationRef(driver_id="repo_safety", operation="code_safety_check"),
        )
    )
    registry.register(
        Capability(
            capability_id="repo.publish_artifact",
            name="Publish Artifact",
            description="Publish a build artifact to the release channel",
            safety_class=SafetyClass.WRITE,
            tags=["repo", "publish", "release", "artifact"],
            impl=ImplementationRef(driver_id="memory", operation="publish"),
        )
    )

    publish_driver = InMemoryDriver()

    def publish(ctx: ExecutionContext) -> dict[str, object]:
        return {"artifact": ctx.args.get("artifact", "build.tar.gz"), "published": True}

    publish_driver.register_handler("publish", publish)

    router = StaticRouter(
        routes={
            "repo.code_safety_check": ["repo_safety"],
            "repo.publish_artifact": ["memory"],
        }
    )
    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret=_SECRET),
        router=router,
    )
    kernel.register_driver(RepositoryCheckDriver(command=[sys.executable, "-c", _CHECKER_SOURCE]))
    kernel.register_driver(publish_driver)
    return kernel


async def run_safety_check(
    kernel: Kernel, principal: Principal, path: str
) -> tuple[bool, list[dict[str, object]], str]:
    """Run the policy-controlled safety check and return ``(passed, findings, action_id)``.

    Reads findings from the firewalled Frame in ``table`` mode: an empty preview
    means no findings (the change is clean). This keeps the gate decision on the
    audited Frame rather than on raw driver output.
    """
    request = CapabilityRequest(
        capability_id="repo.code_safety_check",
        goal="scan staged changes before publishing",
    )
    token = kernel.get_token(request, principal, justification="")
    frame = await kernel.invoke(
        token,
        principal=principal,
        args={"operation": "code_safety_check", "path": path},
        response_mode="table",
    )
    findings = list(frame.table_preview)
    return (not findings, findings, frame.action_id)


async def publish_artifact(kernel: Kernel, principal: Principal, artifact: str) -> str:
    """Grant + invoke the gated publish action and return its audit ``action_id``."""
    request = CapabilityRequest(
        capability_id="repo.publish_artifact",
        goal="publish the build artifact to the release channel",
    )
    token = kernel.get_token(
        request,
        principal,
        justification="release approved: safety check passed, publishing tagged build",
    )
    frame = await kernel.invoke(
        token, principal=principal, args={"operation": "publish", "artifact": artifact}
    )
    return frame.action_id


async def attempt_publish(kernel: Kernel, principal: Principal, label: str, snippet: str) -> None:
    """Run the check-then-publish gate over one staged change."""
    print(f"\n=== Change: {label} ===")
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "staged_change.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(snippet)

        passed, findings, check_action = await run_safety_check(kernel, principal, path)
        print(f"  check: {'PASS' if passed else 'BLOCK'} ({len(findings)} finding(s))")
        for finding in findings:
            print(
                f"    • line {finding.get('line')}: {finding.get('rule')} — {finding.get('message')}"
            )
        # The safety check is always auditable, whether it passed or blocked.
        check_trace = kernel.explain(check_action)
        print(f"  audited check: action_id={check_trace.action_id} driver={check_trace.driver_id}")

        if not passed:
            # Policy-controlled gate: do NOT grant the publish capability when
            # the safety check found blocking issues.
            print("  publish: SKIPPED — safety check returned blocking findings")
            assert findings, "block path must carry findings"
            return

        publish_action = await publish_artifact(kernel, principal, artifact=f"{label}.tar.gz")
        publish_trace = kernel.explain(publish_action)
        assert not findings, "pass path must have zero findings"
        print(f"  publish: DONE — action_id={publish_trace.action_id}")


async def main() -> None:
    kernel = build_kernel()
    # A release agent: may read (run checks) and write (publish), not an admin.
    agent = Principal(principal_id="release-bot", roles=["reader", "writer"])

    print("=== Repository safety check as a policy-controlled capability ===")
    await attempt_publish(kernel, agent, "clean-change", _CLEAN_SNIPPET)
    await attempt_publish(kernel, agent, "risky-change", _RISKY_SNIPPET)

    print("\n✓ repository_safety_check.py complete.")


if __name__ == "__main__":
    asyncio.run(main())
