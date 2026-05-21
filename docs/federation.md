# Capability Federation — Marketplace Part 1

> Issue [#52](https://github.com/dgenio/agent-kernel/issues/52) (manifest
> format & local registry) is implemented here. Discovery over a network
> (issue [#51](https://github.com/dgenio/agent-kernel/issues/51)) is **not**
> part of this milestone — `agent-kernel` does not fetch manifests over
> HTTP or sign them on your behalf yet. Bring your own transport for now.

## What this gives you

A single kernel can:

1. **Advertise** its capabilities as a JSON-serialisable
   [`CapabilityManifest`](../src/agent_kernel/models.py).
2. **Import** another kernel's manifest, registering each capability locally
   and routing invocations through a caller-supplied driver
   (typically [`HTTPDriver`](integrations.md) or
   [`MCPDriver`](integrations.md)).

Every imported invocation still runs through the *local* policy → token →
firewall pipeline. The remote endpoint is never trusted to authorise on the
importing kernel's behalf. This keeps weaver-spec invariants intact for
imported capabilities:

| Invariant | How it's enforced for imports |
|-----------|------------------------------|
| **I-01** — Firewall on every result | The local `Firewall` runs on the driver's `RawResult` exactly as for native capabilities. |
| **I-02** — Authorize + audit each call | The local `PolicyEngine` evaluates every request; the local `TraceStore` records every action. |
| **I-06** — Tokens bind principal + capability + constraints | Tokens are signed with the importing kernel's HMAC secret. A token issued by Kernel A cannot be verified by Kernel B, because their secrets differ. |

## Publishing a manifest

```python
from agent_kernel import (
    Capability, CapabilityRegistry, HMACTokenProvider, Kernel,
    SafetyClass, SensitivityTag,
)

registry = CapabilityRegistry()
registry.register(
    Capability(
        capability_id="billing.invoices.list",
        name="List Invoices",
        description="List recent invoices",
        safety_class=SafetyClass.READ,
        sensitivity=SensitivityTag.PII,
        tags=["billing", "invoices"],
    )
)

kernel = Kernel(
    registry=registry,
    token_provider=HMACTokenProvider(secret="…"),
    kernel_id="agent-b",
)

manifest = kernel.advertise(endpoint="https://agent-b.example/kernel")
print(manifest.to_dict())
# {
#   "kernel_id": "agent-b",
#   "version": "1",
#   "endpoint": "https://agent-b.example/kernel",
#   "trust_level": "unverified",
#   "capabilities": [
#     {
#       "capability_id": "billing.invoices.list",
#       "name": "List Invoices",
#       …
#     }
#   ]
# }
```

The manifest deliberately omits internal driver IDs, operation names,
`parameters_model` Python references, and `tool_hints`. Only the
[`CapabilityDescriptor`](../src/agent_kernel/models.py) projection of each
capability is published.

## Importing a manifest

```python
import json

import httpx
from agent_kernel import (
    CapabilityManifest, CapabilityRegistry, HMACTokenProvider, Kernel,
)
from agent_kernel.drivers.http import HTTPDriver, HTTPEndpoint

# 1. Fetch the manifest by whatever transport suits you.
raw = httpx.get("https://agent-b.example/kernel/manifest").json()
manifest = CapabilityManifest.from_dict(raw)

# 2. Build a local driver pointing at the remote endpoint.
remote = HTTPDriver(driver_id="agent-b")
for cap in manifest.capabilities:
    remote.register_endpoint(
        cap.capability_id,
        HTTPEndpoint(url=f"{manifest.endpoint}/invoke/{cap.capability_id}",
                     method="POST"),
    )

# 3. Import. `import_remote` registers the driver and adds routes.
kernel = Kernel(
    registry=CapabilityRegistry(),
    token_provider=HMACTokenProvider(secret="local-secret"),
    kernel_id="agent-a",
)
kernel.import_remote(manifest, driver=remote, trust_policy="most_restrictive")

# 4. Use imported capabilities exactly like local ones.
for cap in kernel.list_capabilities():
    print(cap.capability_id, "→", cap.impl.driver_id)
```

## Trust policies

`import_remote(manifest, driver=..., trust_policy=...)` accepts three
values for `trust_policy`:

| Value | Sensitivity handling | When to use |
|-------|---------------------|-------------|
| `"most_restrictive"` *(default)* | Imported capability keeps the remote `SensitivityTag` verbatim — the local firewall will then redact accordingly. | Crossing trust boundaries — when you can't fully verify the remote's policy. |
| `"local_only"` | Imported capability is registered with `SensitivityTag.NONE`; the importing kernel's policy is the only thing that gates the call. | You own both kernels and have a single canonical policy. |
| `"remote_deferred"` | Same sensitivity handling as `most_restrictive` today. Reserved for part 2, when the importing kernel will be able to defer to a remote policy decision before applying its own. | Delegation patterns where the remote owns the authoritative policy. |

`merge_sensitivity(local, remote)` is exported for callers that maintain
their own capability records and want the canonical strictest-wins union.

## What is *not* covered yet

- **No network transport.** `agent-kernel` does not fetch, sign, or
  authenticate manifests over HTTP — bring your own transport. Part 2
  (issue #51) adds an opt-in manifest endpoint and a discovery protocol.
- **No remote policy delegation.** `"remote_deferred"` currently behaves
  identically to `"most_restrictive"`. The full "remote policy decides
  first" semantics need part 2.
- **No automatic re-import.** Manifests are imported once. If the publisher
  adds capabilities, the importer must re-fetch and re-import.
- **No identity verification.** `trust_level` is a publisher-declared hint;
  it does not authenticate the publisher. Signature verification arrives
  with part 2.

## Reference

- Models: [`CapabilityDescriptor`](../src/agent_kernel/models.py),
  [`CapabilityManifest`](../src/agent_kernel/models.py).
- Functions: [`build_manifest`](../src/agent_kernel/federation.py),
  [`import_manifest`](../src/agent_kernel/federation.py),
  [`merge_sensitivity`](../src/agent_kernel/federation.py).
- Kernel methods: `Kernel.advertise()`, `Kernel.import_remote()`,
  `Kernel.kernel_id`.
- Errors: `FederationError`, `ManifestError`, `TrustPolicyError`.
