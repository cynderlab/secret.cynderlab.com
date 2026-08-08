"""Generate a CycloneDX 1.6 SBOM (sbom.json) for the whole project.

Covers: every locked Python dependency (runtime vs dev scope resolved from the
uv.lock graph), the vendored JavaScript, and the bundled font files. Pure
stdlib — regenerate any time with:  uv run python scripts/gen_sbom.py
"""

import hashlib
import json
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "sbom.json"

# Components no lockfile knows about: vendored code and embedded assets.
EXTRA_COMPONENTS = [
    {
        "type": "library",
        "name": "qrcode-generator",
        "version": "1.5.0",
        "purl": "pkg:npm/qrcode-generator@1.5.0",
        "licenses": [{"license": {"id": "MIT"}}],
        "description": "Vendored QR encoder (Kazuhiko Arase), static/js/vendor/qrcode.js",
        "_hash_file": "static/js/vendor/qrcode.js",
    },
    {
        "type": "file",
        "name": "JetBrains Mono (font family)",
        "version": "bundled",
        "licenses": [{"license": {"id": "OFL-1.1"}}],
        "description": "Self-hosted webfont, static/fonts/JetBrainsMono-*.ttf",
        "_hash_file": "static/fonts/JetBrainsMono-Regular.ttf",
    },
    {
        "type": "file",
        "name": "Barlow / Barlow SemiCondensed (font family)",
        "version": "bundled",
        "licenses": [{"license": {"id": "OFL-1.1"}}],
        "description": "Self-hosted webfont, static/fonts/Barlow*.ttf",
        "_hash_file": "static/fonts/Barlow-Regular.ttf",
    },
]


def sha256_of(rel_path: str) -> str:
    return hashlib.sha256((ROOT / rel_path).read_bytes()).hexdigest()


def load_lock() -> tuple[dict, dict[str, dict]]:
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    packages = {p["name"]: p for p in lock["package"]}
    root = next(p for p in lock["package"]
                if p.get("source", {}).get("virtual") == ".")
    return root, packages


def runtime_closure(root: dict, packages: dict[str, dict]) -> set[str]:
    """Names reachable from the project's runtime dependencies, extras included
    (e.g. uvicorn[standard] pulls uvloop/httptools into the runtime scope)."""
    seen: set[str] = set()
    queue = [(d["name"], tuple(d.get("extra", []))) for d in root.get("dependencies", [])]
    while queue:
        name, extras = queue.pop()
        if name not in packages:
            continue
        if name in seen and not extras:
            continue
        seen.add(name)
        pkg = packages[name]
        deps = list(pkg.get("dependencies", []))
        for extra in extras:
            deps += pkg.get("optional-dependencies", {}).get(extra, [])
        queue += [(d["name"], tuple(d.get("extra", []))) for d in deps]
    return seen


def package_component(pkg: dict, runtime: set[str]) -> dict:
    component = {
        "type": "library",
        "name": pkg["name"],
        "version": pkg["version"],
        "purl": f"pkg:pypi/{pkg['name']}@{pkg['version']}",
        "scope": "required" if pkg["name"] in runtime else "optional",
        "properties": [{"name": "cynderlab:dependency-group",
                        "value": "runtime" if pkg["name"] in runtime else "dev"}],
    }
    sdist_hash = pkg.get("sdist", {}).get("hash", "")
    if sdist_hash.startswith("sha256:"):
        component["hashes"] = [{"alg": "SHA-256", "content": sdist_hash[7:]}]
    return component


def main() -> None:
    root, packages = load_lock()
    runtime = runtime_closure(root, packages)

    components = [package_component(p, runtime)
                  for name, p in sorted(packages.items()) if name != root["name"]]
    for extra in EXTRA_COMPONENTS:
        entry = {k: v for k, v in extra.items() if not k.startswith("_")}
        entry["scope"] = "required"
        entry["hashes"] = [{"alg": "SHA-256", "content": sha256_of(extra["_hash_file"])}]
        components.append(entry)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"name": "scripts/gen_sbom.py",
                       "vendor": "CYNDERLAB DIGITAL SL"}],
            "component": {
                "type": "application",
                "name": "secret.cynderlab.com",
                "version": root["version"],
                "description": "One-time secret sharing — browser-side encryption, burn on read",
                "licenses": [{"license": {"id": "MIT"}}],
                "externalReferences": [
                    {"type": "vcs",
                     "url": "https://github.com/cynderlab/secret.cynderlab.com"},
                    {"type": "website", "url": "https://secret.cynderlab.com"},
                ],
            },
        },
        "components": components,
    }

    OUT.write_text(json.dumps(bom, indent=2, ensure_ascii=False) + "\n")
    n_runtime = sum(1 for c in components if c.get("scope") == "required")
    print(f"sbom.json written: {len(components)} components "
          f"({n_runtime} runtime, {len(components) - n_runtime} dev)")


if __name__ == "__main__":
    main()
