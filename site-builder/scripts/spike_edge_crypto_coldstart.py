#!/usr/bin/env python3
"""3c-0 spike: Lambda cold-start cost of vendoring `cryptography` into the Edge runtime.

Measures two python3.11 / x86_64 Lambda functions in us-east-1:

  A  spike-3c-edge-crypto-stdlib    stdlib-only imports, returns {"ok": true}
  B  spike-3c-edge-crypto-vendored  vendored `cryptography` in its **final verifier
                                    form**: the public key is parsed at module scope
                                    and one warm-up verify runs at import time, so the
                                    handler does nothing but `PUB.verify(...)`

Per config (arm x memory) it collects 20 cold starts, and after each cold invoke it
runs 3 warm invokes of the same execution environment.

Decision rule (restated after review): vendored is accepted if the added TOTAL
cold-path latency (Init Duration + first-invoke Duration, vendored minus stdlib at
the same memory) has median <= 300 ms and p95 <= 600 ms.

Safety: every resource this script creates is named with the prefix
`spike-3c-edge-crypto-`. It refuses to run unless the caller's account matches
`account_id` in site-builder/config.ini, refuses to run if anything with that prefix
already exists, cleans up in a `finally` block, and exits non-zero if cleanup leaves
anything behind.

Run with the repo's Homebrew `python3` (>= 3.10):

    python3 site-builder/scripts/spike_edge_crypto_coldstart.py
    python3 site-builder/scripts/spike_edge_crypto_coldstart.py --regen-requirements
"""

from __future__ import annotations

import argparse
import base64
import configparser
import hashlib
import json
import math
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import traceback
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

REGION = "us-east-1"
PREFIX = "spike-3c-edge-crypto-"
FN_STDLIB = PREFIX + "stdlib"
FN_VENDORED = PREFIX + "vendored"
ARMS = (FN_STDLIB, FN_VENDORED)
ROLE_NAME = PREFIX + "role"
BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

RUNTIME = "python3.11"
ARCH = "x86_64"
HANDLER = "index.lambda_handler"
TIMEOUT_S = 30
MEMORIES = (128, 256)
COLD_SAMPLES = 20
WARM_PER_COLD = 3
MAX_ATTEMPTS_PER_CONFIG = 40

TOP_REQUIREMENT = "cryptography==50.0.0"
PIP_PLATFORM = "manylinux2014_x86_64"
PIP_PYVER = "3.11"
PIP_IMPL = "cp"

RULE_TOTAL_MEDIAN_MAX_MS = 300
RULE_TOTAL_P95_MAX_MS = 600

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = Path(__file__).resolve().parent
REQUIREMENTS_FILE = SCRIPT_DIR / "spike_edge_crypto_requirements.txt"
RAW_DIR = REPO_ROOT / "docs" / "design" / "3c-spike"

# REPORT line parsing. The fixed-width negative lookbehinds keep bare `Duration:`
# from matching the `Billed Duration:` / `Init Duration:` fields.
RE_INIT = re.compile(r"\bInit Duration:\s+([\d.]+)\s+ms")
RE_BILLED = re.compile(r"\bBilled Duration:\s+([\d.]+)\s+ms")
RE_DURATION = re.compile(r"(?<!Billed )(?<!Init )\bDuration:\s+([\d.]+)\s+ms")
RE_MAXMEM = re.compile(r"\bMax Memory Used:\s+([\d.]+)\s+MB")
RE_REPORT = re.compile(r"^REPORT\s", re.MULTILINE)


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}Z] {msg}", flush=True)


# ---------------------------------------------------------------- preconditions


def config_account_id() -> str:
    cfg_path = REPO_ROOT / "site-builder" / "config.ini"
    if not cfg_path.exists():
        raise SystemExit(f"ABORT: {cfg_path} missing; cannot verify target account")
    parser = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    parser.read(cfg_path)
    if not parser.sections():
        raise SystemExit("ABORT: config.ini parsed to zero sections")
    found: set[str] = set()
    for section in parser.sections():
        if parser.has_option(section, "account_id"):
            found.add(parser.get(section, "account_id").strip())
    if len(found) != 1:
        raise SystemExit(f"ABORT: expected exactly one account_id in config.ini, found {len(found)}")
    return found.pop()


def assert_target_account() -> str:
    expected = config_account_id()
    actual = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    if actual != expected:
        raise SystemExit(
            "ABORT: caller account does not match config.ini "
            f"(caller ...{actual[-4:]} vs config ...{expected[-4:]})"
        )
    log(f"account check ok (...{actual[-4:]}), region {REGION}")
    return actual


def list_prefixed(iam, lam, logs) -> dict[str, list[str]]:
    functions = [
        fn["FunctionName"]
        for page in lam.get_paginator("list_functions").paginate()
        for fn in page["Functions"]
        if fn["FunctionName"].startswith(PREFIX)
    ]
    groups = [
        grp["logGroupName"]
        for grp in logs.describe_log_groups(logGroupNamePrefix=f"/aws/lambda/{PREFIX}").get(
            "logGroups", []
        )
    ]
    roles: list[str] = []
    try:
        iam.get_role(RoleName=ROLE_NAME)
        roles.append(ROLE_NAME)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    return {"functions": functions, "log_groups": groups, "roles": roles}


def assert_nothing_preexists(iam, lam, logs) -> None:
    """P2 fix: never reuse a leftover from an earlier run. Refuse instead."""
    existing = list_prefixed(iam, lam, logs)
    if any(existing.values()):
        lines = [f"  {kind}: {names}" for kind, names in existing.items() if names]
        raise SystemExit(
            "ABORT: resources with the spike prefix already exist. This run would "
            "reuse or clobber them, which makes the measurement unreproducible.\n"
            + "\n".join(lines)
            + "\nDelete them by hand, then rerun."
        )
    log("pre-flight ok: no functions / log groups / role with the spike prefix exist")


# ------------------------------------------------------------- key material gen

KEYGEN_SRC = r'''
import base64, json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Throwaway key. The private half never leaves this process.
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub_pem = key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("ascii")


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


header = b64u(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "spike-3c-0"},
                         separators=(",", ":")).encode())
payload_obj = {
    "sub": "spike-user@example.invalid",
    "email": "spike-user@example.invalid",
    "token_use": "session",
    "aud": "app.example.invalid",
    "iat": 1767225600,
    "exp": 1767312000,
    "rev": 7,
    "pad": "",
}
while True:
    payload = b64u(json.dumps(payload_obj, separators=(",", ":")).encode())
    msg = (header + "." + payload).encode("ascii")
    if len(msg) >= 350:
        break
    payload_obj["pad"] += "x" * 8

sig = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
import cryptography
print(json.dumps({
    "public_key_pem": pub_pem,
    "message": msg.decode("ascii"),
    "message_len": len(msg),
    "signature_b64": base64.b64encode(sig).decode("ascii"),
    "keygen_cryptography_version": cryptography.__version__,
}))
'''


def generate_key_material() -> dict:
    """Generate PEM + message + signature with the contract venv (native cryptography).

    The manylinux target dir built for Lambda is not importable on macOS, so the
    signing side uses the repo's existing macOS-native cryptography install.
    """
    venv_py = REPO_ROOT / "site-builder" / "contract" / ".venv" / "bin" / "python"
    if not venv_py.exists():
        raise SystemExit(f"ABORT: {venv_py} missing (rebuild the contract venv)")
    proc = subprocess.run(
        [str(venv_py), "-c", KEYGEN_SRC], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise SystemExit(f"ABORT: key generation failed\n{proc.stderr}")
    data = json.loads(proc.stdout)
    log(
        "key material generated with cryptography "
        f"{data['keygen_cryptography_version']} (message {data['message_len']} bytes)"
    )
    return data


# ------------------------------------------------------- hash-pinned requirements

PIP_TARGET_FLAGS = [
    "--platform",
    PIP_PLATFORM,
    "--only-binary",
    ":all:",
    "--python-version",
    PIP_PYVER,
    "--implementation",
    PIP_IMPL,
]


def pip_hash_of(wheel: Path) -> str:
    """sha256 via `pip hash`, cross-checked against a local digest."""
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "hash", str(wheel)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"ABORT: pip hash failed for {wheel.name}\n{proc.stderr}")
    match = re.search(r"--hash=sha256:([0-9a-f]{64})", proc.stdout)
    if not match:
        raise SystemExit(f"ABORT: could not parse pip hash output for {wheel.name}:\n{proc.stdout}")
    pip_digest = match.group(1)
    local_digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if pip_digest != local_digest:
        raise SystemExit(f"ABORT: pip hash disagrees with local sha256 for {wheel.name}")
    return pip_digest


def generate_requirements(dest: Path) -> None:
    """`pip download` the manylinux cp311 wheel closure, then pin each with its hash."""
    with tempfile.TemporaryDirectory(prefix="spike-3c-dl-") as tmp:
        cmd = [
            sys.executable,
            "-m",
            "pip",
            "download",
            *PIP_TARGET_FLAGS,
            "-d",
            tmp,
            TOP_REQUIREMENT,
        ]
        log("pip download: " + " ".join(cmd[3:]))
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise SystemExit(
                "ABORT: pip download failed (no fallback to native macOS wheels)\n"
                f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
            )
        wheels = sorted(Path(tmp).glob("*.whl"))
        if not wheels:
            raise SystemExit(f"ABORT: pip download produced no wheels\n{proc.stdout}")
        entries: list[tuple[str, str, str]] = []
        for wheel in wheels:
            name, version = wheel.name.split("-")[0], wheel.name.split("-")[1]
            entries.append((name.replace("_", "-"), version, pip_hash_of(wheel)))
    entries.sort()
    body = [
        "# Hash-pinned wheel closure for the 3c-0 edge crypto cold-start spike.",
        "# Generated by site-builder/scripts/spike_edge_crypto_coldstart.py",
        f"# --regen-requirements, targeting {PIP_PLATFORM} / {PIP_IMPL}{PIP_PYVER.replace('.', '')}.",
        f"# Top-level requirement: {TOP_REQUIREMENT}. Installed with --require-hashes,",
        "# without --no-deps, so pip also proves this closure is complete.",
        "",
    ]
    for name, version, digest in entries:
        body.append(f"{name}=={version} \\")
        body.append(f"    --hash=sha256:{digest}")
    dest.write_text("\n".join(body) + "\n", encoding="utf-8")
    log(f"wrote {dest.name} with {len(entries)} pinned wheels")


def pip_install_pinned(target: Path) -> dict:
    if not REQUIREMENTS_FILE.exists():
        log(f"{REQUIREMENTS_FILE.name} absent; generating it")
        generate_requirements(REQUIREMENTS_FILE)
    else:
        log(f"using existing {REQUIREMENTS_FILE.name} (pass --regen-requirements to rebuild)")
    req_sha = hashlib.sha256(REQUIREMENTS_FILE.read_bytes()).hexdigest()
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        *PIP_TARGET_FLAGS,
        "--require-hashes",
        "-r",
        str(REQUIREMENTS_FILE),
        "--target",
        str(target),
    ]
    log("pip install (hash-checked): " + " ".join(cmd[3:]))
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise SystemExit(
            "ABORT: hash-checked pip cross-install failed (no fallback to native wheels)\n"
            f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
        )
    versions: dict[str, str] = {}
    for entry in sorted(target.glob("*.dist-info")):
        name, _, ver = entry.name[: -len(".dist-info")].rpartition("-")
        versions[name.lower().replace("_", "-")] = ver
    log("vendored wheels: " + ", ".join(f"{k}=={v}" for k, v in sorted(versions.items())))
    return {
        "versions": versions,
        "requirements_file": str(REQUIREMENTS_FILE.relative_to(REPO_ROOT)),
        "requirements_sha256": req_sha,
        "pip_install_args": cmd[3:],
    }


# ---------------------------------------------------------------- zip building

INDEX_STDLIB = '''"""Stdlib-only baseline for the 3c-0 cold-start spike."""

import base64
import hashlib
import hmac
import json
import time


def lambda_handler(event, context):
    return {"ok": True}
'''

# Final verifier form: parse the SPKI once at import, warm the verify path once at
# import, and leave the handler with nothing but the verify call.
INDEX_VENDORED_TMPL = '''"""Vendored-cryptography arm of the 3c-0 cold-start spike (final verifier form)."""

import base64
import hashlib
import hmac
import json
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

PUBLIC_KEY_PEM = {pem!r}
MESSAGE = {message!r}
SIGNATURE = base64.b64decode({sig!r})

PUB = serialization.load_pem_public_key(PUBLIC_KEY_PEM)
PAD = padding.PKCS1v15()
ALG = hashes.SHA256()

# One warm-up verify at import time. If the embedded material is wrong this raises
# during Init, so a broken build fails loudly instead of quietly measuring nothing.
PUB.verify(SIGNATURE, MESSAGE, PAD, ALG)


def lambda_handler(event, context):
    PUB.verify(SIGNATURE, MESSAGE, PAD, ALG)
    return {{"ok": True}}
'''


def build_zip(zip_path: Path, source_dir: Path) -> dict:
    uncompressed = 0
    file_count = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(source_dir.rglob("*")):
            if "__pycache__" in path.parts or path.name.endswith(".pyc"):
                continue
            if not path.is_file():
                continue
            zf.write(path, str(path.relative_to(source_dir)))
            uncompressed += path.stat().st_size
            file_count += 1
    blob = zip_path.read_bytes()
    return {
        "compressed_bytes": len(blob),
        "uncompressed_bytes": uncompressed,
        "file_count": file_count,
        "sha256": hashlib.sha256(blob).hexdigest(),
        "zip_path": str(zip_path),
    }


def build_packages(workdir: Path, key_material: dict) -> tuple[dict, dict, dict]:
    a_dir = workdir / "stdlib"
    a_dir.mkdir(parents=True)
    (a_dir / "index.py").write_text(INDEX_STDLIB, encoding="utf-8")
    a_meta = build_zip(workdir / "stdlib.zip", a_dir)
    log(
        f"built {FN_STDLIB} zip: {a_meta['compressed_bytes']} B compressed / "
        f"{a_meta['uncompressed_bytes']} B uncompressed, {a_meta['file_count']} files"
    )

    b_dir = workdir / "vendored"
    b_dir.mkdir(parents=True)
    pin_info = pip_install_pinned(b_dir)
    index_src = INDEX_VENDORED_TMPL.format(
        pem=key_material["public_key_pem"].encode("ascii"),
        message=key_material["message"].encode("ascii"),
        sig=key_material["signature_b64"],
    )
    compile(index_src, "index.py", "exec")  # cheap syntax guard on the generated file
    (b_dir / "index.py").write_text(index_src, encoding="utf-8")
    b_meta = build_zip(workdir / "vendored.zip", b_dir)
    log(
        f"built {FN_VENDORED} zip: {b_meta['compressed_bytes']} B compressed / "
        f"{b_meta['uncompressed_bytes']} B uncompressed, {b_meta['file_count']} files"
    )
    return a_meta, b_meta, pin_info


# ------------------------------------------------------------------ AWS plumbing

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def guard_name(name: str) -> str:
    if not name.startswith(PREFIX):
        raise SystemExit(f"ABORT: refusing to touch resource outside prefix: {name!r}")
    return name


def create_role(iam) -> str:
    guard_name(ROLE_NAME)
    resp = iam.create_role(
        RoleName=ROLE_NAME,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        Description="Throwaway execution role for the 3c-0 edge crypto cold-start spike",
    )
    log(f"created role {ROLE_NAME}")
    iam.attach_role_policy(RoleName=ROLE_NAME, PolicyArn=BASIC_EXEC_POLICY)
    log("attached AWSLambdaBasicExecutionRole")
    return resp["Role"]["Arn"]


def create_function(lam, name: str, zip_path: str, role_arn: str) -> None:
    guard_name(name)
    blob = Path(zip_path).read_bytes()
    last_err: Exception | None = None
    for attempt in range(1, 9):
        try:
            lam.create_function(
                FunctionName=name,
                Runtime=RUNTIME,
                Role=role_arn,
                Handler=HANDLER,
                Code={"ZipFile": blob},
                MemorySize=MEMORIES[0],
                Timeout=TIMEOUT_S,
                Architectures=[ARCH],
                Publish=False,
                Environment={"Variables": {"SPIKE_NONCE": "init"}},
                Description="3c-0 cold-start spike; delete me",
            )
            log(f"created function {name} (attempt {attempt})")
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            log(f"create_function {name}: role not propagated yet (attempt {attempt}); retrying")
            time.sleep(5)
    else:
        raise SystemExit(f"ABORT: create_function {name} failed after 8 attempts: {last_err}")
    lam.get_waiter("function_active_v2").wait(
        FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )
    log(f"{name} active")


def update_and_wait(lam, name: str, **kwargs) -> None:
    guard_name(name)
    for _ in range(10):
        try:
            lam.update_function_configuration(FunctionName=name, **kwargs)
            break
        except lam.exceptions.ResourceConflictException:
            time.sleep(3)
    else:
        raise SystemExit(f"ABORT: update_function_configuration {name} stayed conflicted")
    lam.get_waiter("function_updated_v2").wait(
        FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )


def parse_report(log_text: str) -> dict | None:
    if not RE_REPORT.search(log_text):
        return None
    init = RE_INIT.search(log_text)
    dur = RE_DURATION.search(log_text)
    billed = RE_BILLED.search(log_text)
    maxmem = RE_MAXMEM.search(log_text)
    if dur is None:
        return None
    return {
        "init_duration_ms": float(init.group(1)) if init else None,
        "duration_ms": float(dur.group(1)),
        "billed_duration_ms": float(billed.group(1)) if billed else None,
        "max_memory_used_mb": float(maxmem.group(1)) if maxmem else None,
    }


def invoke_once(lam, name: str) -> dict:
    guard_name(name)
    resp = lam.invoke(
        FunctionName=name, InvocationType="RequestResponse", LogType="Tail", Payload=b"{}"
    )
    raw_payload = resp["Payload"].read().decode("utf-8", "replace")
    log_text = base64.b64decode(resp.get("LogResult", "")).decode("utf-8", "replace")
    if resp.get("FunctionError"):
        raise SystemExit(
            f"ABORT: {name} returned FunctionError={resp['FunctionError']}\n"
            f"payload: {raw_payload[:800]}\nlog tail:\n{log_text[-2000:]}"
        )
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        raise SystemExit(f"ABORT: {name} payload is not JSON: {raw_payload[:400]!r}")
    if payload.get("ok") is not True:
        raise SystemExit(f"ABORT: {name} payload ok is not true: {payload!r}")
    report = parse_report(log_text)
    if report is None:
        raise SystemExit(f"ABORT: could not parse REPORT line for {name}:\n{log_text[-2000:]}")
    report["ts"] = datetime.now(timezone.utc).isoformat()
    return report


def cold_plus_warm(lam, name: str, nonce: str) -> dict:
    """Force a fresh execution environment, invoke once cold, then WARM_PER_COLD warm."""
    update_and_wait(lam, name, Environment={"Variables": {"SPIKE_NONCE": nonce}})
    cold = invoke_once(lam, name)
    cold["nonce"] = nonce
    if cold["init_duration_ms"] is None:
        return {"cold": cold, "warm": [], "was_cold": False}
    warm = []
    for _ in range(WARM_PER_COLD):
        # No configuration change between these, so the same environment is reused.
        warm.append(invoke_once(lam, name))
    return {"cold": cold, "warm": warm, "was_cold": True}


# --------------------------------------------------------------------- stats


def percentile_nearest_rank(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(q * len(ordered)) - 1)]


def percentile_linear(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = q * (len(ordered) - 1)
    low, high = math.floor(pos), math.ceil(pos)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (pos - low)


def summarize(values: list[float]) -> dict:
    return {
        "n": len(values),
        "min": min(values),
        "median": statistics.median(values),
        "p95_nearest_rank": percentile_nearest_rank(values, 0.95),
        "p95_linear": percentile_linear(values, 0.95),
        "max": max(values),
        "mean": statistics.fmean(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def delta_block(vendored: list[float], stdlib: list[float]) -> dict:
    paired = [v - s for v, s in zip(vendored, stdlib)]
    return {
        "delta_median_ms": statistics.median(vendored) - statistics.median(stdlib),
        "delta_p95_ms": percentile_nearest_rank(vendored, 0.95)
        - percentile_nearest_rank(stdlib, 0.95),
        "delta_p95_ms_linear": percentile_linear(vendored, 0.95) - percentile_linear(stdlib, 0.95),
        "paired_delta_median_ms": statistics.median(paired),
        "paired_delta_p95_ms": percentile_nearest_rank(paired, 0.95),
        "paired_delta_min_ms": min(paired),
        "paired_delta_max_ms": max(paired),
    }


# ------------------------------------------------------------------- cleanup


def cleanup(iam, lam, logs) -> dict:
    result: dict = {"actions": [], "errors": [], "leftovers": {}}

    for name in ARMS:
        guard_name(name)
        try:
            lam.delete_function(FunctionName=name)
            result["actions"].append(f"deleted function {name}")
        except lam.exceptions.ResourceNotFoundException:
            result["actions"].append(f"function {name} absent")
        except ClientError as exc:
            result["errors"].append(f"delete_function {name}: {exc.response['Error']['Code']}")

    try:
        groups = logs.describe_log_groups(logGroupNamePrefix=f"/aws/lambda/{PREFIX}")
        for grp in groups.get("logGroups", []):
            gname = grp["logGroupName"]
            if not gname.startswith(f"/aws/lambda/{PREFIX}"):
                result["errors"].append(f"skipped unexpected log group {gname}")
                continue
            try:
                logs.delete_log_group(logGroupName=gname)
                result["actions"].append(f"deleted log group {gname}")
            except ClientError as exc:
                result["errors"].append(
                    f"delete_log_group {gname}: {exc.response['Error']['Code']}"
                )
        if not groups.get("logGroups"):
            result["actions"].append("no matching log groups")
    except ClientError as exc:
        result["errors"].append(f"describe_log_groups: {exc.response['Error']['Code']}")

    guard_name(ROLE_NAME)
    try:
        iam.detach_role_policy(RoleName=ROLE_NAME, PolicyArn=BASIC_EXEC_POLICY)
        result["actions"].append("detached AWSLambdaBasicExecutionRole")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "NoSuchEntity":
            result["actions"].append("policy already detached / role absent")
        else:
            result["errors"].append(f"detach_role_policy: {code}")
    try:
        iam.delete_role(RoleName=ROLE_NAME)
        result["actions"].append(f"deleted role {ROLE_NAME}")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "NoSuchEntity":
            result["actions"].append(f"role {ROLE_NAME} absent")
        else:
            result["errors"].append(f"delete_role: {code}")

    try:
        result["leftovers"] = list_prefixed(iam, lam, logs)
    except ClientError as exc:
        result["errors"].append(f"leftover verification: {exc.response['Error']['Code']}")
        result["leftovers"] = {"verification": ["FAILED"]}

    result["clean"] = all(not v for v in result["leftovers"].values()) and not result["errors"]
    return result


# ---------------------------------------------------------------------- main


def measure(lam, results: dict) -> None:
    for mem in MEMORIES:
        for name in ARMS:
            update_and_wait(lam, name, MemorySize=mem)
            log(f"{name} MemorySize={mem}")

        keys = {name: f"{name}@{mem}MB" for name in ARMS}
        for key in keys.values():
            results["samples"][key] = []
            results["discarded_non_cold"][key] = 0
            results["warm_unexpectedly_cold"][key] = 0
        attempts = {name: 0 for name in ARMS}

        # Interleave the two arms sample by sample so fleet drift hits both equally.
        for i in range(COLD_SAMPLES):
            for name in ARMS:
                key = keys[name]
                while len(results["samples"][key]) <= i:
                    if attempts[name] >= MAX_ATTEMPTS_PER_CONFIG:
                        raise SystemExit(
                            f"ABORT: {key} hit {MAX_ATTEMPTS_PER_CONFIG} attempts with only "
                            f"{len(results['samples'][key])} cold samples"
                        )
                    attempts[name] += 1
                    got = cold_plus_warm(lam, name, f"{mem}-{attempts[name]}")
                    if not got["was_cold"]:
                        results["discarded_non_cold"][key] += 1
                        log(f"{key}: attempt {attempts[name]} was warm; discarding")
                        continue
                    stray = [w for w in got["warm"] if w["init_duration_ms"] is not None]
                    if stray:
                        results["warm_unexpectedly_cold"][key] += len(stray)
                    results["samples"][key].append(
                        {
                            "cold": got["cold"],
                            "warm": got["warm"],
                            "total_cold_path_ms": got["cold"]["init_duration_ms"]
                            + got["cold"]["duration_ms"],
                        }
                    )
            a, b = (results["samples"][keys[n]][i] for n in ARMS)
            log(
                f"mem {mem} MB sample {i + 1}/{COLD_SAMPLES}: "
                f"stdlib total={a['total_cold_path_ms']:.1f} ms  "
                f"vendored total={b['total_cold_path_ms']:.1f} ms "
                f"(init {b['cold']['init_duration_ms']:.1f} + first {b['cold']['duration_ms']:.1f})"
            )
        results["attempts"][str(mem)] = attempts


def compute_stats(results: dict) -> None:
    def series(key: str) -> dict[str, list[float]]:
        samples = results["samples"][key]
        return {
            "init": [s["cold"]["init_duration_ms"] for s in samples],
            "first": [s["cold"]["duration_ms"] for s in samples],
            "total": [s["total_cold_path_ms"] for s in samples],
            "warm": [w["duration_ms"] for s in samples for w in s["warm"]],
            "maxmem": [
                v
                for s in samples
                for v in [s["cold"]["max_memory_used_mb"]]
                + [w["max_memory_used_mb"] for w in s["warm"]]
                if v is not None
            ],
        }

    for key in results["samples"]:
        s = series(key)
        results["summary"][key] = {
            "init_duration_ms": summarize(s["init"]),
            "first_invoke_duration_ms": summarize(s["first"]),
            "total_cold_path_ms": summarize(s["total"]),
            "warm_duration_ms": summarize(s["warm"]),
            "max_memory_used_mb": {
                "min": min(s["maxmem"]),
                "median": statistics.median(s["maxmem"]),
                "max": max(s["maxmem"]),
            },
        }

    for mem in MEMORIES:
        sk, vk = f"{FN_STDLIB}@{mem}MB", f"{FN_VENDORED}@{mem}MB"
        s, v = series(sk), series(vk)
        block = {
            "init": delta_block(v["init"], s["init"]),
            "first_invoke": delta_block(v["first"], s["first"]),
            "total_cold_path": delta_block(v["total"], s["total"]),
            "warm_median_delta_ms": statistics.median(v["warm"]) - statistics.median(s["warm"]),
        }
        tot = block["total_cold_path"]
        block["pass_total_median_le_300"] = tot["delta_median_ms"] <= RULE_TOTAL_MEDIAN_MAX_MS
        block["pass_total_p95_le_600"] = tot["delta_p95_ms"] <= RULE_TOTAL_P95_MAX_MS
        block["pass"] = bool(
            block["pass_total_median_le_300"] and block["pass_total_p95_le_600"]
        )
        results["deltas"][f"{mem}MB"] = block


def fmt(v) -> str:
    return "-" if v is None else f"{v:.1f}"


def print_summary(r: dict) -> None:
    print()
    print("=" * 112)
    print("3c-0 spike: vendored `cryptography` cold-start cost, final verifier form")
    print("python3.11 / x86_64 / us-east-1   key parsed at module scope, one warm-up verify at import")
    print("=" * 112)
    print("  wheels: " + ", ".join(f"{k}=={v}" for k, v in sorted(r["pin"]["versions"].items())))
    print(f"  pin file: {r['pin']['requirements_file']}  sha256 {r['pin']['requirements_sha256'][:16]}...")
    for name, meta in r["zips"].items():
        print(
            f"  zip {name:32s} {meta['compressed_bytes']:>10,} B compressed  "
            f"{meta['uncompressed_bytes']:>12,} B uncompressed  ({meta['file_count']} files)"
        )
    print()
    cols = (
        f"{'config':38s} {'n':>3s} {'init med':>8s} {'init p95':>8s} {'1st med':>8s} "
        f"{'1st p95':>8s} {'TOT med':>8s} {'TOT p95':>8s} {'warm med':>8s} {'warm p95':>8s} {'mem':>5s}"
    )
    print(cols)
    print("-" * len(cols))
    for mem in r["memories_mb"]:
        for base in ARMS:
            key = f"{base}@{mem}MB"
            s = r["summary"][key]
            print(
                f"{key:38s} {s['init_duration_ms']['n']:>3d} "
                f"{fmt(s['init_duration_ms']['median']):>8s} "
                f"{fmt(s['init_duration_ms']['p95_nearest_rank']):>8s} "
                f"{fmt(s['first_invoke_duration_ms']['median']):>8s} "
                f"{fmt(s['first_invoke_duration_ms']['p95_nearest_rank']):>8s} "
                f"{fmt(s['total_cold_path_ms']['median']):>8s} "
                f"{fmt(s['total_cold_path_ms']['p95_nearest_rank']):>8s} "
                f"{fmt(s['warm_duration_ms']['median']):>8s} "
                f"{fmt(s['warm_duration_ms']['p95_nearest_rank']):>8s} "
                f"{fmt(s['max_memory_used_mb']['max']):>5s}"
            )
    print()
    print("deltas, vendored minus stdlib at the same memory (ms)")
    hdr = (
        f"{'memory':>7s} {'metric':>16s} {'d median':>9s} {'d p95':>9s} "
        f"{'paired med':>11s} {'paired p95':>11s}"
    )
    print(hdr)
    print("-" * len(hdr))
    for mem in r["memories_mb"]:
        d = r["deltas"][f"{mem}MB"]
        for metric in ("init", "first_invoke", "total_cold_path"):
            b = d[metric]
            print(
                f"{str(mem) + ' MB':>7s} {metric:>16s} {b['delta_median_ms']:>9.1f} "
                f"{b['delta_p95_ms']:>9.1f} {b['paired_delta_median_ms']:>11.1f} "
                f"{b['paired_delta_p95_ms']:>11.1f}"
            )
    print()
    print(
        f"verdict on TOTAL cold path (rule: median <= {RULE_TOTAL_MEDIAN_MAX_MS} ms, "
        f"p95 <= {RULE_TOTAL_P95_MAX_MS} ms)"
    )
    for mem in r["memories_mb"]:
        d = r["deltas"][f"{mem}MB"]
        t = d["total_cold_path"]
        print(
            f"  {mem:>4d} MB  median {t['delta_median_ms']:>7.1f} "
            f"{'PASS' if d['pass_total_median_le_300'] else 'FAIL'}   "
            f"p95 {t['delta_p95_ms']:>7.1f} "
            f"{'PASS' if d['pass_total_p95_le_600'] else 'FAIL'}   "
            f"=> {'PASS' if d['pass'] else 'FAIL'}"
        )
        print(f"           warm-invoke median delta {d['warm_median_delta_ms']:>7.1f} ms")
    print()
    for key in r["samples"]:
        if r["discarded_non_cold"].get(key):
            print(f"  note: {key} discarded {r['discarded_non_cold'][key]} warm-when-expected-cold attempt(s)")
        if r["warm_unexpectedly_cold"].get(key):
            print(f"  note: {key} saw {r['warm_unexpectedly_cold'][key]} warm invoke(s) report Init Duration")
    print("=" * 112)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--regen-requirements",
        action="store_true",
        help="rebuild the hash-pinned requirements file before installing",
    )
    args = ap.parse_args()

    started = datetime.now(timezone.utc)
    account = assert_target_account()

    iam = boto3.client("iam", region_name=REGION)
    lam = boto3.client("lambda", region_name=REGION)
    logs = boto3.client("logs", region_name=REGION)

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    if subprocess.run(
        ["git", "check-ignore", "-q", str(RAW_DIR / "x.json")], cwd=str(REPO_ROOT), check=False
    ).returncode != 0:
        raise SystemExit(f"ABORT: {RAW_DIR} is not gitignored; refusing to write raw output there")
    log("raw output dir docs/design/3c-spike/ is gitignored")

    assert_nothing_preexists(iam, lam, logs)

    if args.regen_requirements:
        generate_requirements(REQUIREMENTS_FILE)

    key_material = generate_key_material()
    workdir = Path(tempfile.mkdtemp(prefix="spike-3c-edge-crypto-"))
    log(f"workdir {workdir}")

    results: dict = {
        "spike": "3c-0 edge crypto cold start (final verifier form)",
        "region": REGION,
        "account_id": account,
        "runtime": RUNTIME,
        "architecture": ARCH,
        "started_utc": started.isoformat(),
        "cold_samples_target": COLD_SAMPLES,
        "warm_invokes_per_cold": WARM_PER_COLD,
        "memories_mb": list(MEMORIES),
        "verifier_form": {
            "public_key_parsed_at": "module scope",
            "warmup_verify_at_import": True,
            "handler_body": "PUB.verify(SIGNATURE, MESSAGE, PAD, ALG); return {'ok': True}",
        },
        "decision_rule": {
            "metric": "total cold path = Init Duration + first-invoke Duration",
            "delta_median_ms_max": RULE_TOTAL_MEDIAN_MAX_MS,
            "delta_p95_ms_max": RULE_TOTAL_P95_MAX_MS,
            "p95_method": "nearest-rank",
            "total_method": "per-sample init+duration, then median/p95 of the totals",
        },
        "keygen": {
            "cryptography_version": key_material["keygen_cryptography_version"],
            "message_len_bytes": key_material["message_len"],
            "signature_alg": "RSASSA-PKCS1-v1_5 / SHA-256 / RSA-2048",
        },
        "samples": {},
        "discarded_non_cold": {},
        "warm_unexpectedly_cold": {},
        "attempts": {},
        "summary": {},
        "deltas": {},
    }

    failure: BaseException | None = None
    try:
        a_meta, b_meta, pin_info = build_packages(workdir, key_material)
        results["zips"] = {FN_STDLIB: a_meta, FN_VENDORED: b_meta}
        results["pin"] = pin_info

        role_arn = create_role(iam)
        log("sleeping 10 s for role propagation")
        time.sleep(10)
        for name, meta in ((FN_STDLIB, a_meta), (FN_VENDORED, b_meta)):
            create_function(lam, name, meta["zip_path"], role_arn)

        measure(lam, results)
        compute_stats(results)
        results["finished_utc"] = datetime.now(timezone.utc).isoformat()
        print_summary(results)
    except BaseException as exc:  # noqa: BLE001 - cleanup must still run
        failure = exc
        log(f"RUN FAILED: {exc!r}")
        traceback.print_exc()
    finally:
        log("cleanup (finally)")
        try:
            report = cleanup(iam, lam, logs)
        except Exception as exc:  # noqa: BLE001
            report = {
                "actions": [],
                "errors": [f"cleanup raised: {exc!r}"],
                "leftovers": {"unknown": ["cleanup did not complete"]},
                "clean": False,
            }
        results["cleanup"] = report
        for action in report.get("actions", []):
            log("cleanup: " + action)
        for err in report.get("errors", []):
            log("cleanup ERROR: " + err)
        log(f"cleanup clean={report.get('clean')} leftovers={report.get('leftovers')}")

        out = RAW_DIR / f"edge-crypto-coldstart-{started.strftime('%Y%m%dT%H%M%SZ')}.json"
        out.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
        log(f"raw JSON written: {out.relative_to(REPO_ROOT)}")
        shutil.rmtree(workdir, ignore_errors=True)
        log("removed workdir")

    if not results["cleanup"].get("clean"):
        print("\nCLEANUP FAILED. Leftovers that need manual deletion:", file=sys.stderr)
        for kind, names in results["cleanup"].get("leftovers", {}).items():
            if names:
                print(f"  {kind}: {names}", file=sys.stderr)
        for err in results["cleanup"].get("errors", []):
            print(f"  error: {err}", file=sys.stderr)
        return 2
    if failure is not None:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
