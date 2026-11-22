#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Securing_Infrastructure_for_AI_Applications.py

build, audit and tear down the secure AI development
environment from the "Securing Infrastructure for AI Applications" codelab.

What it builds (all in one Google Cloud project):
  * A custom-mode VPC + subnet with Private Google Access and VPC flow logs
  * A logged "deny all ingress" firewall rule (default-deny posture)
  * Optional: an IAP-only SSH rule and Cloud NAT for outbound package installs
  * A least-privilege service account for the Workbench instance
  * A Vertex AI Workbench instance with no public IP, Shielded VM
    (secure boot, vTPM, integrity monitoring), root access disabled,
    file downloads / nbconvert disabled, and a single instance owner
  * A Cloud Storage bucket with public access prevention, uniform
    bucket-level access, object versioning and soft delete; the service
    account gets object access on this bucket only
  * Cloud Storage Data Access audit logs (DATA_READ / DATA_WRITE)

Usage:
  python securing_infrastructure_for_ai_applications.py deploy   --project my-proj [--nat] [--allow-iap-ssh]
  python securing_infrastructure_for_ai_applications.py audit    --project my-proj [--json]
  python securing_infrastructure_for_ai_applications.py teardown --project my-proj [--yes]

Add --dry-run to any command to print the gcloud commands without running them.
Requires the gcloud CLI, authenticated as a user with Owner (or equivalent)
on the project.
"""

from __future__ import annotations



import argparse
import json
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------
# Lab defaults (names and ranges taken from the codelab)
# --------------------------------------------------------------------------
VPC = "genai-secure-vpc"
SUBNET_PREFIX = "genai-subnet"  # full name is genai-subnet-<region>
SUBNET_RANGE = "10.0.1.0/24"
SA_NAME = "vertex-workbench-sa"
INSTANCE = "secure-workbench"
FW_DENY = "genai-deny-all-ingress"
FW_IAP_SSH = "genai-allow-iap-ssh"
ROUTER = "genai-router"
NAT = "genai-nat"
IAP_RANGE = "35.235.240.0/20"  # Google's Identity-Aware Proxy TCP forwarding range
STATE_FILE = Path(".secure_ai_infra.json")
DEFAULT_REGION = "us-central1"

APIS = [
    "compute.googleapis.com",
    "notebooks.googleapis.com",
    "aiplatform.googleapis.com",
    "iam.googleapis.com",
    "storage.googleapis.com",
    "logging.googleapis.com",
]

# Project-level roles for the Workbench service account. Bucket access is
# granted on the bucket itself, not here, to keep the blast radius small.
SA_PROJECT_ROLES = [
    "roles/aiplatform.user",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
]
SA_BUCKET_ROLE = "roles/storage.objectUser"
DANGEROUS_ROLES = {"roles/owner", "roles/editor", "roles/iam.serviceAccountAdmin",
                   "roles/iam.serviceAccountTokenCreator", "roles/storage.admin"}

WORKBENCH_METADATA = {
    "notebook-disable-root": "true",
    "notebook-disable-downloads": "true",
    "notebook-disable-nbconvert": "true",
}

# --------------------------------------------------------------------------
# gcloud helpers
# --------------------------------------------------------------------------
class Runner:
    def __init__(self, project: str, dry_run: bool = False, verbose: bool = False):
        self.project = project
        self.dry_run = dry_run
        self.verbose = verbose

    def _cmd(self, args: list[str]) -> list[str]:
        return ["gcloud", *args, f"--project={self.project}", "--quiet"]

    def run(self, args: list[str], check: bool = True) -> str:
        """Run a gcloud command that changes something. Honours --dry-run."""
        cmd = self._cmd(args)
        print("  $ " + shlex.join(cmd))
        if self.dry_run:
            return ""
        res = _exec(cmd)
        if res.returncode != 0 and check:
            raise GcloudError(cmd, res.stderr.strip())
        if self.verbose and res.stdout.strip():
            print(res.stdout.strip())
        return res.stdout

    def read(self, args: list[str]) -> Any:
        """Run a read-only gcloud command and return parsed JSON, or None if it fails."""
        if self.dry_run:
            return None
        res = _exec(self._cmd([*args, "--format=json"]))
        if res.returncode != 0:
            return None
        try:
            return json.loads(res.stdout or "null")
        except json.JSONDecodeError:
            return None

    def exists(self, args: list[str]) -> bool:
        return self.read(args) is not None


GCLOUD = shutil.which("gcloud") or "gcloud"  # resolves gcloud.cmd on Windows


def _exec(cmd: list[str]) -> subprocess.CompletedProcess:
    if cmd and cmd[0] == "gcloud":
        cmd = [GCLOUD, *cmd[1:]]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        sys.exit("gcloud CLI not found. Install it: https://cloud.google.com/sdk/docs/install")


class GcloudError(RuntimeError):
    def __init__(self, cmd: list[str], stderr: str):
        super().__init__(f"Command failed: {shlex.join(cmd)}\n{stderr}")


def gcloud_config(key: str) -> str:
    res = _exec(["gcloud", "config", "get-value", key])
    return res.stdout.strip() if res.returncode == 0 else ""


def step(title: str) -> None:
    print(f"\n== {title}")


def skip(what: str) -> None:
    print(f"  - {what} already exists, skipping")

# --------------------------------------------------------------------------
# deploy
# --------------------------------------------------------------------------
def deploy(r: Runner, c: Config) -> None:
    step("1/8 Enable APIs")
    r.run(["services", "enable", *APIS])

    step("2/8 Private VPC and subnet")
    if r.exists(["compute", "networks", "describe", VPC]):
        skip(f"VPC {VPC}")
    else:
        r.run(["compute", "networks", "create", VPC,
               "--subnet-mode=custom", "--bgp-routing-mode=regional"])
    if r.exists(["compute", "networks", "subnets", "describe", c.subnet, f"--region={c.region}"]):
        skip(f"subnet {c.subnet}")
    else:
        r.run(["compute", "networks", "subnets", "create", c.subnet,
               f"--network={VPC}", f"--region={c.region}", f"--range={SUBNET_RANGE}",
               "--enable-private-ip-google-access",
               "--enable-flow-logs", "--logging-metadata=include-all"])

    step("3/8 Default-deny firewall")
    if r.exists(["compute", "firewall-rules", "describe", FW_DENY]):
        skip(f"firewall rule {FW_DENY}")
    else:
        # Lowest user priority, so any deliberate allow rule above still wins,
        # but every blocked attempt is logged for auditing.
        r.run(["compute", "firewall-rules", "create", FW_DENY,
               f"--network={VPC}", "--direction=INGRESS", "--action=DENY",
               "--rules=all", "--source-ranges=0.0.0.0/0", "--priority=65534",
               "--enable-logging", "--logging-metadata=include-all"])
    if c.allow_iap_ssh:
        if r.exists(["compute", "firewall-rules", "describe", FW_IAP_SSH]):
            skip(f"firewall rule {FW_IAP_SSH}")
        else:
            r.run(["compute", "firewall-rules", "create", FW_IAP_SSH,
                   f"--network={VPC}", "--direction=INGRESS", "--action=ALLOW",
                   "--rules=tcp:22", f"--source-ranges={IAP_RANGE}", "--priority=1000",
                   "--enable-logging"])

    step("4/8 Outbound access (Cloud NAT)")
    if not c.nat:
        print("  - skipped (pass --nat to allow pip/apt installs from the internet)")
    else:
        if r.exists(["compute", "routers", "describe", ROUTER, f"--region={c.region}"]):
            skip(f"router {ROUTER}")
        else:
            r.run(["compute", "routers", "create", ROUTER,
                   f"--network={VPC}", f"--region={c.region}"])
        if r.exists(["compute", "routers", "nats", "describe", NAT,
                     f"--router={ROUTER}", f"--region={c.region}"]):
            skip(f"NAT {NAT}")
        else:
            r.run(["compute", "routers", "nats", "create", NAT,
                   f"--router={ROUTER}", f"--region={c.region}",
                   "--auto-allocate-nat-external-ips",
                   f"--nat-custom-subnet-ip-ranges={c.subnet}",
                   "--enable-logging"])

    step("5/8 Least-privilege service account")
    if r.exists(["iam", "service-accounts", "describe", c.sa_email]):
        skip(f"service account {c.sa_email}")
    else:
        r.run(["iam", "service-accounts", "create", SA_NAME,
               "--display-name=Vertex AI Workbench (least privilege)"])
    for role in SA_PROJECT_ROLES:
        retry(lambda role=role: r.run(
            ["projects", "add-iam-policy-binding", c.project,
             f"--member=serviceAccount:{c.sa_email}", f"--role={role}",
             "--condition=None"]),
            what=f"grant {role}", dry_run=r.dry_run)

    step("6/8 Secure Cloud Storage bucket")
    gs = f"gs://{c.bucket}"
    if r.exists(["storage", "buckets", "describe", gs]):
        skip(f"bucket {gs}")
    else:
        r.run(["storage", "buckets", "create", gs,
               f"--location={c.region}",
               "--uniform-bucket-level-access",
               "--public-access-prevention",
               "--soft-delete-duration=7d"])
    r.run(["storage", "buckets", "update", gs, "--versioning"])
    retry(lambda: r.run(
        ["storage", "buckets", "add-iam-policy-binding", gs,
         f"--member=serviceAccount:{c.sa_email}", f"--role={SA_BUCKET_ROLE}"]),
        what="grant bucket access", dry_run=r.dry_run)

    step("7/8 Data Access audit logs for Cloud Storage")
    enable_storage_audit_logs(r, c.project)

    step("8/8 Hardened Vertex AI Workbench instance (takes ~5-10 minutes)")
    if r.exists(["workbench", "instances", "describe", INSTANCE, f"--location={c.zone}"]):
        skip(f"Workbench instance {INSTANCE}")
    else:
        metadata = ",".join(f"{k}={v}" for k, v in WORKBENCH_METADATA.items())
        r.run(["workbench", "instances", "create", INSTANCE,
               f"--location={c.zone}",
               f"--machine-type={c.machine_type}",
               f"--network={c.network_path}",
               f"--subnet={c.subnet_path}",
               f"--subnet-region={c.region}",
               "--disable-public-ip",
               f"--service-account-email={c.sa_email}",
               f"--instance-owners={c.owner}",
               "--shielded-secure-boot=true",
               "--shielded-vtpm=true",
               "--shielded-integrity-monitoring=true",
               f"--metadata={metadata}",
               f"--labels=env=dev,managed-by=secure-ai-infra"])

    print(f"""
Done. Open JupyterLab through the secure proxy:
  https://console.cloud.google.com/vertex-ai/workbench/instances?project={c.project}
Bucket: gs://{c.bucket}
Check the setup any time with:  python3 {Path(sys.argv[0]).name} audit --project {c.project}""")


def retry(fn, what: str, dry_run: bool, attempts: int = 6, wait: int = 10) -> None:
    """New service accounts can take a minute to be visible to IAM; retry briefly."""
    for i in range(attempts):
        try:
            fn()
            return
        except GcloudError as e:
            if dry_run or i == attempts - 1 or "does not exist" not in str(e):
                raise
            print(f"  ... {what}: service account not visible yet, retrying in {wait}s")
            time.sleep(wait)


def enable_storage_audit_logs(r: Runner, project: str) -> None:
    """Merge DATA_READ/DATA_WRITE audit logging for storage into the project policy."""
    if r.dry_run:
        print(f"  $ gcloud projects get-iam-policy {project}  # add auditConfigs for "
              "storage.googleapis.com, then set-iam-policy")
        return
    policy = r.read(["projects", "get-iam-policy", project])
    if not isinstance(policy, dict):
        raise RuntimeError("Could not read the project IAM policy.")
    wanted = {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}
    configs = policy.setdefault("auditConfigs", [])
    entry = next((a for a in configs if a.get("service") == "storage.googleapis.com"), None)
    if entry is None:
        entry = {"service": "storage.googleapis.com", "auditLogConfigs": []}
        configs.append(entry)
    have = {lc.get("logType") for lc in entry.setdefault("auditLogConfigs", [])}
    missing = wanted - have
    if not missing:
        skip("storage Data Access audit logging")
        return
    entry["auditLogConfigs"].extend({"logType": t} for t in sorted(missing))
    # The policy keeps its etag, so a concurrent change makes this fail safely
    # instead of overwriting someone else's edit.
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(policy, f)
        path = f.name
    try:
        r.run(["projects", "set-iam-policy", project, path])
    finally:
        Path(path).unlink(missing_ok=True)

# --------------------------------------------------------------------------
# State (remembers the random bucket name between commands)
# --------------------------------------------------------------------------
def _load_all() -> dict:
    try:
        data = json.loads(STATE_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    if "project" in data and isinstance(data.get("project"), str):  # old single-project format
        return {data["project"]: data}
    return data


def load_state(project: str) -> dict:
    return _load_all().get(project, {})


def save_state(project: str, state: dict) -> None:
    data = _load_all()
    data[project] = {**state, "project": project}
    STATE_FILE.write_text(json.dumps(data, indent=2) + "\n")


def forget_state(project: str) -> None:
    data = _load_all()
    data.pop(project, None)
    if data:
        STATE_FILE.write_text(json.dumps(data, indent=2) + "\n")
    else:
        STATE_FILE.unlink(missing_ok=True)


@dataclass
class Config:
    project: str
    region: str
    zone: str
    bucket: str
    owner: str
    machine_type: str
    nat: bool
    allow_iap_ssh: bool

    @property
    def sa_email(self) -> str:
        return f"{SA_NAME}@{self.project}.iam.gserviceaccount.com"

    @property
    def network_path(self) -> str:
        return f"projects/{self.project}/global/networks/{VPC}"

    @property
    def subnet(self) -> str:
        return f"{SUBNET_PREFIX}-{self.region}"

    @property
    def subnet_path(self) -> str:
        return f"projects/{self.project}/regions/{self.region}/subnetworks/{self.subnet}"

# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------
@dataclass
class Report:
    results: list[dict] = field(default_factory=list)

    def add(self, area: str, check: str, ok: bool | None, detail: str = "") -> None:
        status = "PASS" if ok else ("WARN" if ok is None else "FAIL")
        self.results.append({"area": area, "check": check, "status": status, "detail": detail})

    @property
    def failed(self) -> int:
        return sum(1 for x in self.results if x["status"] == "FAIL")

    def print(self) -> None:
        icons = {"PASS": "✔", "FAIL": "✘", "WARN": "!"}
        area = None
        for x in self.results:
            if x["area"] != area:
                area = x["area"]
                print(f"\n{area}")
            line = f"  {icons[x['status']]} {x['status']}  {x['check']}"
            print(line + (f"  ({x['detail']})" if x["detail"] else ""))
        counts = {s: sum(1 for x in self.results if x["status"] == s) for s in icons}
        print(f"\n{counts['PASS']} passed, {counts['FAIL']} failed, {counts['WARN']} warnings")


def audit(r: Runner, c: Config) -> Report:
    rep = Report()

    # ---- Preflight: tell "can't see it" apart from "it isn't there"
    if not isinstance(r.read(["projects", "describe", c.project]), dict):
        raise SystemExit(f"Cannot read project {c.project}. Check `gcloud auth list`, the project "
                         "ID, and that your account has at least Viewer on it.")

    # ---- Network
    A = "Network"
    net = r.read(["compute", "networks", "describe", VPC])
    rep.add(A, f"VPC {VPC} exists", bool(net))
    if net:
        rep.add(A, "VPC uses custom subnet mode", net.get("autoCreateSubnetworks") is False)
    sub = r.read(["compute", "networks", "subnets", "describe", c.subnet, f"--region={c.region}"])
    rep.add(A, f"Subnet {c.subnet} exists", bool(sub))
    if sub:
        rep.add(A, "Private Google Access enabled", bool(sub.get("privateIpGoogleAccess")))
        rep.add(A, "VPC flow logs enabled", bool((sub.get("logConfig") or {}).get("enable")))
    default_net = r.read(["compute", "networks", "describe", "default"])
    rep.add(A, "No 'default' network (it ships with open SSH/RDP rules)",
            None if default_net else True,
            "consider deleting it if nothing uses it" if default_net else "")

    # ---- Firewall
    A = "Firewall"
    rules = r.read(["compute", "firewall-rules", "list",
                    f"--filter=network~/{VPC}$"]) or []
    deny = next((x for x in rules if x.get("name") == FW_DENY), None)
    rep.add(A, "Deny-all ingress rule exists", bool(deny))
    if deny:
        denies_all = (deny.get("direction") == "INGRESS" and not deny.get("disabled")
                      and any(d.get("IPProtocol") == "all" for d in deny.get("denied") or [])
                      and "0.0.0.0/0" in (deny.get("sourceRanges") or []))
        rep.add(A, "Deny-all rule still denies all ingress from 0.0.0.0/0", denies_all)
        rep.add(A, "Deny-all rule logs blocked traffic",
                bool((deny.get("logConfig") or {}).get("enable")))
    open_rules = [x["name"] for x in rules
                  if x.get("direction") == "INGRESS" and x.get("allowed")
                  and {"0.0.0.0/0", "::/0"} & set(x.get("sourceRanges") or [])
                  and not x.get("disabled")]
    rep.add(A, "No ingress allowed from anywhere (0.0.0.0/0, ::/0)", not open_rules, ", ".join(open_rules))

    # ---- Identity
    A = "Identity"
    sa = r.read(["iam", "service-accounts", "describe", c.sa_email])
    rep.add(A, f"Service account {SA_NAME} exists", bool(sa))
    policy = r.read(["projects", "get-iam-policy", c.project]) or {}
    member = f"serviceAccount:{c.sa_email}"
    sa_roles = {b["role"] for b in policy.get("bindings", []) if member in b.get("members", [])}
    bad = sorted(sa_roles & DANGEROUS_ROLES)
    rep.add(A, "Service account has no broad admin roles", not bad, ", ".join(bad))
    extra = sorted(sa_roles - set(SA_PROJECT_ROLES))
    rep.add(A, "Service account holds only expected project roles",
            None if extra else True, ("extra: " + ", ".join(extra)) if extra else "")
    keys = r.read(["iam", "service-accounts", "keys", "list",
                   f"--iam-account={c.sa_email}", "--managed-by=user"]) or []
    rep.add(A, "No user-managed keys for the service account", not keys,
            f"{len(keys)} key(s)" if keys else "")

    # ---- Workbench
    A = "Workbench"
    inst = r.read(["workbench", "instances", "describe", INSTANCE, f"--location={c.zone}"])
    rep.add(A, f"Instance {INSTANCE} exists", bool(inst))
    if inst:
        gce = inst.get("gceSetup", {})
        rep.add(A, "No public IP", bool(gce.get("disablePublicIp")))
        nics = gce.get("networkInterfaces") or [{}]
        rep.add(A, "Attached to the secure VPC",
                str(nics[0].get("network", "")).endswith(f"/networks/{VPC}"))
        emails = [s.get("email") for s in gce.get("serviceAccounts", [])]
        rep.add(A, "Runs as the least-privilege service account", c.sa_email in emails,
                ", ".join(e for e in emails if e))
        sh = gce.get("shieldedInstanceConfig", {})
        rep.add(A, "Shielded VM: secure boot", bool(sh.get("enableSecureBoot")))
        rep.add(A, "Shielded VM: vTPM", bool(sh.get("enableVtpm")))
        rep.add(A, "Shielded VM: integrity monitoring", bool(sh.get("enableIntegrityMonitoring")))
        md = gce.get("metadata", {})
        for key in WORKBENCH_METADATA:
            rep.add(A, f"Metadata {key}=true", str(md.get(key, "")).lower() == "true")
        owners = inst.get("instanceOwners") or []
        rep.add(A, "Single instance owner", len(owners) == 1, ", ".join(owners))

    # ---- Storage
    A = "Storage"
    gs = f"gs://{c.bucket}" if c.bucket else ""
    b = r.read(["storage", "buckets", "describe", gs, "--raw"]) if gs else None
    rep.add(A, f"Bucket {gs or '(unknown)'} exists", bool(b),
            "" if gs else "pass --bucket or run deploy from this folder")
    if b:
        iam_cfg = b.get("iamConfiguration", {})
        rep.add(A, "Public access prevention enforced",
                iam_cfg.get("publicAccessPrevention") == "enforced")
        rep.add(A, "Uniform bucket-level access",
                bool((iam_cfg.get("uniformBucketLevelAccess") or {}).get("enabled")))
        rep.add(A, "Object versioning on", bool((b.get("versioning") or {}).get("enabled")))
        sd = int((b.get("softDeletePolicy") or {}).get("retentionDurationSeconds", 0) or 0)
        rep.add(A, "Soft delete on", sd > 0, f"{sd // 86400} day(s)" if sd else "")
        biam = r.read(["storage", "buckets", "get-iam-policy", gs]) or {}
        public = [b_["role"] for b_ in biam.get("bindings", [])
                  if {"allUsers", "allAuthenticatedUsers"} & set(b_.get("members", []))]
        rep.add(A, "No public IAM bindings", not public, ", ".join(public))

    # ---- Logging
    A = "Logging"
    logged = set()
    for ac in policy.get("auditConfigs", []):
        if ac.get("service") in ("storage.googleapis.com", "allServices"):
            logged |= {lc.get("logType") for lc in ac.get("auditLogConfigs", [])
                       if not lc.get("exemptedMembers")}
    rep.add(A, "Storage DATA_READ audit logs", "DATA_READ" in logged)
    rep.add(A, "Storage DATA_WRITE audit logs", "DATA_WRITE" in logged)

    return rep

# --------------------------------------------------------------------------
# teardown
# --------------------------------------------------------------------------
def teardown(r: Runner, c: Config, assume_yes: bool) -> None:
    if not assume_yes and not r.dry_run:
        print(f"This deletes the Workbench instance, the bucket gs://{c.bucket or '?'} and ALL "
              f"its data, the service account and the network in project {c.project}.")
        if input("Type the project ID to confirm: ").strip() != c.project:
            sys.exit("Aborted.")

    failures: list[str] = []

    def quiet(args: list[str], describe: list[str]) -> None:
        if not (r.dry_run or r.exists(describe)):
            print("  - not found, nothing to delete")
            return
        try:
            r.run(args)
        except GcloudError as e:
            failures.append(shlex.join(args[:4]))
            print(f"  ✘ FAILED: {str(e).splitlines()[-1] if str(e) else 'unknown error'}")

    step("Workbench instance")
    quiet(["workbench", "instances", "delete", INSTANCE, f"--location={c.zone}"],
          ["workbench", "instances", "describe", INSTANCE, f"--location={c.zone}"])

    step("Bucket")
    if c.bucket:
        gs = f"gs://{c.bucket}"
        quiet(["storage", "rm", "--recursive", "--all-versions", gs],
              ["storage", "buckets", "describe", gs])
        print("  note: soft-deleted objects are kept for up to 7 days, then purged")
    else:
        print("  - no bucket name known, skipping (pass --bucket)")

    step("Service account")
    for role in SA_PROJECT_ROLES:
        r.run(["projects", "remove-iam-policy-binding", c.project,
               f"--member=serviceAccount:{c.sa_email}", f"--role={role}",
               "--condition=None"], check=False)
    quiet(["iam", "service-accounts", "delete", c.sa_email],
          ["iam", "service-accounts", "describe", c.sa_email])

    step("Network")
    quiet(["compute", "routers", "delete", ROUTER, f"--region={c.region}"],
          ["compute", "routers", "describe", ROUTER, f"--region={c.region}"])
    for fw in (FW_IAP_SSH, FW_DENY):
        quiet(["compute", "firewall-rules", "delete", fw],
              ["compute", "firewall-rules", "describe", fw])
    quiet(["compute", "networks", "subnets", "delete", c.subnet, f"--region={c.region}"],
          ["compute", "networks", "subnets", "describe", c.subnet, f"--region={c.region}"])
    quiet(["compute", "networks", "delete", VPC], ["compute", "networks", "describe", VPC])

    if failures:
        print(f"\nTeardown INCOMPLETE: {len(failures)} step(s) failed:")
        for f_ in failures:
            print(f"  - gcloud {f_}")
        print(f"State kept in {STATE_FILE} so you can fix the cause and rerun teardown.")
        raise SystemExit(2)
    print("\nTeardown finished. Storage Data Access audit logging was left on; "
          "turn it off under IAM & Admin > Audit Logs if you no longer want it.")
    if not r.dry_run:
        forget_state(c.project)

# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0].strip(),
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--project", help="project ID (default: gcloud config)")
    common.add_argument("--region", default=None,
                        help=f"region (default: remembered from deploy, else {DEFAULT_REGION})")
    common.add_argument("--zone", default=None,
                        help="Workbench zone (default: remembered from deploy, else <region>-a)")
    common.add_argument("--bucket", help="bucket name (default: random on deploy, then remembered)")
    common.add_argument("--dry-run", action="store_true", help="print commands, change nothing")
    common.add_argument("-v", "--verbose", action="store_true")

    d = sub.add_parser("deploy", parents=[common], help="build the secure environment")
    d.add_argument("--owner", help="the one user allowed to open the notebook "
                                   "(default: your gcloud account)")
    d.add_argument("--machine-type", default="e2-standard-4")
    d.add_argument("--nat", action="store_true",
                   help="add Cloud NAT so the instance can install packages from the internet")
    d.add_argument("--allow-iap-ssh", action="store_true",
                   help="allow SSH only through Identity-Aware Proxy")

    a = sub.add_parser("audit", parents=[common], help="check every control and report")
    a.add_argument("--json", action="store_true", help="machine-readable output")

    t = sub.add_parser("teardown", parents=[common], help="delete everything deploy created")
    t.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    args = p.parse_args(argv)

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    project = args.project or gcloud_config("project")
    if not project:
        p.error("no project: pass --project or run `gcloud config set project <id>`")

    state = load_state(project)
    bucket = args.bucket or state.get("bucket")
    region = args.region or state.get("region") or DEFAULT_REGION
    if args.zone:
        zone = args.zone
    elif not args.region and state.get("zone"):
        zone = state["zone"]
    else:
        zone = f"{region}-a"
    if args.command == "deploy" and not bucket:
        bucket = f"genai-data-{secrets.token_hex(6)}"  # random, hard-to-guess name

    owner = getattr(args, "owner", None)
    if args.command == "deploy" and not owner:
        owner = gcloud_config("account")
    if args.command == "deploy" and not owner and not args.dry_run:
        p.error("no owner: pass --owner you@example.com")

    c = Config(project=project, region=region, zone=zone,
               bucket=bucket or "", owner=owner or "you@example.com",
               machine_type=getattr(args, "machine_type", "e2-standard-4"),
               nat=getattr(args, "nat", False), allow_iap_ssh=getattr(args, "allow_iap_ssh", False))
    r = Runner(project, dry_run=args.dry_run, verbose=args.verbose)

    try:
        if args.command == "deploy":
            if not args.dry_run:
                save_state(project, {"bucket": c.bucket, "region": c.region, "zone": c.zone})
            deploy(r, c)
        elif args.command == "audit":
            if args.dry_run:
                sys.exit("audit only reads; run it without --dry-run")
            rep = audit(r, c)
            if args.json:
                print(json.dumps(rep.results, indent=2))
            else:
                print(f"Security audit for project {project}")
                rep.print()
            return 1 if rep.failed else 0
        elif args.command == "teardown":
            teardown(r, c, args.yes)
    except GcloudError as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())