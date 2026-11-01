"""
Cleanup Plan Generator for disk_investigator.
Generates structured, auditable cleanup plans with pre-flight metadata.
Strict semantics: distinguishes immediate disk reclaim from Recycle Bin deferral.
Does NOT perform any deletion.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..capabilities import get_default_cache_dir
from ..classifiers.risk_classifier import Disposition, RiskClassifier, RiskLevel
from ..models import RecommendedAction, StorageArtifact, UserDataProbability
from ..path_policy import canonicalize_path, determine_node_kind
from .action_types import ActionType

PLAN_ID_REGEX = re.compile(r"^plan_[0-9a-f]{8,32}$")


def get_tool_cache_path(tool: str) -> Optional[str]:
    """Queries tool runtime for its actual active cache directory to bind actions safely."""
    if tool == "npm":
        npm_bin = shutil.which("npm.cmd") or shutil.which("npm")
        if npm_bin:
            try:
                proc = subprocess.run([npm_bin, "config", "get", "cache"], capture_output=True, text=True, timeout=3, shell=False)
                if proc.returncode == 0 and proc.stdout.strip():
                    return canonicalize_path(proc.stdout.strip()).lower()
            except Exception:
                pass
    elif tool == "pip":
        try:
            proc = subprocess.run([sys.executable, "-m", "pip", "cache", "dir"], capture_output=True, text=True, timeout=3, shell=False)
            if proc.returncode == 0 and proc.stdout.strip():
                return canonicalize_path(proc.stdout.strip()).lower()
        except Exception:
            pass
    return None


def get_plan_signing_key(cache_dir: Optional[Any] = None) -> bytes:
    """
    Retrieves or generates a machine/session-scoped secret key for signing cleanup plans.
    Guarantees true plan tamper protection: a caller or agent cannot forge or alter
    plan items without possessing the secret key.
    """
    env_key = os.environ.get("DISK_INVESTIGATOR_SECRET_KEY")
    if env_key:
        return env_key.encode("utf-8")

    if cache_dir is not None:
        base_dir = Path(cache_dir)
    else:
        base_dir = get_default_cache_dir()
    base_dir.mkdir(parents=True, exist_ok=True)
    key_file = base_dir / ".plan_secret.key"

    if key_file.exists():
        try:
            with open(key_file, "rb") as f:
                key = f.read().strip()
                if len(key) >= 32:
                    return key
        except Exception:
            pass

    import secrets
    new_key = secrets.token_hex(32).encode("utf-8")
    try:
        with open(key_file, "wb") as f:
            f.write(new_key)
    except Exception:
        pass
    return new_key


def compute_plan_hash(
    plan_id: str,
    target_root: str,
    created_at: str,
    items: List[PlanItem],
    secret_key: Optional[bytes] = None,
    total_items: Optional[int] = None,
    total_candidate_bytes: Optional[int] = None,
    total_immediate_reclaimable_bytes: Optional[int] = None,
    total_recycle_bin_bytes: Optional[int] = None,
    total_potential_reclaim_bytes: Optional[int] = None,
    schema_version: int = 2,
) -> str:
    """
    Computes an HMAC-SHA256 signature for a CleanupPlan covering all fields:
    plan metadata, total figures, full item payloads, and schema_version.
    Provides true plan tamper protection against adversarial JSON editing.
    """
    if secret_key is None:
        secret_key = get_plan_signing_key()

    item_payloads = []
    for item in sorted(items, key=lambda x: x.item_id):
        item_payloads.append({
            "item_id": item.item_id,
            "path": canonicalize_path(item.path),
            "expected_kind": item.expected_kind,
            "candidate_bytes": item.candidate_bytes,
            "expected_mtime": item.expected_mtime,
            "risk": item.risk.value if isinstance(item.risk, RiskLevel) else str(item.risk),
            "disposition": (
                item.disposition.value
                if isinstance(item.disposition, Disposition)
                else str(item.disposition)
            ),
            "action_type": (
                item.action_type.value
                if isinstance(item.action_type, ActionType)
                else str(item.action_type)
            ),
            "description": item.description,
            "immediate_reclaimable_bytes": item.immediate_reclaimable_bytes,
            "recycle_bin_bytes": item.recycle_bin_bytes,
            "potential_reclaim_bytes": item.potential_reclaim_bytes,
            "warning": item.warning,
            "artifact_id": item.artifact_id,
            "source_detector": item.source_detector,
            "domain": item.domain,
            "category": item.category,
            "action_binding": item.action_binding,
        })

    payload = {
        "schema_version": schema_version,
        "plan_id": plan_id,
        "target_root": canonicalize_path(target_root),
        "created_at": created_at,
        "total_items": total_items if total_items is not None else len(items),
        "total_candidate_bytes": (
            total_candidate_bytes
            if total_candidate_bytes is not None
            else sum(i.candidate_bytes for i in items if i.candidate_bytes)
        ),
        "total_immediate_reclaimable_bytes": (
            total_immediate_reclaimable_bytes
            if total_immediate_reclaimable_bytes is not None
            else sum(i.immediate_reclaimable_bytes for i in items)
        ),
        "total_recycle_bin_bytes": (
            total_recycle_bin_bytes
            if total_recycle_bin_bytes is not None
            else sum(i.recycle_bin_bytes for i in items)
        ),
        "total_potential_reclaim_bytes": (
            total_potential_reclaim_bytes
            if total_potential_reclaim_bytes is not None
            else sum(i.potential_reclaim_bytes for i in items)
        ),
        "items": item_payloads,
    }
    encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
    import hmac
    return hmac.new(secret_key, encoded, hashlib.sha256).hexdigest()


def validate_plan_schema(plan: CleanupPlan) -> None:
    """
    Validates structural integrity and constraints of a CleanupPlan before execution.
    Fails closed on duplicate item_ids, count mismatches, or non-positive IDs.
    """
    if plan.total_items != len(plan.items):
        raise ValueError(
            f"SECURITY REFUSAL: Plan schema error: total_items ({plan.total_items}) does not match len(items) ({len(plan.items)})"
        )
    item_ids = [item.item_id for item in plan.items]
    if len(item_ids) != len(set(item_ids)):
        raise ValueError(
            f"SECURITY REFUSAL: Duplicate item_id detected in plan {plan.plan_id}. Plan integrity violated."
        )
    if any(iid <= 0 for iid in item_ids):
        raise ValueError(
            f"SECURITY REFUSAL: Invalid non-positive item_id in plan {plan.plan_id}."
        )


@dataclass
class PlanItem:
    item_id: int
    path: str
    expected_kind: str
    candidate_bytes: int
    expected_mtime: Optional[float]
    risk: RiskLevel
    disposition: Disposition
    action_type: ActionType
    description: str
    immediate_reclaimable_bytes: int
    recycle_bin_bytes: int
    potential_reclaim_bytes: int
    warning: Optional[str] = None
    artifact_id: Optional[str] = None
    source_detector: Optional[str] = None
    domain: Optional[str] = None
    category: Optional[str] = None
    action_binding: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "item_id": self.item_id,
            "path": self.path,
            "expected_kind": self.expected_kind,
            "candidate_bytes": self.candidate_bytes,
            "expected_mtime": self.expected_mtime,
            "risk": self.risk.value if isinstance(self.risk, RiskLevel) else self.risk,
            "disposition": (
                self.disposition.value if isinstance(self.disposition, Disposition) else self.disposition
            ),
            "action_type": (
                self.action_type.value if isinstance(self.action_type, ActionType) else self.action_type
            ),
            "description": self.description,
            "immediate_reclaimable_bytes": self.immediate_reclaimable_bytes,
            "recycle_bin_bytes": self.recycle_bin_bytes,
            "potential_reclaim_bytes": self.potential_reclaim_bytes,
            "warning": self.warning,
            "artifact_id": self.artifact_id,
            "source_detector": self.source_detector,
            "domain": self.domain,
            "category": self.category,
            "action_binding": self.action_binding,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PlanItem:
        candidate_b = data.get("candidate_bytes", data.get("expected_size", 0))
        imm = data.get("immediate_reclaimable_bytes", 0)
        rec = data.get("recycle_bin_bytes", 0)
        pot = data.get("potential_reclaim_bytes", data.get("estimated_reclaim_bytes", candidate_b))

        return cls(
            item_id=data["item_id"],
            path=data["path"],
            expected_kind=data["expected_kind"],
            candidate_bytes=candidate_b,
            expected_mtime=data.get("expected_mtime"),
            risk=RiskLevel(data["risk"]),
            disposition=Disposition(data["disposition"]),
            action_type=ActionType(data["action_type"]),
            description=data["description"],
            immediate_reclaimable_bytes=imm,
            recycle_bin_bytes=rec,
            potential_reclaim_bytes=pot,
            warning=data.get("warning"),
            artifact_id=data.get("artifact_id"),
            source_detector=data.get("source_detector"),
            domain=data.get("domain"),
            category=data.get("category"),
            action_binding=data.get("action_binding"),
        )


@dataclass
class CleanupPlan:
    plan_id: str
    target_root: str
    created_at: str
    total_items: int
    total_candidate_bytes: int
    total_immediate_reclaimable_bytes: int
    total_recycle_bin_bytes: int
    total_potential_reclaim_bytes: int
    plan_hash: str = ""
    items: List[PlanItem] = field(default_factory=list)
    schema_version: int = 2

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "target_root": self.target_root,
            "created_at": self.created_at,
            "total_items": self.total_items,
            "total_candidate_bytes": self.total_candidate_bytes,
            "total_immediate_reclaimable_bytes": self.total_immediate_reclaimable_bytes,
            "total_recycle_bin_bytes": self.total_recycle_bin_bytes,
            "total_potential_reclaim_bytes": self.total_potential_reclaim_bytes,
            "plan_hash": self.plan_hash,
            "items": [i.to_dict() for i in self.items],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CleanupPlan:
        return cls(
            plan_id=data["plan_id"],
            target_root=data["target_root"],
            created_at=data["created_at"],
            total_items=data["total_items"],
            total_candidate_bytes=data.get("total_candidate_bytes", 0),
            total_immediate_reclaimable_bytes=data.get("total_immediate_reclaimable_bytes", 0),
            total_recycle_bin_bytes=data.get("total_recycle_bin_bytes", 0),
            total_potential_reclaim_bytes=data.get(
                "total_potential_reclaim_bytes", data.get("total_estimated_reclaim_bytes", 0)
            ),
            plan_hash=data.get("plan_hash", ""),
            items=[PlanItem.from_dict(i) for i in data.get("items", [])],
            schema_version=data.get("schema_version", 1),
        )


class PlanGenerator:
    """Generates structured cleanup proposals for human approval."""

    def __init__(self, cache_dir: Optional[str] = None, secret_key: Optional[bytes] = None):
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = get_default_cache_dir() / "plans"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.secret_key = secret_key or get_plan_signing_key(self.cache_dir)
        self.classifier = RiskClassifier()

    def generate_plan(
        self,
        target_root: str,
        candidates: List[Any],
    ) -> CleanupPlan:
        plan_id = f"plan_{uuid.uuid4().hex[:8]}"
        items: List[PlanItem] = []
        current_id = 1

        for c in candidates:
            if isinstance(c, StorageArtifact):
                p = canonicalize_path(c.canonical_path or c.path)
                a_type = c.artifact_type
                sz = c.logical_bytes
                owner_app = c.owner_app
                warning = None
                art_id = c.artifact_id
                source_det = c.source_detector
                dom = c.domain.value if hasattr(c.domain, "value") else str(c.domain)
                cat = c.category.value if hasattr(c.category, "value") else str(c.category)
                cap_id = c.capability_id

                # Hard blocked or review-only items are strictly excluded from cleanup plans
                if c.recommended_action in (RecommendedAction.BLOCK, RecommendedAction.REVIEW_ONLY):
                    continue
                if c.user_data_probability != UserDataProbability.LOW:
                    continue
            else:
                p = canonicalize_path(c.get("path", ""))
                a_type = c.get("artifact_type")
                sz = c.get("logical_bytes", 0)
                owner_app = c.get("owner_app")
                warning = c.get("warning")
                art_id = c.get("artifact_id")
                source_det = c.get("source_detector")
                dom = c.get("domain")
                cat = c.get("category")
                cap_id = c.get("capability_id")

            # Classify item
            classification = self.classifier.classify(
                path=p,
                artifact_type=a_type,
                owner_app=owner_app,
                stale_candidate=getattr(c, "stale_candidate", False) if not isinstance(c, StorageArtifact) else False,
            )

            # Hard blocked items are strictly excluded from cleanup plans
            if classification.disposition == Disposition.BLOCKED:
                continue

            mtime = None
            try:
                mtime = os.path.getmtime(p)
            except (OSError, PermissionError):
                # Fail closed: items whose metadata cannot be fingerprinted at planning time
                # are strictly excluded from executable plans
                continue

            # Determine action type and separate immediate vs recycle bin reclaim
            action = ActionType.RECYCLE_PATH
            immediate_b = 0
            recycle_b = 0

            if a_type == "package_cache" and owner_app == "npm":
                active_npm = get_tool_cache_path("npm")
                # Bind typed action only if candidate path matches active tool cache
                if active_npm and p.lower() == active_npm:
                    action = ActionType.NPM_CACHE_CLEAN
                    immediate_b = sz
                else:
                    action = ActionType.RECYCLE_PATH
                    recycle_b = sz
            elif a_type == "package_cache" and owner_app == "pip":
                active_pip = get_tool_cache_path("pip")
                # Bind typed action only if candidate path matches active tool cache
                if active_pip and p.lower() == active_pip:
                    action = ActionType.PIP_CACHE_PURGE
                    immediate_b = sz
                else:
                    action = ActionType.RECYCLE_PATH
                    recycle_b = sz
            elif a_type == "docker_builder":
                action = ActionType.DOCKER_BUILDER_PRUNE
                immediate_b = sz
            elif a_type == "browser_cache":
                action = ActionType.BROWSER_CACHE_PURGE
                recycle_b = sz
            elif a_type in ("office_file_cache", "teams_cache"):
                action = ActionType.OFFICE_CACHE_PURGE
                recycle_b = sz
            elif a_type in ("adobe_media_cache", "davinci_render_cache", "capcut_cache"):
                action = ActionType.CREATOR_CACHE_PURGE
                recycle_b = sz
            elif a_type in ("steam_shader_cache", "steam_downloading"):
                action = ActionType.GAMING_CACHE_PURGE
                recycle_b = sz
            elif a_type in ("obs_log_dir", "obs_crash_dir"):
                action = ActionType.STREAMING_LOGS_PURGE
                recycle_b = sz
            else:
                action = ActionType.RECYCLE_PATH
                # Moving to Recycle Bin does not immediately reclaim disk space on the volume!
                recycle_b = sz

            kind_str = determine_node_kind(p).value

            action_binding = {
                "action": action.value,
                "owner_app": owner_app,
                "capability_id": cap_id,
            }

            item = PlanItem(
                item_id=current_id,
                path=p,
                expected_kind=kind_str,
                candidate_bytes=sz,
                expected_mtime=mtime,
                risk=classification.risk,
                disposition=classification.disposition,
                action_type=action,
                description=f"Clean {a_type or 'item'} ({sz / (1024*1024):.1f} MB) via {action.value}",
                immediate_reclaimable_bytes=immediate_b,
                recycle_bin_bytes=recycle_b,
                potential_reclaim_bytes=immediate_b + recycle_b,
                warning=warning,
                artifact_id=art_id,
                source_detector=source_det,
                domain=dom,
                category=cat,
                action_binding=action_binding,
            )
            items.append(item)
            current_id += 1

        # Reject / filter out overlapping items (child paths inside parent paths)
        non_overlapping_items: List[PlanItem] = []
        for itm in sorted(items, key=lambda x: len(x.path)):
            itm_canon = canonicalize_path(itm.path).lower()
            is_overlap = False
            for parent_itm in non_overlapping_items:
                parent_canon = canonicalize_path(parent_itm.path).lower().rstrip("\\/") + "\\"
                if itm_canon.startswith(parent_canon):
                    is_overlap = True
                    break
            if not is_overlap:
                non_overlapping_items.append(itm)

        # Re-number item_ids sequentially starting at 1
        for idx, itm in enumerate(non_overlapping_items, start=1):
            itm.item_id = idx

        items = non_overlapping_items

        total_candidates = sum(i.candidate_bytes for i in items)
        total_immediate = sum(i.immediate_reclaimable_bytes for i in items)
        total_recycle = sum(i.recycle_bin_bytes for i in items)

        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        target_root_canon = canonicalize_path(target_root)
        total_potential = total_immediate + total_recycle
        plan_hash = compute_plan_hash(
            plan_id=plan_id,
            target_root=target_root_canon,
            created_at=created_at,
            items=items,
            secret_key=self.secret_key,
            total_items=len(items),
            total_candidate_bytes=total_candidates,
            total_immediate_reclaimable_bytes=total_immediate,
            total_recycle_bin_bytes=total_recycle,
            total_potential_reclaim_bytes=total_potential,
            schema_version=2,
        )

        plan = CleanupPlan(
            plan_id=plan_id,
            target_root=target_root_canon,
            created_at=created_at,
            total_items=len(items),
            total_candidate_bytes=total_candidates,
            total_immediate_reclaimable_bytes=total_immediate,
            total_recycle_bin_bytes=total_recycle,
            total_potential_reclaim_bytes=total_potential,
            plan_hash=plan_hash,
            items=items,
            schema_version=2,
        )

        # Save plan to cache
        self.save_plan(plan)
        return plan

        # Save plan to cache
        self.save_plan(plan)
        return plan

    def save_plan(self, plan: CleanupPlan) -> str:
        if not PLAN_ID_REGEX.match(plan.plan_id):
            raise ValueError(f"SECURITY REFUSAL: Invalid plan_id format '{plan.plan_id}'. Path traversal prevented.")
        fp = self.cache_dir / f"{plan.plan_id}.json"
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(plan.to_dict(), f, indent=2, ensure_ascii=False)
        return str(fp)

    def load_plan(self, plan_id: str) -> Optional[CleanupPlan]:
        if not PLAN_ID_REGEX.match(plan_id):
            raise ValueError(f"SECURITY REFUSAL: Invalid plan_id format '{plan_id}'. Path traversal prevented.")
        fp = self.cache_dir / f"{plan_id}.json"
        if not fp.exists():
            return None
        with open(fp, "r", encoding="utf-8") as f:
            data = json.load(f)
        return CleanupPlan.from_dict(data)
