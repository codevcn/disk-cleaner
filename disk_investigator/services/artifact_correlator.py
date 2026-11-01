"""
Artifact Correlator: Deduplicates, merges evidence conservatively, and manages
hierarchical containment between detected storage artifacts.
"""

from __future__ import annotations

import os
from typing import Dict, List, Set

from ..models import (
    ArtifactCategory,
    ArtifactDomain,
    Confidence,
    Evidence,
    RecommendedAction,
    RecoveryCost,
    Regenerability,
    StorageArtifact,
    UserDataProbability,
    generate_artifact_id,
)
from ..path_policy import canonicalize_path


class ArtifactCorrelator:
    """
    Correlates artifacts from multiple detectors:
    1. Deduplicates artifacts pointing to the exact same canonical path.
    2. Resolves conflicting attributes using fail-closed conservative rules.
    3. Identifies parent-child containment to prevent double-counting bytes.
    """

    # Precedence hierarchies (higher rank = higher priority/more conservative)
    # Fail-closed invariant: Non-cleanup actions (BLOCK, KEEP, REVIEW_ONLY, UNINSTALL_VIA_APP)
    # strictly take precedence over cleanup actions (TYPED_CLEANUP, RECYCLE_KNOWN_CACHE).
    # If any detector reports KEEP, it must override any detector suggesting cleanup.
    ACTION_PRECEDENCE = {
        RecommendedAction.BLOCK: 100,
        RecommendedAction.KEEP: 90,
        RecommendedAction.REVIEW_ONLY: 80,
        RecommendedAction.UNINSTALL_VIA_APP: 70,
        RecommendedAction.TYPED_CLEANUP: 30,
        RecommendedAction.RECYCLE_KNOWN_CACHE: 20,
    }

    USER_DATA_PRECEDENCE = {
        UserDataProbability.HIGH: 30,
        UserDataProbability.MEDIUM: 20,
        UserDataProbability.LOW: 10,
    }

    # For regenerability, lower ability to regenerate is more dangerous/conservative
    REGENERABILITY_CONSERVATIVE = {
        Regenerability.NONE: 10,     # most conservative / dangerous to delete
        Regenerability.PARTIAL: 20,
        Regenerability.FULL: 30,     # least conservative
    }

    RECOVERY_COST_PRECEDENCE = {
        RecoveryCost.IMPOSSIBLE: 40,
        RecoveryCost.HIGH: 30,
        RecoveryCost.MEDIUM: 20,
        RecoveryCost.LOW: 10,
    }

    CONFIDENCE_PRECEDENCE = {
        Confidence.HIGH: 30,
        Confidence.MEDIUM: 20,
        Confidence.LOW: 10,
    }

    @classmethod
    def correlate(cls, artifacts: List[StorageArtifact]) -> List[StorageArtifact]:
        """
        Deduplicate identical paths, merge evidence conservatively,
        and annotate containment relationships.
        """
        if not artifacts:
            return []

        # Step 1: Group by canonical path
        grouped: Dict[str, List[StorageArtifact]] = {}
        for art in artifacts:
            canon = canonicalize_path(art.canonical_path or art.path)
            grouped.setdefault(canon.lower(), []).append(art)

        # Step 2: Merge each group
        merged_list: List[StorageArtifact] = []
        for canon_lower, group in grouped.items():
            if len(group) == 1:
                # Ensure canonical_path is properly set
                single = group[0]
                if not single.canonical_path:
                    single.canonical_path = canonicalize_path(single.path)
                merged_list.append(single)
            else:
                merged_list.append(cls._merge_group(group))

        # Step 3: Sort by canonical path length (shortest first)
        merged_list.sort(key=lambda a: a.canonical_path.lower())

        # Step 4: Check containment (parent vs child paths)
        cls._annotate_containment(merged_list)

        return merged_list

    @classmethod
    def _merge_group(cls, group: List[StorageArtifact]) -> StorageArtifact:
        """Merge multiple artifacts for the same path into one conservative artifact."""
        base = group[0]
        canon = canonicalize_path(base.canonical_path or base.path)

        # Conservative action: highest rank in ACTION_PRECEDENCE
        best_action = max(
            (a.recommended_action for a in group),
            key=lambda act: cls.ACTION_PRECEDENCE.get(act, 0),
        )

        # Conservative user data probability: highest rank
        best_user_data = max(
            (a.user_data_probability for a in group),
            key=lambda udp: cls.USER_DATA_PRECEDENCE.get(udp, 0),
        )

        # Conservative regenerability: lowest ability (NONE < PARTIAL < FULL)
        best_regen = min(
            (a.regenerability for a in group),
            key=lambda reg: cls.REGENERABILITY_CONSERVATIVE.get(reg, 99),
        )

        # Conservative recovery cost: highest rank
        best_rec_cost = max(
            (a.recovery_cost for a in group),
            key=lambda rc: cls.RECOVERY_COST_PRECEDENCE.get(rc, 0),
        )

        # Highest confidence
        best_conf = max(
            (a.confidence for a in group),
            key=lambda c: cls.CONFIDENCE_PRECEDENCE.get(c, 0),
        )

        # Pick domain and category that is most specific
        chosen_domain = base.domain
        for a in group:
            if a.domain != ArtifactDomain.GENERAL:
                chosen_domain = a.domain
                break

        chosen_category = base.category
        for a in group:
            if a.category != ArtifactCategory.UNKNOWN:
                chosen_category = a.category
                break

        # Pick largest reported size
        max_bytes = max(a.logical_bytes for a in group)

        # Latest mtime if available
        valid_mtimes = [a.mtime for a in group if a.mtime is not None]
        mtime = max(valid_mtimes) if valid_mtimes else None

        # Merge evidence avoiding exact duplicates
        all_evidence: List[Evidence] = []
        seen_evidence: Set[str] = set()
        for a in group:
            for ev in a.evidence:
                ev_obj = ev if isinstance(ev, Evidence) else Evidence.from_dict(ev)
                ev_key = f"{ev_obj.kind}|{ev_obj.source}|{ev_obj.value}"
                if ev_key not in seen_evidence:
                    seen_evidence.add(ev_key)
                    all_evidence.append(ev_obj)

        source_detectors = sorted(list({a.source_detector for a in group if a.source_detector}))
        merged_source = "+".join(source_detectors) if source_detectors else "correlator"

        owner_apps = [a.owner_app for a in group if a.owner_app]
        merged_owner = owner_apps[0] if owner_apps else None

        capability_ids = [a.capability_id for a in group if a.capability_id]
        merged_cap = capability_ids[0] if capability_ids else None

        art_type = group[0].artifact_type
        for a in group:
            if a.artifact_type and a.artifact_type != "unknown":
                art_type = a.artifact_type
                break

        return StorageArtifact(
            artifact_id=generate_artifact_id(canon, art_type, merged_source),
            path=base.path,
            canonical_path=canon,
            domain=chosen_domain,
            category=chosen_category,
            artifact_type=art_type,
            owner_app=merged_owner,
            capability_id=merged_cap,
            source_detector=merged_source,
            logical_bytes=max_bytes,
            mtime=mtime,
            regenerability=best_regen,
            user_data_probability=best_user_data,
            recovery_cost=best_rec_cost,
            recommended_action=best_action,
            confidence=best_conf,
            evidence=all_evidence,
        )

    @classmethod
    def _annotate_containment(cls, artifacts: List[StorageArtifact]) -> None:
        """
        Check for parent-child containment among artifacts.
        If artifact A contains artifact B, add an evidence record to artifact B
        pointing to its parent artifact ID.
        """
        for i, parent in enumerate(artifacts):
            p_path = parent.canonical_path.rstrip("\\/") + "\\"
            for j, child in enumerate(artifacts):
                if i == j:
                    continue
                c_path = child.canonical_path
                if c_path.lower().startswith(p_path.lower()):
                    child.evidence.append(
                        Evidence(
                            kind="containment",
                            source="correlator",
                            value=parent.canonical_path,
                            message=f"Contained inside parent artifact {parent.artifact_id}",
                        )
                    )

    @classmethod
    def calculate_net_bytes(cls, artifacts: List[StorageArtifact]) -> int:
        """
        Calculate total non-overlapping logical bytes.
        If a child path is completely contained within a parent path,
        the child's bytes are not double-counted on top of the parent.
        """
        if not artifacts:
            return 0

        # Sort by canonical path length
        sorted_arts = sorted(artifacts, key=lambda a: len(a.canonical_path))
        accounted_paths: List[str] = []
        total_bytes = 0

        for art in sorted_arts:
            canon = art.canonical_path.rstrip("\\/")
            # Check if this art is a child of an already accounted path
            is_child = False
            for parent_path in accounted_paths:
                if canon.lower().startswith((parent_path + "\\").lower()):
                    is_child = True
                    break

            if not is_child:
                total_bytes += art.logical_bytes
                accounted_paths.append(canon)

        return total_bytes
