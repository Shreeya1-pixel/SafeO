"""
BehaviorAgent: insider-threat detection via CUSUM change-point detection
augmented with an EWMA baseline.

Algorithm: CUSUM (Cumulative Sum Control Chart)
  Sequential analysis technique that is optimal (in the SPRT sense) for
  detecting a shift of a specified magnitude in a process mean.

  Upper CUSUM (detects sustained rate increase):
    S_n⁺ = max(0, S_{n-1}⁺ + (x_n - μ_0 - k))

  Lower CUSUM (detects sustained rate drop followed by burst — impersonation signal):
    S_n⁻ = max(0, S_{n-1}⁻ - (x_n - μ_0 - k))

  Alert triggers when: S_n⁺ > h  or  S_n⁻ > h

  Where:
    x_n  = current action count in the sliding window
    μ_0  = EWMA baseline (tracks slow drift of normal behavior)
    k    = allowable slack = CUSUM_K * σ  (half the shift to detect)
    h    = decision threshold = CUSUM_H * σ

  Variance σ² is estimated online using Welford's algorithm with exponential
  decay so that old observations do not permanently anchor the estimate.

CUSUM vs simple multiplier threshold:
  • CUSUM accumulates evidence over time — a sustained moderate excess triggers
    it even if no single sample crosses 3×baseline.
  • CUSUM is robust to transient spikes: a single burst resets without alerting
    unless the elevated rate is sustained.
  • CUSUM provides a principled, statistically grounded false-alarm rate.
"""

import math
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Tuple

from ..models.schemas import BehaviorResponse

# ── Sliding window ────────────────────────────────────────────────────────────
_action_log: Dict[str, List[datetime]] = defaultdict(list)
_baselines: Dict[str, float] = {}

WINDOW_HOURS = 1
HARD_LIMIT = 60  # absolute ceiling regardless of baseline

# ── CUSUM parameters ──────────────────────────────────────────────────────────
# k: allowable slack as a multiple of σ — half the shift we want to detect.
#    Lower k = more sensitive; higher k = more robust to noise.
CUSUM_K = 0.5

# h: decision threshold as a multiple of σ.
#    5σ gives a roughly 1/370 false-alarm probability per observation under H₀.
CUSUM_H = 5.0

# Minimum σ floor so that sparse users (few actions) have a reasonable threshold.
CUSUM_MIN_SIGMA = 0.8

# EWMA smoothing for variance tracking (Welford-style with exponential decay).
VARIANCE_ALPHA = 0.15   # weight on the new observation
VARIANCE_DECAY = 0.85   # weight on historical estimate

# EWMA smoothing for baseline tracking.
BASELINE_ALPHA = 0.30

# CUSUM state per user: S_pos (upper), S_neg (lower), variance, n_obs.
_cusum: Dict[str, Dict[str, float]] = defaultdict(
    lambda: {"S_pos": 0.0, "S_neg": 0.0, "variance": 2.0, "n_obs": 0}
)


def _update_cusum(
    user_id: str, count: float, baseline: float
) -> Tuple[float, bool, str]:
    """
    Advance the CUSUM statistics for user_id given the current action count.

    Returns:
        risk_score  -- float [0, 1]
        alert       -- True if either CUSUM statistic exceeded its threshold
        explanation -- human-readable summary
    """
    state = _cusum[user_id]

    # ── Online variance estimate (Welford with exponential decay) ────────────
    state["n_obs"] += 1
    deviation_sq = (count - baseline) ** 2
    if state["n_obs"] <= 2:
        state["variance"] = max(deviation_sq, CUSUM_MIN_SIGMA ** 2)
    else:
        state["variance"] = (
            VARIANCE_DECAY * state["variance"] + VARIANCE_ALPHA * deviation_sq
        )

    sigma = max(math.sqrt(state["variance"]), CUSUM_MIN_SIGMA)
    k = CUSUM_K * sigma
    h = CUSUM_H * sigma

    # ── Upper CUSUM: detect upward mean shift (rate surge) ────────────────────
    state["S_pos"] = max(0.0, state["S_pos"] + (count - baseline - k))

    # ── Lower CUSUM: detect downward shift (gap then burst = impersonation) ───
    state["S_neg"] = max(0.0, state["S_neg"] - (count - baseline + k))

    S_pos = state["S_pos"]
    S_neg = state["S_neg"]
    alert = S_pos > h or S_neg > h

    if S_pos > h:
        # Risk scales with how far S_pos exceeded h (capped at 1.0).
        risk = round(min(0.45 + (S_pos - h) / (h * 3), 1.0) * 0.90, 3)
        explanation = (
            f"CUSUM upper alert: cumulative deviation S⁺={S_pos:.1f} exceeds "
            f"threshold h={h:.1f} (σ={sigma:.1f}) — "
            f"sustained activity surge detected for {user_id}"
        )
        # Reset after alert to re-arm detection for the next episode.
        state["S_pos"] = 0.0

    elif S_neg > h:
        # Downward shift is less dangerous — weight lower.
        risk = round(min(0.30 + (S_neg - h) / (h * 4), 0.70), 3)
        explanation = (
            f"CUSUM lower alert: inactivity gap S⁻={S_neg:.1f} exceeds "
            f"threshold h={h:.1f} — "
            f"unusual pause-then-burst pattern for {user_id} (possible session hijack)"
        )
        state["S_neg"] = 0.0

    else:
        risk = 0.0
        explanation = "Behavior within normal parameters"

    return risk, alert, explanation


class BehaviorAgent:
    name = "BehaviorWatch-CUSUM"
    description = (
        "Insider-threat detection using CUSUM change-point detection "
        "with online EWMA baseline tracking"
    )

    def track_action(self, user_id: str, action: str) -> BehaviorResponse:
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=WINDOW_HOURS)

        _action_log[user_id].append(now)
        _action_log[user_id] = [t for t in _action_log[user_id] if t > cutoff]
        count = len(_action_log[user_id])

        # ── EWMA baseline update ──────────────────────────────────────────────
        if user_id not in _baselines:
            _baselines[user_id] = float(count)
        else:
            _baselines[user_id] = (
                BASELINE_ALPHA * count + (1 - BASELINE_ALPHA) * _baselines[user_id]
            )
        baseline = _baselines[user_id]

        # ── CUSUM change-point detection ──────────────────────────────────────
        cusum_risk, cusum_alert, cusum_explanation = _update_cusum(
            user_id, float(count), baseline
        )

        # ── Hard rate-limit guardrail (preserved from original) ───────────────
        hard_limit_triggered = count >= HARD_LIMIT
        if hard_limit_triggered:
            hard_risk = round(min(count / 100, 1.0), 3)
            hard_explanation = f"Rate limit breach: {count} actions in the last hour"
        else:
            hard_risk = 0.0
            hard_explanation = ""

        # ── Take the maximum risk across both detection paths ─────────────────
        if hard_limit_triggered and hard_risk >= cusum_risk:
            final_risk = hard_risk
            anomaly = True
            explanation = hard_explanation
        elif cusum_alert:
            final_risk = cusum_risk
            anomaly = True
            explanation = cusum_explanation
        else:
            final_risk = 0.0
            anomaly = False
            explanation = "Behavior within normal parameters"

        return BehaviorResponse(
            user_id=user_id,
            risk_score=round(final_risk, 3),
            anomaly_detected=anomaly,
            explanation=explanation,
            action_count=count,
            baseline_avg=round(baseline, 1),
        )

    def get_history(self, user_id: str) -> dict:
        return {
            "user_id": user_id,
            "action_count_last_hour": len(_action_log.get(user_id, [])),
            "baseline_avg": round(_baselines.get(user_id, 0), 1),
            "cusum_S_pos": round(_cusum[user_id]["S_pos"], 2),
            "cusum_S_neg": round(_cusum[user_id]["S_neg"], 2),
        }
