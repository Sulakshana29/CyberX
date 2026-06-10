"""CVSS v3.1 scoring utilities for vulnerability assessment.

Implements the official CVSS 3.1 base score formula as defined in:
https://www.first.org/cvss/v3.1/specification-document
"""

import math
from typing import Dict


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup function: round up to 1 decimal place.

    Rounds to the nearest tenth, rounding up when the value is exactly
    half-way between two tenths (as specified by CVSS 3.1 §7.4).
    """
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return math.floor(int_input / 10000 + 1) / 10


def calculate_cvss_score(
    attack_vector: str = "NETWORK",
    attack_complexity: str = "LOW",
    privileges_required: str = "NONE",
    user_interaction: str = "NONE",
    scope: str = "UNCHANGED",
    confidentiality: str = "HIGH",
    integrity: str = "HIGH",
    availability: str = "HIGH",
) -> Dict:
    """Calculate CVSS v3.1 base score.

    Args:
        attack_vector:        AV  — NETWORK | ADJACENT | LOCAL | PHYSICAL
        attack_complexity:    AC  — LOW | HIGH
        privileges_required:  PR  — NONE | LOW | HIGH
        user_interaction:     UI  — NONE | REQUIRED
        scope:                S   — UNCHANGED | CHANGED
        confidentiality:      C   — NONE | LOW | HIGH
        integrity:            I   — NONE | LOW | HIGH
        availability:         A   — NONE | LOW | HIGH

    Returns:
        {
            'score':    float  (0.0 – 10.0, one decimal),
            'severity': str    (NONE | LOW | MEDIUM | HIGH | CRITICAL),
            'vector':   str    (CVSS:3.1/AV:…),
        }
    """
    # ---- Metric value tables ----------------------------------------

    av_map = {'NETWORK': 0.85, 'ADJACENT': 0.62, 'LOCAL': 0.55, 'PHYSICAL': 0.20}
    ac_map = {'LOW': 0.77, 'HIGH': 0.44}
    # PR values differ by Scope (CVSS 3.1 §7.1 table)
    pr_map = {
        'UNCHANGED': {'NONE': 0.85, 'LOW': 0.62, 'HIGH': 0.27},
        'CHANGED':   {'NONE': 0.85, 'LOW': 0.68, 'HIGH': 0.50},
    }
    ui_map  = {'NONE': 0.85, 'REQUIRED': 0.62}
    imp_map = {'NONE': 0.00, 'LOW': 0.22, 'HIGH': 0.56}

    # ---- Retrieve numeric values ------------------------------------

    av  = av_map.get(attack_vector.upper(),       0.85)
    ac  = ac_map.get(attack_complexity.upper(),   0.77)
    pr  = pr_map.get(scope.upper(), pr_map['UNCHANGED']).get(
              privileges_required.upper(), 0.85)
    ui  = ui_map.get(user_interaction.upper(),    0.85)
    c   = imp_map.get(confidentiality.upper(),    0.56)
    i   = imp_map.get(integrity.upper(),          0.56)
    a   = imp_map.get(availability.upper(),       0.56)

    # ---- ISS (Impact Sub-Score) ------------------------------------
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    # ---- Impact ----------------------------------------------------
    if scope.upper() == 'UNCHANGED':
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    # ---- Exploitability --------------------------------------------
    exploitability = 8.22 * av * ac * pr * ui

    # ---- Base Score ------------------------------------------------
    if impact <= 0:
        base_score = 0.0
    elif scope.upper() == 'UNCHANGED':
        base_score = _roundup(min((impact + exploitability), 10))
    else:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10))

    # ---- Severity --------------------------------------------------
    if base_score == 0.0:
        severity = 'NONE'
    elif base_score < 4.0:
        severity = 'LOW'
    elif base_score < 7.0:
        severity = 'MEDIUM'
    elif base_score < 9.0:
        severity = 'HIGH'
    else:
        severity = 'CRITICAL'

    # ---- Short-form metric letters for vector string ---------------
    av_short  = attack_vector[0]      # N/A/L/P
    ac_short  = attack_complexity[0]  # L/H
    pr_short  = privileges_required[0]
    ui_short  = 'N' if user_interaction.upper() == 'NONE' else 'R'
    s_short   = 'U' if scope.upper() == 'UNCHANGED' else 'C'
    c_short   = confidentiality[0]
    i_short   = integrity[0]
    a_short   = availability[0]

    vector = (
        f"CVSS:3.1/AV:{av_short}/AC:{ac_short}/PR:{pr_short}"
        f"/UI:{ui_short}/S:{s_short}/C:{c_short}/I:{i_short}/A:{a_short}"
    )

    return {'score': base_score, 'severity': severity, 'vector': vector}


# ---------------------------------------------------------------------------
# Pre-built profiles for common vulnerability types
# ---------------------------------------------------------------------------

def get_sqli_cvss() -> Dict:
    """CVSS 3.1 for unauthenticated error-based SQL Injection (typical)."""
    return calculate_cvss_score(
        attack_vector='NETWORK',
        attack_complexity='LOW',
        privileges_required='NONE',
        user_interaction='NONE',
        scope='UNCHANGED',
        confidentiality='HIGH',
        integrity='HIGH',
        availability='HIGH',
    )


def get_xss_cvss() -> Dict:
    """CVSS 3.1 for Reflected XSS (scope changed — attacker targets user)."""
    return calculate_cvss_score(
        attack_vector='NETWORK',
        attack_complexity='LOW',
        privileges_required='NONE',
        user_interaction='REQUIRED',
        scope='CHANGED',
        confidentiality='LOW',
        integrity='LOW',
        availability='NONE',
    )


def get_missing_headers_cvss() -> Dict:
    """CVSS 3.1 for missing security headers."""
    return calculate_cvss_score(
        attack_vector='NETWORK',
        attack_complexity='LOW',
        privileges_required='NONE',
        user_interaction='REQUIRED',
        scope='UNCHANGED',
        confidentiality='LOW',
        integrity='LOW',
        availability='NONE',
    )


def get_ssrf_cvss() -> Dict:
    """CVSS 3.1 for Server-Side Request Forgery."""
    return calculate_cvss_score(
        attack_vector='NETWORK',
        attack_complexity='LOW',
        privileges_required='NONE',
        user_interaction='NONE',
        scope='CHANGED',
        confidentiality='HIGH',
        integrity='NONE',
        availability='NONE',
    )
