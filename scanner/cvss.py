"""CVSS v3.1 scoring utilities for vulnerability assessment."""

from enum import Enum
from typing import Dict


class CVSSVector(Enum):
    """CVSS v3.1 metric enumerations."""
    
    # Attack Vector
    NETWORK = 0.85
    ADJACENT = 0.62
    LOCAL = 0.55
    PHYSICAL = 0.2
    
    # Attack Complexity
    LOW = 0.77
    HIGH = 0.44
    
    # Privileges Required
    NONE = 0.85
    LOW = 0.62
    HIGH = 0.27
    
    # User Interaction
    NONE = 0.85
    REQUIRED = 0.62
    
    # Scope
    UNCHANGED = 1.0
    CHANGED = 1.08


def calculate_cvss_score(
    attack_vector: str = "NETWORK",
    attack_complexity: str = "LOW",
    privileges_required: str = "NONE",
    user_interaction: str = "NONE",
    scope: str = "UNCHANGED",
    confidentiality: str = "HIGH",
    integrity: str = "HIGH",
    availability: str = "HIGH"
) -> Dict[str, float]:
    """Calculate CVSS v3.1 score for a vulnerability.
    
    Args:
        attack_vector: AV - How vulnerable component is attacked.
        attack_complexity: AC - Conditions required to exploit.
        privileges_required: PR - Privilege level needed.
        user_interaction: UI - User interaction required.
        scope: S - Whether vulnerable component is isolated.
        confidentiality: C - Impact to confidentiality (HIGH/MEDIUM/LOW/NONE).
        integrity: I - Impact to integrity (HIGH/MEDIUM/LOW/NONE).
        availability: A - Impact to availability (HIGH/MEDIUM/LOW/NONE).
        
    Returns:
        Dictionary with 'score' (0-10) and 'severity' (CRITICAL/HIGH/MEDIUM/LOW/NONE).
    """
    # Impact metrics mapping
    impact_values = {
        'HIGH': 0.56,
        'MEDIUM': 0.22,
        'LOW': 0.22,
        'NONE': 0.0
    }
    
    # Scope modifier
    scope_mult = 1.08 if scope == "CHANGED" else 1.0
    
    # Calculate Base Score
    iss = (1 - ((1 - impact_values[confidentiality]) *
                (1 - impact_values[integrity]) *
                (1 - impact_values[availability])))
    
    # Base score components
    av_value = {'NETWORK': 0.85, 'ADJACENT': 0.62, 'LOCAL': 0.55, 'PHYSICAL': 0.2}
    ac_value = {'LOW': 0.77, 'HIGH': 0.44}
    pr_values = {'UNCHANGED': {'NONE': 0.85, 'LOW': 0.62, 'HIGH': 0.27},
                 'CHANGED': {'NONE': 0.85, 'LOW': 0.68, 'HIGH': 0.50}}
    ui_value = {'NONE': 0.85, 'REQUIRED': 0.62}
    
    pr_val = pr_values.get(scope, {}).get(privileges_required, 0.85)
    
    exploitability = (8.22 * av_value.get(attack_vector, 0.85) *
                     ac_value.get(attack_complexity, 0.77) *
                     pr_val * ui_value.get(user_interaction, 0.85))
    
    base_score = ((iss * exploitability * scope_mult) + 1.4) if iss > 0 else 0
    base_score = min(base_score, 10.0)
    
    # Severity rating
    if base_score >= 9.0:
        severity = 'CRITICAL'
    elif base_score >= 7.0:
        severity = 'HIGH'
    elif base_score >= 4.0:
        severity = 'MEDIUM'
    elif base_score > 0:
        severity = 'LOW'
    else:
        severity = 'NONE'
    
    return {
        'score': round(base_score, 1),
        'severity': severity,
        'vector': f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
    }


def get_sqli_cvss() -> Dict[str, float]:
    """Get CVSS score for SQL Injection vulnerability.
    
    Returns:
        CVSS scoring dictionary.
    """
    return calculate_cvss_score(
        attack_vector="NETWORK",
        attack_complexity="LOW",
        privileges_required="NONE",
        user_interaction="NONE",
        scope="UNCHANGED",
        confidentiality="HIGH",
        integrity="HIGH",
        availability="HIGH"
    )


def get_xss_cvss() -> Dict[str, float]:
    """Get CVSS score for Reflected XSS vulnerability.
    
    Returns:
        CVSS scoring dictionary.
    """
    return calculate_cvss_score(
        attack_vector="NETWORK",
        attack_complexity="LOW",
        privileges_required="NONE",
        user_interaction="REQUIRED",
        scope="CHANGED",
        confidentiality="HIGH",
        integrity="HIGH",
        availability="HIGH"
    )
