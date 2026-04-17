"""CVSS 3.1 score calculator."""

import math

# CVSS 3.1 metric weights
WEIGHTS = {
    "attack_vector": {"Network": 0.85, "Adjacent": 0.62, "Local": 0.55, "Physical": 0.20},
    "attack_complexity": {"Low": 0.77, "High": 0.44},
    "privileges_required": {
        "Unchanged": {"None": 0.85, "Low": 0.62, "High": 0.27},
        "Changed": {"None": 0.85, "Low": 0.68, "High": 0.50},
    },
    "user_interaction": {"None": 0.85, "Required": 0.62},
    "confidentiality": {"High": 0.56, "Low": 0.22, "None": 0.0},
    "integrity": {"High": 0.56, "Low": 0.22, "None": 0.0},
    "availability": {"High": 0.56, "Low": 0.22, "None": 0.0},
}


def calculate_cvss(dimensions: dict) -> dict:
    """Calculate CVSS 3.1 base score from dimensions.

    Args:
        dimensions: {attack_vector, attack_complexity, privileges_required,
                     user_interaction, scope, confidentiality, integrity, availability}

    Returns:
        {score, severity, vector, dict}
    """
    av = dimensions.get("attack_vector", "Network")
    ac = dimensions.get("attack_complexity", "Low")
    pr = dimensions.get("privileges_required", "None")
    ui = dimensions.get("user_interaction", "None")
    scope = dimensions.get("scope", "Unchanged")
    c = dimensions.get("confidentiality", "None")
    i = dimensions.get("integrity", "None")
    a = dimensions.get("availability", "None")

    # Get weights
    av_w = WEIGHTS["attack_vector"].get(av, 0.85)
    ac_w = WEIGHTS["attack_complexity"].get(ac, 0.77)
    pr_w = WEIGHTS["privileges_required"].get(scope, {}).get(pr, 0.85)
    ui_w = WEIGHTS["user_interaction"].get(ui, 0.85)
    c_w = WEIGHTS["confidentiality"].get(c, 0.0)
    i_w = WEIGHTS["integrity"].get(i, 0.0)
    a_w = WEIGHTS["availability"].get(a, 0.0)

    # Impact Sub Score (ISS)
    iss = 1 - ((1 - c_w) * (1 - i_w) * (1 - a_w))

    # Impact
    if scope == "Unchanged":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    # Exploitability
    exploitability = 8.22 * av_w * ac_w * pr_w * ui_w

    # Base Score
    if impact <= 0:
        score = 0.0
    elif scope == "Unchanged":
        score = min(impact + exploitability, 10.0)
        score = math.ceil(score * 10) / 10
    else:
        score = min(1.08 * (impact + exploitability), 10.0)
        score = math.ceil(score * 10) / 10

    # Severity rating
    if score == 0.0:
        severity = "None"
    elif score <= 3.9:
        severity = "Low"
    elif score <= 6.9:
        severity = "Medium"
    elif score <= 8.9:
        severity = "High"
    else:
        severity = "Critical"

    # Vector string
    av_short = {"Network": "N", "Adjacent": "A", "Local": "L", "Physical": "P"}.get(av, "N")
    ac_short = {"Low": "L", "High": "H"}.get(ac, "L")
    pr_short = {"None": "N", "Low": "L", "High": "H"}.get(pr, "N")
    ui_short = {"None": "N", "Required": "R"}.get(ui, "N")
    s_short = {"Unchanged": "U", "Changed": "C"}.get(scope, "U")
    c_short = {"None": "N", "Low": "L", "High": "H"}.get(c, "N")
    i_short = {"None": "N", "Low": "L", "High": "H"}.get(i, "N")
    a_short = {"None": "N", "Low": "L", "High": "H"}.get(a, "N")

    vector = f"CVSS:3.1/AV:{av_short}/AC:{ac_short}/PR:{pr_short}/UI:{ui_short}/S:{s_short}/C:{c_short}/I:{i_short}/A:{a_short}"

    return {
        "score": score,
        "severity": severity,
        "vector": vector,
        "dict": dimensions,
    }
