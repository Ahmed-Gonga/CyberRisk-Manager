"""Risk scoring utilities used by the application and tests."""
from datetime import date


SEVERITIES = ["Low", "Medium", "High", "Critical"]


def calculate_risk_score(likelihood: int, impact: int) -> int:
    """Return risk score after validating likelihood and impact are 1-5."""
    if likelihood not in range(1, 6):
        raise ValueError("likelihood must be between 1 and 5")
    if impact not in range(1, 6):
        raise ValueError("impact must be between 1 and 5")
    return likelihood * impact


def map_severity(score: int) -> str:
    """Map a 1-25 score to the project severity matrix."""
    if score < 1 or score > 25:
        raise ValueError("score must be between 1 and 25")
    if score <= 4:
        return "Low"
    if score <= 9:
        return "Medium"
    if score <= 16:
        return "High"
    return "Critical"


def severity_class(likelihood: int, impact: int) -> str:
    return map_severity(calculate_risk_score(likelihood, impact))


def build_heatmap(risks):
    """Return a 5x5 likelihood/impact matrix with counts and severity per cell."""
    cells = []
    for impact in range(5, 0, -1):
        row = []
        for likelihood in range(1, 6):
            count = len([r for r in risks if r.impact == impact and r.likelihood == likelihood])
            row.append({
                "likelihood": likelihood,
                "impact": impact,
                "score": likelihood * impact,
                "severity": severity_class(likelihood, impact),
                "count": count,
            })
        cells.append({"impact": impact, "cells": row})
    return cells


def is_overdue(target_date) -> bool:
    """Return True when a risk/finding due date has passed."""
    return bool(target_date and target_date < date.today())
