from app.utils.risk import calculate_risk_score, map_severity


def test_risk_score_calculation():
    assert calculate_risk_score(5, 4) == 20


def test_severity_mapping():
    assert map_severity(4) == "Low"
    assert map_severity(9) == "Medium"
    assert map_severity(16) == "High"
    assert map_severity(17) == "Critical"
