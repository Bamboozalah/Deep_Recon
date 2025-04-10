# risk_utils.py
import re

def apply_risk_score(results):
    """
    Assigns risk scores to findings based on known indicators of severity.
    Input is a list of dictionaries, each representing a finding.
    Each dictionary will be enhanced with a 'risk_score' (0–100) and 'risk_level'.
    """
    scored = []
    for item in results:
        score = 0
        reason = []

        data = item.get("content", "") + " " + item.get("url", "") + " " + item.get("source", "")
        data = data.lower()

        if any(x in data for x in ["apikey", "secret", "token", "password"]):
            score += 40
            reason.append("credential leak")

        if any(x in data for x in ["s3.amazonaws.com", ".env", ".git", "/.aws", "/admin"]):
            score += 30
            reason.append("sensitive endpoint")

        if re.search(r"(?:authorization|bearer|basic)\s+[a-z0-9\-_.]+", data):
            score += 20
            reason.append("authorization token pattern")

        if re.search(r"error.*(stack|trace|exception)", data):
            score += 10
            reason.append("debug output")

        if "production" in data or "prod" in data:
            score += 5
            reason.append("production indicator")

        if score >= 70:
            level = "Critical"
        elif score >= 40:
            level = "High"
        elif score >= 20:
            level = "Medium"
        elif score > 0:
            level = "Low"
        else:
            level = "Informational"

        item["risk_score"] = score
        item["risk_level"] = level
        item["risk_reasons"] = reason
        scored.append(item)

    return scored
