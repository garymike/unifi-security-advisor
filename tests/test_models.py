import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from models import Finding

def test_finding_required_fields():
    f = Finding(
        id="TEST-001", section="Test", severity="high",
        status="gap", title="A finding", current_state="Something is wrong",
    )
    assert f.id == "TEST-001"
    assert f.severity == "high"

def test_finding_optional_defaults():
    f = Finding(
        id="TEST-002", section="Test", severity="low",
        status="ok", title="Fine", current_state="All good",
    )
    assert f.recommendation is None
    assert f.intent_question is None
    assert f.evidence == {}
    assert f.maps_to == {}
    assert f.effort == "medium"
    assert f.impact == "medium"
