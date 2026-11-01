from pathlib import Path
from vulnscope.triage.train import evaluate, labeled_findings
from vulnscope.triage.model import features, FEATURE_NAMES

FX = Path(__file__).parents[1] / "fixtures"


def test_feature_vector_shape():
    f, _ = labeled_findings(FX / "vulnapp")[0]
    assert features(f).shape == (len(FEATURE_NAMES),)


def test_labels_include_false_positives_on_heldout_repo():
    labels = [y for _, y in labeled_findings(FX / "vulnapp2")]
    assert 1 in labels and 0 in labels


def test_repo_level_triage_evaluation_runs():
    res = evaluate([FX / "vulnapp", FX / "vulnapp3"], [FX / "vulnapp2"])
    assert res["n_test"] > 0 and "fp_reduction" in res and res["feature_importance"]
