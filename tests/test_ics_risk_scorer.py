"""Tests for ICS/OT Risk Scorer module."""

import pytest
from unittest.mock import patch

from industrialxpl.modules.assessment.risk.ics_risk_scorer import Exploit as RiskScorer


class TestRiskScorerMetadata:
    def test_info_name(self):
        e = RiskScorer()
        info = e.get_info()
        assert "Risk" in info["name"] or "risk" in info["name"].lower()

    def test_info_has_authors(self):
        e = RiskScorer()
        assert len(e.get_info()["authors"]) > 0


class TestRiskScorerVectors:
    def test_vectors_module_var(self):
        from industrialxpl.modules.assessment.risk import ics_risk_scorer
        assert hasattr(ics_risk_scorer, "_VECTORS")
        assert len(ics_risk_scorer._VECTORS) == 10

    def test_vector_structure(self):
        from industrialxpl.modules.assessment.risk.ics_risk_scorer import _VECTORS
        for v in _VECTORS:
            assert "id" in v
            assert "name" in v
            assert "description" in v
            assert "score_yes" in v
            assert "score_partial" in v
            assert "recommendation" in v

    def test_vector_ids_sequential(self):
        from industrialxpl.modules.assessment.risk.ics_risk_scorer import _VECTORS
        ids = [v["id"] for v in _VECTORS]
        assert ids == list(range(1, 11))

    def test_vector_scores_positive(self):
        from industrialxpl.modules.assessment.risk.ics_risk_scorer import _VECTORS
        for v in _VECTORS:
            assert v["score_yes"] > 0
            assert v["score_partial"] > 0
            assert v["score_partial"] < v["score_yes"]

    def test_vector_has_mitre_refs(self):
        from industrialxpl.modules.assessment.risk.ics_risk_scorer import _VECTORS
        for v in _VECTORS:
            assert "mitre" in v
            assert len(v["mitre"]) > 0

    def test_vector_has_standard_refs(self):
        from industrialxpl.modules.assessment.risk.ics_risk_scorer import _VECTORS
        for v in _VECTORS:
            assert "standard" in v
            assert len(v["standard"]) > 0
