"""Deterministic framework detection for immutable source snapshots."""

from lrail_detector.engine import Detector, detect
from lrail_detector.models import DETECTOR_VERSION, RULESET_VERSION, DetectionResult

__all__ = ["DETECTOR_VERSION", "RULESET_VERSION", "DetectionResult", "Detector", "detect"]
