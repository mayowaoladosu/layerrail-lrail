"""Deterministic framework detection for immutable source snapshots."""

from lrail_detector.engine import Detector, detect
from lrail_detector.models import DetectionResult

__all__ = ["DetectionResult", "Detector", "detect"]
