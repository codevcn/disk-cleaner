"""
AI/ML model and cache detectors (Ollama, HuggingFace).
"""

from .huggingface import HuggingFaceCacheDetector
from .ollama import OllamaModelDetector

__all__ = ["OllamaModelDetector", "HuggingFaceCacheDetector"]
