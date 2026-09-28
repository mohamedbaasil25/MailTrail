import logging

logger = logging.getLogger(__name__)

class PhishingNLPAnalyzer:
    """
    Wrapper for a HuggingFace transformers pipeline to detect phishing intent using DistilBERT.
    """
    def __init__(self, model_name: str = "ealvaradob/bert-finetuned-phishing"):
        self.model_name = model_name
        self.classifier = None
        self._loaded = False

    def _load_model(self):
        if self._loaded:
            return
        from config import settings
        if not settings.enable_heavy_nlp:
            logger.info("Heavy NLP model disabled via config (likely low-memory environment). Skipping load.")
            self._loaded = True
            return

        try:
            from transformers import pipeline
            logger.info(f"Loading NLP model: {self.model_name}...")
            self.classifier = pipeline("text-classification", model=self.model_name, truncation=True, max_length=512)
            logger.info("NLP model loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load NLP model {self.model_name}: {e}")
            self.classifier = None
        finally:
            self._loaded = True

    def analyze_text(self, text: str) -> dict:
        self._load_model()
        """
        Analyzes text and normalizes the output to a phishing probability score (0.0 to 1.0).
        """
        if not self.classifier:
            return {
                "status": "unavailable",
                "phishing_probability": None, 
                "intent_label": "UNAVAILABLE", 
                "raw_score": None
            }
            
        if not text.strip():
            return {
                "status": "available",
                "phishing_probability": 0.0, 
                "intent_label": "UNKNOWN", 
                "raw_score": 0.0
            }

        try:
            # DistilBERT handles up to 512 tokens. The pipeline truncation=True will truncate it,
            # but we can also pre-trim to avoid massive string processing.
            truncated_text = " ".join(text.split()[:512])
            
            result = self.classifier(truncated_text)[0]
            label = result['label']
            score = result['score']
            
            # --- Score Normalization Logic ---
            # Explicit model configuration mapping
            NLP_POSITIVE_LABELS = {"PHISHING", "SPAM", "MALICIOUS", "NEGATIVE", "LABEL_1"}
            is_malicious = label.upper() in NLP_POSITIVE_LABELS
            
            # Map to a 0.0 - 1.0 probability of being phishing
            phishing_prob = score if is_malicious else (1.0 - score)
            
            return {
                "status": "available",
                "phishing_probability": phishing_prob,
                "intent_label": label,
                "raw_score": score
            }
            
        except Exception as e:
            logger.error(f"NLP analysis failed: {e}")
            return {
                "status": "error",
                "phishing_probability": None, 
                "intent_label": "ERROR", 
                "raw_score": None
            }

# Export a singleton instance to be imported by routes
nlp_analyzer = PhishingNLPAnalyzer()
