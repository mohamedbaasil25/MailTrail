import logging
from transformers import pipeline

# Configure logging
logging.basicConfig(level=logging.INFO)
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
        try:
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
        if not self.classifier or not text.strip():
            return {
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
            # If using a specialized phishing model, LABEL_1 or 'phishing' implies malicious.
            # If using SST-2 (Sentiment), 'NEGATIVE' implies malicious (for testing purposes).
            is_malicious = label.upper() in ["PHISHING", "SPAM", "MALICIOUS", "NEGATIVE", "LABEL_1"]
            
            # Map to a 0.0 - 1.0 probability of being phishing
            phishing_prob = score if is_malicious else (1.0 - score)
            
            return {
                "phishing_probability": phishing_prob,
                "intent_label": label,
                "raw_score": score
            }
            
        except Exception as e:
            logger.error(f"NLP analysis failed: {e}")
            return {
                "phishing_probability": 0.0, 
                "intent_label": "ERROR", 
                "raw_score": 0.0
            }

# Export a singleton instance to be imported by routes
nlp_analyzer = PhishingNLPAnalyzer()
