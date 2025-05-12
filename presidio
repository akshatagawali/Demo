from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import AnonymizerConfig

class DynamicPIIAnalyzer:
    def __init__(self):
        self.registry = RecognizerRegistry()
        self.anonymizer = AnonymizerEngine()
        self.custom_recognizers = {}
        self.analyzer = None

    def _initialize_analyzer(self) -> None:
        if not self.analyzer:
            self.analyzer = AnalyzerEngine(registry=self.registry)

    def _add_recognizer(self, entity_name: str, regex_patterns: list, scores: list = None, class_name: str = None) -> None:
        if isinstance(regex_patterns, str):
            regex_patterns = [regex_patterns]
        if scores is None:
            scores = [1.0] * len(regex_patterns)
        patterns = [Pattern(name=entity_name, regex=regex, score=score) for regex, score in zip(regex_patterns, scores)]
        recognizer_class = type(class_name, (PatternRecognizer,), {})
        recognizer = recognizer_class(supported_entity=entity_name, patterns=patterns)
        self.registry.add_recognizer(recognizer)
        self.custom_recognizers[entity_name] = recognizer
        print(f"Added recognizer for: {entity_name} as {recognizer.__class__.__name__}")
        self._initialize_analyzer()

    def _remove_recognizer(self, entity_name: str) -> None:
        if entity_name in self.custom_recognizers:
            recognizer = self.custom_recognizers.pop(entity_name)
            self.registry.remove_recognizer(recognizer.__class__.__name__)
            print(f"Recognizer for '{entity_name}' removed successfully.")
        else:
            print(f"No custom recognizer found for entity '{entity_name}'")

    def add_custom_recognizer(self, entity_name: str, regex_patterns: list, scores: list = None, class_name: str = None) -> None:
        class_name = class_name or f"Custom{entity_name.title().replace('_', '')}Recognizer"
        self._add_recognizer(entity_name, regex_patterns, scores, class_name)

    def remove_custom_recognizer(self, entity_name: str) -> None:
        self._remove_recognizer(entity_name)

    def analyze_and_anonymize_pii(self, content: str, entities: list) -> str:
        try:
            if not isinstance(content, str):
                raise ValueError("Input content must be a string.")
            if not isinstance(entities, list):
                entities = [entities]

            self._initialize_analyzer()
            results = self.analyzer.analyze(text=content, entities=entities, language='en')

            # Custom anonymization format: just the lowercase entity name without < >
            anonymizers_config = {
                result.entity_type: AnonymizerConfig("replace", {"new_value": result.entity_type.lower()})
                for result in results
            }

            if results:
                return self.anonymizer.anonymize(
                    text=content,
                    analyzer_results=results,
                    anonymizers_config=anonymizers_config
                ).text
            return None
        except ValueError as ve:
            print(f"ValueError: {ve}")
            return None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

    def list_available_recognizers(self) -> None:
        print("\nAvailable Recognizers:\n")
        for recognizer in self.registry.recognizers:
            print(f"Recognizer: {recognizer.__class__.__name__}, Supported Entities: {recognizer.supported_entities}")
