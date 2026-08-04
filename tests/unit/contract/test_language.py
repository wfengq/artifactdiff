from artifactdiff.contract.language import detect_language
from artifactdiff.contract.models import LanguageKind


def test_detect_language_distinguishes_chinese_english_and_bilingual() -> None:
    assert detect_language("第四条 付款条件").kind is LanguageKind.CHINESE
    assert detect_language("Section 4 Payment Terms").kind is LanguageKind.ENGLISH
    assert detect_language("第四条 Payment Terms 付款条件").kind is LanguageKind.BILINGUAL


def test_detect_language_counts_only_supported_characters() -> None:
    profile = detect_language("第四条 123 !")

    assert profile.model_dump(mode="json") == {
        "kind": "zh",
        "han_characters": 3,
        "latin_letters": 0,
    }


def test_detect_language_returns_other_when_no_supported_characters() -> None:
    assert detect_language("123 !? ").kind is LanguageKind.OTHER
