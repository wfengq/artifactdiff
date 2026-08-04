"""Deterministic language profiling for contract text."""

from artifactdiff.contract.models import LanguageKind, LanguageProfile


def detect_language(text: str) -> LanguageProfile:
    """Classify text from its supported Han and ASCII Latin character counts."""
    han = sum("\u3400" <= char <= "\u9fff" for char in text)
    latin = sum(char.isascii() and char.isalpha() for char in text)
    total = han + latin
    if total == 0:
        kind = LanguageKind.OTHER
    elif han / total >= 0.2 and latin / total >= 0.2:
        kind = LanguageKind.BILINGUAL
    elif han > latin:
        kind = LanguageKind.CHINESE
    else:
        kind = LanguageKind.ENGLISH
    return LanguageProfile(kind=kind, han_characters=han, latin_letters=latin)
