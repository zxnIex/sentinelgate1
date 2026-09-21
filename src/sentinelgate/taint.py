from collections.abc import Iterable

from sentinelgate.models import DataClassification, TrustLevel

CLASSIFICATION_RANK = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.RESTRICTED: 3,
}

TRUST_RANK = {
    TrustLevel.TRUSTED: 0,
    TrustLevel.MIXED: 1,
    TrustLevel.UNTRUSTED: 2,
}


def highest_classification(
    values: Iterable[DataClassification],
) -> DataClassification:
    return max(values, key=CLASSIFICATION_RANK.get, default=DataClassification.PUBLIC)


def least_trusted(values: Iterable[TrustLevel]) -> TrustLevel:
    return max(values, key=TRUST_RANK.get, default=TrustLevel.TRUSTED)


def classification_exceeds(
    actual: DataClassification, maximum: DataClassification
) -> bool:
    return CLASSIFICATION_RANK[actual] > CLASSIFICATION_RANK[maximum]
