"""Utility functions for entropy calculation and file hashing."""

import hashlib
import math
from collections import Counter
from typing import Dict


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of byte data.

    Args:
        data: Bytes to analyze

    Returns:
        Entropy value between 0.0 (uniform) and 8.0 (random)

    Interpretation:
        < 5.0: Plain text, low compression
        5.0 - 7.0: Normal compiled code
        > 7.0: High compression/encryption (potentially suspicious)
    """
    if not data:
        return 0.0

    byte_counts = Counter(data)
    entropy = 0.0

    for count in byte_counts.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)

    return entropy


def calculate_hashes(file_path: str) -> Dict[str, str]:
    """
    Calculate MD5, SHA1, and SHA256 hashes of a file.

    Args:
        file_path: Path to the file

    Returns:
        Dictionary with hash algorithm names as keys and hex digests as values
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest(),
    }
