"""PhishGuard URL feature extractor.

The extractor returns the current PhishGuard feature set only. Removed features
(e.g. IsTrancoTop10000, IsIPv6, user-info features, and old encoding counters)
are intentionally not generated.

Expected input CSV columns:
    URLs   : raw URL string
    Labels : optional target label (0=phishing, 1=legitimate)

Usage:
    python feature_extractor.py input.csv output.csv
    python feature_extractor.py input.csv output.csv --chunk-size 5000

The output contains valid extracted rows. Rows that fail parsing are written to
<output_stem>_failed.csv rather than being silently filled with missing values.
"""

from __future__ import annotations

import argparse
import ipaddress
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

import numpy as np
import pandas as pd

try:
    import tldextract
except ImportError as exc:  # pragma: no cover - depends on the user's environment
    raise ImportError(
        "The feature extractor requires 'tldextract'. Install it with: "
        "pip install tldextract"
    ) from exc


# Avoid network requests for the Public Suffix List while extracting features.
# tldextract uses its bundled suffix list when suffix_list_urls=None.
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)

# Numeric model features in the exact order requested for the current dataset.
FEATURE_COLUMNS: list[str] = [
    "URLLength",
    "HasScheme",
    "IsHTTPS",
    "IsHTTP",
    "HasWWW",
    "HasPort",
    "PortNumber",
    "HasPath",
    "HasQuery",
    "HasFragment",
    "HostLength",
    "DomainLength",
    "TLDLength",
    "SubdomainCount",
    "DomainTokenCount",
    "HostTokenCount",
    "DomainDigitCount",
    "DomainLetterCount",
    "DomainHyphenCount",
    "DomainDotCount",
    "HasDigitInDomain",
    "HasHyphenInDomain",
    "DomainDigitRatio",
    "DomainLetterRatio",
    "DomainSpecialCharRatio",
    "DomainEntropy",
    "HostEntropy",
    "IsIPAddress",
    "SubdomainLength",
    "MaxSubdomainLength",
    "AvgSubdomainLength",
    "SubdomainDigitCount",
    "SubdomainLetterCount",
    "SubdomainHyphenCount",
    "SubdomainDotCount",
    "SubdomainDigitRatio",
    "SubdomainLetterRatio",
    "SubdomainEntropy",
    "HasDigitInSubdomain",
    "HasHyphenInSubdomain",
    "PathLength",
    "PathDepth",
    "EmptyPathSegmentCount",
    "PathDigitCount",
    "PathLetterCount",
    "PathSpecialCharCount",
    "PathHyphenCount",
    "PathUnderscoreCount",
    "PathDotCount",
    "PathSlashCount",
    "PathDigitRatio",
    "PathLetterRatio",
    "PathSpecialCharRatio",
    "PathEntropy",
    "PathTokenCount",
    "LongestPathSegment",
    "AvgPathSegmentLength",
    "QueryLength",
    "QueryParameterCount",
    "QueryValueCount",
    "QueryDigitCount",
    "QueryLetterCount",
    "QuerySpecialCharCount",
    "QueryDigitRatio",
    "QueryLetterRatio",
    "QuerySpecialCharRatio",
    "QueryEntropy",
    "QueryTokenCount",
    "LongestQueryKey",
    "LongestQueryValue",
    "AvgQueryValueLength",
    "QuestionMarkCount",
    "EqualCount",
    "AmpersandCount",
    "PercentCount",
    "PlusCount",
    "SemicolonCount",
    "ColonCount",
    "AtCount",
    "HashCount",
    "TotalDigitCount",
    "TotalLetterCount",
    "UppercaseCount",
    "LowercaseCount",
    "SpecialCharCount",
    "DigitRatio",
    "LetterRatio",
    "UppercaseRatio",
    "SpecialCharRatio",
    "URLEntropy",
    "TotalTokenCount",
    "UniqueTokenCount",
    "AvgTokenLength",
    "MaxTokenLength",
    "MinTokenLength",
    "NumericTokenCount",
    "AlphanumericTokenCount",
    "HasPercentEncoding",
    "PercentEncodedCount",
    "PercentEncodedRatio",
    "HexSequenceCount",
    "DoubleSlashCount",
    "RepeatedDelimiterCount",
    "ConsecutiveHyphenCount",
    "ConsecutiveDigitRunCount",
    "MaxConsecutiveDigitCount",
    "MaxRepeatedCharacterRun",
    "IsNonStandardPort",
    "FragmentLength",
    "FragmentTokenCount",
    "FragmentDigitCount",
    "FragmentSpecialCharCount",
    "FragmentEntropy",
    "DomainToURLRatio",
    "PathToURLRatio",
    "QueryToURLRatio",
    "SubdomainToHostRatio",
    "HasAtSymbol",
    "HasLongNumericToken",
    "HasLongAlphanumericToken",
    "HasEncodedPath",
    "HasEncodedQuery",
]

# Includes the raw URL and target label columns when present in dataset CSVs.
DATASET_COLUMNS: list[str] = ["URLs", "FullDomain", *FEATURE_COLUMNS, "Labels"]

_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_TOKEN_SPLIT_RE = re.compile(r"[./?&=_%+\\\-:@;,#]+")
_PERCENT_ENCODING_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_HEX_SEQUENCE_RE = re.compile(r"(?:0x|%)[0-9A-Fa-f]+", re.IGNORECASE)
_REPEAT_DELIMITER_RE = re.compile(r"([./?&=_+\-:;])\1+")
_CONSECUTIVE_DOT_RE = re.compile(r"\.{2,}")
_CONSECUTIVE_HYPHEN_RE = re.compile(r"-{2,}")
_DIGIT_RUN_RE = re.compile(r"\d+")
_REPEATED_CHAR_RE = re.compile(r"(.)\1+")


def safe_ratio(numerator: float, denominator: float) -> float:
    """Return numerator / denominator, using 0.0 for a zero denominator."""
    if denominator == 0:
        return 0.0
    return float(numerator) / float(denominator)


def entropy(value: str) -> float:
    """Calculate Shannon entropy (base 2) for a string."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return float(-sum((count / length) * math.log2(count / length)
                      for count in counts.values()))


def count_digits(value: str) -> int:
    return sum(char.isdigit() for char in value)


def count_letters(value: str) -> int:
    return sum(char.isalpha() for char in value)


def count_special_chars(value: str) -> int:
    """Count characters that are neither alphabetic nor numeric."""
    return sum(not char.isalnum() for char in value)


def tokenise(value: str) -> list[str]:
    """Split a component into non-empty tokens using URL delimiters."""
    if not value:
        return []
    return [token for token in _TOKEN_SPLIT_RE.split(value) if token]


def _ip_version(host: str) -> int | None:
    """Return IP version (4 or 6), or None when host is not an IP address."""
    try:
        return ipaddress.ip_address(host).version
    except ValueError:
        return None


def _split_url(url: str) -> dict[str, Any]:
    """Parse schemeful, schemeless, and protocol-relative URL strings safely."""
    original = url.strip()
    if not original:
        raise ValueError("URL cannot be empty or whitespace-only.")

    has_scheme = bool(_SCHEME_RE.match(original))
    if has_scheme:
        parsed = urlsplit(original)
        scheme = parsed.scheme.lower()
    else:
        # Support protocol-relative URLs and ordinary schemeless hostnames.
        candidate = original if original.startswith("//") else f"//{original}"
        parsed = urlsplit(candidate)
        scheme = ""

    # Accessing .port can raise ValueError for malformed or out-of-range ports.
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in URL: {exc}") from exc

    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        raise ValueError("URL does not contain a parseable hostname.")

    ip_version = _ip_version(host)
    if ip_version is not None:
        # IP addresses are represented directly as Domain for these features.
        domain = host
        subdomain = ""
        tld = ""
        full_domain = host
    else:
        extracted = _TLD_EXTRACTOR(host)
        domain = extracted.domain or host
        subdomain = extracted.subdomain or ""
        tld = extracted.suffix or ""
        # Preserve the previous FullDomain behaviour: registrable domain plus suffix,
        # excluding subdomains. Unknown/localhost-like hosts fall back to host.
        full_domain = f"{domain}.{tld}" if tld else host

    return {
        "original": original,
        "parsed": parsed,
        "scheme": scheme,
        "has_scheme": has_scheme,
        "host": host,
        "domain": domain,
        "subdomain": subdomain,
        "tld": tld,
        "port": port,
        "path": parsed.path or "",
        "query": parsed.query or "",
        "fragment": parsed.fragment or "",
        "ip_version": ip_version,
        "full_domain": full_domain,
    }


def extract_url_features(url: str) -> dict[str, Any]:
    """Extract exactly the current numeric feature set for one URL.

    The return value also includes ``FullDomain``. The raw URL (``URLs``) and
    label (``Labels``) are added by the CSV-processing function.
    """
    if not isinstance(url, str):
        raise TypeError("URL must be a string.")

    parts = _split_url(url)
    original = parts["original"]
    scheme = parts["scheme"]
    host = parts["host"]
    domain = parts["domain"]
    subdomain = parts["subdomain"]
    tld = parts["tld"]
    path = parts["path"]
    query = parts["query"]
    fragment = parts["fragment"]
    port = parts["port"]

    domain_tokens = tokenise(domain)
    host_tokens = tokenise(host)
    subdomain_parts = [part for part in subdomain.split(".") if part]
    path_segments = [segment for segment in path.split("/") if segment]

    # Query parameters retain empty entries (e.g. x=1&&y=2) because they are
    # part of the supplied URL structure. Values are counted only for key=value.
    query_params = query.split("&") if query else []
    query_keys: list[str] = []
    query_values: list[str] = []
    for parameter in query_params:
        if "=" in parameter:
            key, value = parameter.split("=", 1)
            query_keys.append(key)
            query_values.append(value)
        else:
            query_keys.append(parameter)

    domain_digits = count_digits(domain)
    domain_letters = count_letters(domain)
    subdomain_digits = count_digits(subdomain)
    subdomain_letters = count_letters(subdomain)
    path_digits = count_digits(path)
    path_letters = count_letters(path)
    query_digits = count_digits(query)
    query_letters = count_letters(query)
    total_digits = count_digits(original)
    total_letters = count_letters(original)
    total_special = count_special_chars(original)

    tokens = tokenise(original)
    token_lengths = [len(token) for token in tokens]
    digit_runs = _DIGIT_RUN_RE.findall(original)
    repeated_character_runs = [m.group(0) for m in _REPEATED_CHAR_RE.finditer(original)]
    percent_matches = _PERCENT_ENCODING_RE.findall(original)

    path_digits_in_runs = _DIGIT_RUN_RE.findall(path)
    path_special_count = count_special_chars(path)
    query_special_count = count_special_chars(query)

    # Empty internal path segments are counted, but leading/trailing separators
    # are not treated as empty internal segments.
    path_parts = path.split("/")
    empty_path_segments = sum(segment == "" for segment in path_parts[1:-1])

    features: dict[str, Any] = {
        "FullDomain": parts["full_domain"],
        "URLLength": len(original),
        "HasScheme": int(parts["has_scheme"]),
        "IsHTTPS": int(scheme == "https"),
        "IsHTTP": int(scheme == "http"),
        "HasWWW": int(host.startswith("www.")),
        "HasPort": int(port is not None),
        "PortNumber": int(port) if port is not None else 0,
        "HasPath": int(bool(path)),
        "HasQuery": int(bool(query)),
        "HasFragment": int(bool(fragment)),
        "HostLength": len(host),
        "DomainLength": len(domain),
        "TLDLength": len(tld),
        "SubdomainCount": len(subdomain_parts),
        "DomainTokenCount": len(domain_tokens),
        "HostTokenCount": len(host_tokens),
        "DomainDigitCount": domain_digits,
        "DomainLetterCount": domain_letters,
        "DomainHyphenCount": domain.count("-"),
        "DomainDotCount": domain.count("."),
        "HasDigitInDomain": int(domain_digits > 0),
        "HasHyphenInDomain": int("-" in domain),
        "DomainDigitRatio": safe_ratio(domain_digits, len(domain)),
        "DomainLetterRatio": safe_ratio(domain_letters, len(domain)),
        "DomainSpecialCharRatio": safe_ratio(count_special_chars(domain), len(domain)),
        "DomainEntropy": entropy(domain),
        "HostEntropy": entropy(host),
        "IsIPAddress": int(parts["ip_version"] is not None),
        "SubdomainLength": len(subdomain),
        "MaxSubdomainLength": max((len(part) for part in subdomain_parts), default=0),
        "AvgSubdomainLength": float(np.mean([len(part) for part in subdomain_parts])) if subdomain_parts else 0.0,
        "SubdomainDigitCount": subdomain_digits,
        "SubdomainLetterCount": subdomain_letters,
        "SubdomainHyphenCount": subdomain.count("-"),
        "SubdomainDotCount": subdomain.count("."),
        "SubdomainDigitRatio": safe_ratio(subdomain_digits, len(subdomain)),
        "SubdomainLetterRatio": safe_ratio(subdomain_letters, len(subdomain)),
        "SubdomainEntropy": entropy(subdomain),
        "HasDigitInSubdomain": int(subdomain_digits > 0),
        "HasHyphenInSubdomain": int("-" in subdomain),
        "PathLength": len(path),
        "PathDepth": len(path_segments),
        "EmptyPathSegmentCount": empty_path_segments,
        "PathDigitCount": path_digits,
        "PathLetterCount": path_letters,
        "PathSpecialCharCount": path_special_count,
        "PathHyphenCount": path.count("-"),
        "PathUnderscoreCount": path.count("_"),
        "PathDotCount": path.count("."),
        "PathSlashCount": path.count("/"),
        "PathDigitRatio": safe_ratio(path_digits, len(path)),
        "PathLetterRatio": safe_ratio(path_letters, len(path)),
        "PathSpecialCharRatio": safe_ratio(path_special_count, len(path)),
        "PathEntropy": entropy(path),
        "PathTokenCount": len(tokenise(path)),
        "LongestPathSegment": max((len(segment) for segment in path_segments), default=0),
        "AvgPathSegmentLength": float(np.mean([len(segment) for segment in path_segments])) if path_segments else 0.0,
        "QueryLength": len(query),
        "QueryParameterCount": len(query_params),
        "QueryValueCount": len(query_values),
        "QueryDigitCount": query_digits,
        "QueryLetterCount": query_letters,
        "QuerySpecialCharCount": query_special_count,
        "QueryDigitRatio": safe_ratio(query_digits, len(query)),
        "QueryLetterRatio": safe_ratio(query_letters, len(query)),
        "QuerySpecialCharRatio": safe_ratio(query_special_count, len(query)),
        "QueryEntropy": entropy(query),
        "QueryTokenCount": len(tokenise(query)),
        "LongestQueryKey": max((len(key) for key in query_keys), default=0),
        "LongestQueryValue": max((len(value) for value in query_values), default=0),
        "AvgQueryValueLength": float(np.mean([len(value) for value in query_values])) if query_values else 0.0,
        "QuestionMarkCount": original.count("?"),
        "EqualCount": original.count("="),
        "AmpersandCount": original.count("&"),
        "PercentCount": original.count("%"),
        "PlusCount": original.count("+"),
        "SemicolonCount": original.count(";"),
        "ColonCount": original.count(":"),
        "AtCount": original.count("@"),
        "HashCount": original.count("#"),
        "TotalDigitCount": total_digits,
        "TotalLetterCount": total_letters,
        "UppercaseCount": sum(char.isupper() for char in original),
        "LowercaseCount": sum(char.islower() for char in original),
        "SpecialCharCount": total_special,
        "DigitRatio": safe_ratio(total_digits, len(original)),
        "LetterRatio": safe_ratio(total_letters, len(original)),
        "UppercaseRatio": safe_ratio(sum(char.isupper() for char in original), len(original)),
        "SpecialCharRatio": safe_ratio(total_special, len(original)),
        "URLEntropy": entropy(original),
        "TotalTokenCount": len(tokens),
        "UniqueTokenCount": len(set(tokens)),
        "AvgTokenLength": float(np.mean(token_lengths)) if token_lengths else 0.0,
        "MaxTokenLength": max(token_lengths, default=0),
        "MinTokenLength": min(token_lengths, default=0),
        "NumericTokenCount": sum(token.isdigit() for token in tokens),
        "AlphanumericTokenCount": sum(token.isalnum() and not token.isdigit() for token in tokens),
        "HasPercentEncoding": int(bool(percent_matches)),
        "PercentEncodedCount": len(percent_matches),
        "PercentEncodedRatio": safe_ratio(len(percent_matches), len(original)),
        "HexSequenceCount": len(_HEX_SEQUENCE_RE.findall(original)),
        "DoubleSlashCount": original.split("://", 1)[1].count("//") if "://" in original else original.count("//"),
        "RepeatedDelimiterCount": len(_REPEAT_DELIMITER_RE.findall(original.split("://", 1)[1] if "://" in original else original)),
        "ConsecutiveHyphenCount": len(_CONSECUTIVE_HYPHEN_RE.findall(original)),
        "ConsecutiveDigitRunCount": len(digit_runs),
        "MaxConsecutiveDigitCount": max((len(run) for run in digit_runs), default=0),
        "MaxRepeatedCharacterRun": max((len(run) for run in repeated_character_runs), default=1),
        "IsNonStandardPort": int(port is not None and not (
            (scheme == "http" and port == 80) or
            (scheme == "https" and port == 443)
        )),
        "FragmentLength": len(fragment),
        "FragmentTokenCount": len(tokenise(fragment)),
        "FragmentDigitCount": count_digits(fragment),
        "FragmentSpecialCharCount": count_special_chars(fragment),
        "FragmentEntropy": entropy(fragment),
        "DomainToURLRatio": safe_ratio(len(domain), len(original)),
        "PathToURLRatio": safe_ratio(len(path), len(original)),
        "QueryToURLRatio": safe_ratio(len(query), len(original)),
        "SubdomainToHostRatio": safe_ratio(len(subdomain), len(host)),
        "HasAtSymbol": int("@" in original),
        "HasLongNumericToken": int(any(token.isdigit() and len(token) >= 6 for token in tokens)),
        "HasLongAlphanumericToken": int(any(token.isalnum() and not token.isdigit() and len(token) >= 15 for token in tokens)),
        "HasEncodedPath": int(bool(_PERCENT_ENCODING_RE.search(path))),
        "HasEncodedQuery": int(bool(_PERCENT_ENCODING_RE.search(query))),
    }

    # Fail loudly when a future edit forgets to produce a requested feature or
    # accidentally brings back a removed feature.
    missing = [column for column in FEATURE_COLUMNS if column not in features]
    extra = [column for column in features if column != "FullDomain" and column not in FEATURE_COLUMNS]
    if missing or extra:
        raise RuntimeError(f"Feature schema mismatch. Missing={missing}; extra={extra}")

    # Keep feature order stable, which is essential for model training/inference.
    return {"FullDomain": features["FullDomain"], **{col: features[col] for col in FEATURE_COLUMNS}}


def extract_features_from_urls(urls: Iterable[str]) -> pd.DataFrame:
    """Return FullDomain and numeric feature columns for an iterable of URLs.

    Invalid URLs raise their parsing errors in this helper; use the CSV helper
    below to get a failed-row report when processing a dataset.
    """
    rows = [extract_url_features(url) for url in urls]
    return pd.DataFrame(rows, columns=["FullDomain", *FEATURE_COLUMNS])


def extract_features_from_csv(
    input_csv: str | Path,
    output_csv: str | Path,
    chunk_size: int = 5000,
    url_column: str = "URLs",
    label_column: str = "Labels",
) -> dict[str, int]:
    """Extract features from a large CSV in chunks and write output incrementally.

    A companion *_failed.csv contains rows that could not be parsed. Valid rows
    are written in the exact order: URLs, FullDomain, numeric features, Labels
    (if the input contains the label column).
    """
    input_path = Path(input_csv)
    output_path = Path(output_csv)
    if chunk_size < 1:
        raise ValueError("chunk_size must be >= 1")
    if not input_path.exists():
        raise FileNotFoundError(f"Input CSV not found: {input_path}")
    if input_path.resolve() == output_path.resolve():
        raise ValueError("Input and output CSV paths must be different.")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    failed_path = output_path.with_name(f"{output_path.stem}_failed.csv")
    for path in (output_path, failed_path):
        if path.exists():
            path.unlink()

    total_rows = 0
    successful_rows = 0
    failed_rows = 0
    first_valid_chunk = True
    first_failed_chunk = True

    reader = pd.read_csv(
        input_path,
        chunksize=chunk_size,
        dtype={url_column: "string"},
        keep_default_na=False,
    )

    try:
        for chunk in reader:
            if url_column not in chunk.columns:
                raise ValueError(
                    f"Input CSV must contain '{url_column}'. Found: {list(chunk.columns)}"
                )

            has_labels = label_column in chunk.columns
            valid_records: list[dict[str, Any]] = []
            failed_records: list[dict[str, Any]] = []

            # itertuples is materially faster than iterrows on a large dataset.
            selected_columns = [url_column] + ([label_column] if has_labels else [])
            for values in chunk[selected_columns].itertuples(index=False, name=None):
                raw_url = values[0]
                label_value = values[1] if has_labels else None
                try:
                    features = extract_url_features(str(raw_url))
                    record: dict[str, Any] = {
                        "URLs": str(raw_url).strip(),
                        "FullDomain": features["FullDomain"],
                    }
                    record.update({col: features[col] for col in FEATURE_COLUMNS})
                    if has_labels:
                        record[label_column] = label_value
                    valid_records.append(record)
                except (ValueError, TypeError, UnicodeError) as exc:
                    failed_record = {
                        "URLs": raw_url,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                    if has_labels:
                        failed_record[label_column] = label_value
                    failed_records.append(failed_record)

            if valid_records:
                valid_df = pd.DataFrame(valid_records)
                output_columns = ["URLs", "FullDomain", *FEATURE_COLUMNS]
                if has_labels:
                    output_columns.append(label_column)
                valid_df = valid_df.reindex(columns=output_columns)
                valid_df.to_csv(
                    output_path,
                    mode="w" if first_valid_chunk else "a",
                    header=first_valid_chunk,
                    index=False,
                )
                first_valid_chunk = False
                successful_rows += len(valid_df)

            if failed_records:
                failed_df = pd.DataFrame(failed_records)
                failed_df.to_csv(
                    failed_path,
                    mode="w" if first_failed_chunk else "a",
                    header=first_failed_chunk,
                    index=False,
                )
                first_failed_chunk = False
                failed_rows += len(failed_df)

            total_rows += len(chunk)
            print(
                f"Processed {total_rows:,} rows | "
                f"valid: {successful_rows:,} | failed: {failed_rows:,}"
            )
    finally:
        reader.close()

    print("\nFEATURE EXTRACTION FINISHED")
    print(f"Input rows    : {total_rows:,}")
    print(f"Valid rows    : {successful_rows:,}")
    print(f"Failed rows   : {failed_rows:,}")
    print(f"Output        : {output_path}")
    if failed_rows:
        print(f"Failed report : {failed_path}")

    return {
        "total_rows": total_rows,
        "successful_rows": successful_rows,
        "failed_rows": failed_rows,
    }


def _run_smoke_tests() -> None:
    """Quick schema and behaviour checks for common URL shapes."""
    samples = [
        "https://www.example.com/login?user=alice&id=123#section",
        "http://example.org:8080/a/b-c_1",
        "example.com/path?x=1&y=",
        "https://192.0.2.1/a%20b",
    ]
    for sample in samples:
        output = extract_url_features(sample)
        assert list(output.keys()) == ["FullDomain", *FEATURE_COLUMNS]
        assert len(output) == len(FEATURE_COLUMNS) + 1
        assert all(value is not None for value in output.values())
    print(f"Smoke tests passed. Numeric features: {len(FEATURE_COLUMNS)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract PhishGuard URL features.")
    parser.add_argument("input_csv", nargs="?", help="Input CSV with an URLs column")
    parser.add_argument("output_csv", nargs="?", help="Destination feature CSV")
    parser.add_argument("--chunk-size", type=int, default=5000, help="Rows per batch (default: 5000)")
    parser.add_argument("--self-test", action="store_true", help="Run a few extractor smoke tests")
    args = parser.parse_args()

    if args.self_test:
        _run_smoke_tests()
        return
    if not args.input_csv or not args.output_csv:
        parser.error("input_csv and output_csv are required unless --self-test is used")

    extract_features_from_csv(
        input_csv=args.input_csv,
        output_csv=args.output_csv,
        chunk_size=args.chunk_size,
    )


if __name__ == "__main__":
    main()
