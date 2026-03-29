#!/usr/bin/env bash
# ModScanner Evaluator
# Runs modscanner against the labeled test corpus and computes detection metrics.
# This file is READ-ONLY in the evolution loop — do not modify.
#
# Outputs a score to stdout in the format:
#   score: 0.85
#   precision: 0.90
#   recall: 0.82
#   f1: 0.86
#   false_positives: 1
#   false_negatives: 2
#   true_positives: 9
#   true_negatives: 4

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORPUS_DIR="$SCRIPT_DIR/corpus"
SCANNER="${SCRIPT_DIR}/../target/release/modscanner"

# Build first
echo "Building modscanner..." >&2
(cd "$SCRIPT_DIR/.." && cargo build --release 2>&1) >&2

if [ ! -x "$SCANNER" ]; then
    echo "ERROR: modscanner binary not found at $SCANNER" >&2
    echo "score: 0.0"
    exit 1
fi

# Counters
true_positives=0
false_negatives=0
true_negatives=0
false_positives=0
total_expected_rules_hit=0
total_expected_rules=0

echo "=== Evaluating malicious samples ===" >&2

# Test malicious samples (should produce findings)
for dir in "$CORPUS_DIR"/malicious/*/*; do
    [ -d "$dir" ] || continue
    sample_name="${dir#$CORPUS_DIR/}"

    # Run scanner in JSON mode
    output=$("$SCANNER" scan "$dir" --format json 2>/dev/null || true)

    # Extract findings count and rules
    findings_count=$(echo "$output" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(len(data.get('findings', [])))
except:
    print(0)
" 2>/dev/null || echo "0")

    found_rules=$(echo "$output" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    rules = [f.get('rule', '') for f in data.get('findings', [])]
    print(' '.join(rules))
except:
    print('')
" 2>/dev/null || echo "")

    max_severity=$(echo "$output" | python3 -c "
import sys, json
severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
try:
    data = json.load(sys.stdin)
    severities = [f.get('severity', 'info') for f in data.get('findings', [])]
    if severities:
        print(max(severities, key=lambda s: severity_order.get(s, 0)))
    else:
        print('none')
except:
    print('none')
" 2>/dev/null || echo "none")

    if [ "$findings_count" -gt 0 ]; then
        true_positives=$((true_positives + 1))
        echo "  TP: $sample_name ($findings_count findings, max=$max_severity)" >&2
    else
        false_negatives=$((false_negatives + 1))
        echo "  FN: $sample_name (NO findings - MISSED!)" >&2
    fi
done

echo "" >&2
echo "=== Evaluating benign samples ===" >&2

# Test benign samples (should NOT produce medium+ findings)
for dir in "$CORPUS_DIR"/benign/*/*; do
    [ -d "$dir" ] || continue
    sample_name="${dir#$CORPUS_DIR/}"

    output=$("$SCANNER" scan "$dir" --format json 2>/dev/null || true)

    # Check for medium+ severity findings (false positives)
    high_findings=$(echo "$output" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    high = [f for f in data.get('findings', []) if f.get('severity') in ('critical', 'high', 'medium')]
    print(len(high))
except:
    print(0)
" 2>/dev/null || echo "0")

    if [ "$high_findings" -eq 0 ]; then
        true_negatives=$((true_negatives + 1))
        echo "  TN: $sample_name (clean)" >&2
    else
        false_positives=$((false_positives + 1))
        echo "  FP: $sample_name ($high_findings false positive findings!)" >&2
    fi
done

# Compute metrics
total=$((true_positives + false_negatives + true_negatives + false_positives))
echo "" >&2
echo "=== Results ===" >&2
echo "  TP=$true_positives FN=$false_negatives TN=$true_negatives FP=$false_positives" >&2

# Precision = TP / (TP + FP)
if [ $((true_positives + false_positives)) -gt 0 ]; then
    precision=$(python3 -c "print(round($true_positives / ($true_positives + $false_positives), 4))")
else
    precision="1.0"
fi

# Recall = TP / (TP + FN)
if [ $((true_positives + false_negatives)) -gt 0 ]; then
    recall=$(python3 -c "print(round($true_positives / ($true_positives + $false_negatives), 4))")
else
    recall="1.0"
fi

# F1 = 2 * (precision * recall) / (precision + recall)
f1=$(python3 -c "
p, r = $precision, $recall
if p + r > 0:
    print(round(2 * p * r / (p + r), 4))
else:
    print(0.0)
")

# Composite score: weighted F1 (recall matters more for security)
# score = 0.3 * precision + 0.7 * recall
# Higher is better. 1.0 = perfect.
score=$(python3 -c "print(round(0.3 * $precision + 0.7 * $recall, 4))")

echo "" >&2
echo "=== Metrics ===" >&2

# Output metrics (stdout — this is what the evolution loop reads)
echo "score:            $score"
echo "precision:        $precision"
echo "recall:           $recall"
echo "f1:               $f1"
echo "true_positives:   $true_positives"
echo "false_negatives:  $false_negatives"
echo "true_negatives:   $true_negatives"
echo "false_positives:  $false_positives"
