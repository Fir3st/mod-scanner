# ModScanner Evolution Program

You are an autonomous agent improving a security scanner for game mods. Your goal is to **maximize the detection score** while minimizing false positives.

## Objective

Maximize the composite score output by `eval/evaluate.sh`:

```
score = 0.3 * precision + 0.7 * recall
```

**Higher is better. 1.0 = perfect.**

- **Recall** (weighted 70%): catch all malicious samples. Missing a real threat is worse than a false alarm.
- **Precision** (weighted 30%): avoid flagging clean mods. False positives erode user trust.

## Setup

1. You are on branch `evolve/<date>` (create if needed)
2. Run baseline evaluation:
   ```bash
   bash eval/evaluate.sh > eval/run.log 2>&1
   grep "^score:" eval/run.log
   ```
3. Record baseline in `eval/results.tsv`

## What You Can Modify

You may ONLY edit files in these locations:

- `crates/modscanner-core/src/engine/static_analysis.rs` — add/modify/tune regex detection rules
- `crates/modscanner-core/src/engine/binary.rs` — tune .NET string patterns, entropy thresholds, whitelists
- `crates/modscanner-core/src/engine/unicode.rs` — tune homoglyph detection, zero-width thresholds
- `crates/modscanner-core/src/engine/filetype.rs` — add extension/magic byte mappings
- `crates/modscanner-core/src/engine/polyglot.rs` — add format signatures, trailing data checks
- `crates/modscanner-core/src/scanner.rs` — tune skip extensions list

## What You Must NOT Modify

- `eval/evaluate.sh` — the evaluator is fixed (like a test suite)
- `eval/corpus/` — the test corpus is fixed
- `eval/expected.toml` — expected results are fixed
- `crates/modscanner-platform/` — platform trait interface
- `crates/modscanner-cli/` — CLI is not under evaluation

## Constraints

- Do not add new crate dependencies (edit only Rust source)
- Do not break compilation (`cargo build --release` must succeed)
- Do not break existing tests (`cargo test` must pass)
- Prefer simpler rules over complex ones for equal detection
- Each iteration should make ONE focused change (not bulk rewrites)

## Experiment Ideas

Here are directions to explore (pick one per iteration):

### Improving Recall (catching more threats)
- Add new regex patterns for suspicious API calls
- Lower entropy thresholds for packer detection
- Add new .NET string patterns (e.g., `Environment.GetEnvironmentVariable`, `File.ReadAllBytes`)
- Detect `dofile` with URL arguments in Lua
- Add patterns for PowerShell encoded commands (`-EncodedCommand`, `-e`)
- Detect Base64-encoded strings in Lua/Python (potential payload hiding)
- Add checks for suspicious file extensions in wrong directories (.exe in Textures/)

### Improving Precision (reducing false positives)
- Add more DLLs to the binary engine whitelist
- Refine regex patterns to be more specific (avoid matching comments, string literals)
- Increase minimum token length for mixed-script detection
- Skip known library directories (e.g., `Libs/`, `Libraries/`)

### New Detection Capabilities
- Detect suspiciously large files in unexpected locations
- Check for files with double extensions (e.g., `readme.txt.exe`)
- Detect encoded/encrypted config files
- Add CurseForge-specific patterns (manifest.json anomalies)

## The Loop

```
REPEAT FOREVER:
  1. Read current score from last line of eval/results.tsv
  2. Pick ONE improvement idea
  3. Edit the relevant engine file
  4. Verify: cargo build --release && cargo test
  5. If build fails: fix or revert, try again
  6. Run: bash eval/evaluate.sh > eval/run.log 2>&1
  7. Extract: score=$(grep "^score:" eval/run.log | awk '{print $2}')
  8. Record in eval/results.tsv:
     commit | score | precision | recall | tp | fn | tn | fp | status | description
  9. IF score IMPROVED (higher than previous best):
       git commit -m "improve: <description>"
       status = "keep"
     ELSE IF score SAME:
       Revert changes (git checkout -- .)
       status = "discard"
     ELSE (score DECREASED):
       Revert changes (git checkout -- .)
       status = "discard"
  10. NEVER STOP. Continue to next iteration.
```

## Output Format

Each line in `eval/results.tsv` (tab-separated):
```
commit	score	precision	recall	tp	fn	tn	fp	status	description
```

Example:
```
a1b2c3d	0.8500	0.9000	0.8182	9	2	4	1	keep	baseline
b2c3d4e	0.8800	0.9167	0.8462	10	1	4	1	keep	add dofile URL detection
c3d4e5f	0.8500	0.9000	0.8182	9	2	4	1	discard	lower entropy threshold (no improvement)
```

## Tips

- Run `eval/evaluate.sh` stderr to see which samples are TP/FN/TN/FP
- Focus on FN (false negatives) first — these are missed threats
- A single new regex pattern can flip a FN to a TP
- Check `eval/expected.toml` to understand what each sample should trigger
- If you add a pattern that catches a malicious sample but also flags a benign one, the net effect may be negative
- The evaluator rebuilds from source each time, so your Rust changes take effect immediately
