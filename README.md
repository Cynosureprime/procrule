# procrule

A high-performance, multi-threaded rule processor for wordlists.  procrule
applies hashcat/JtR-compatible rules to wordlists, generating candidate
passwords or matching against known targets.  Only candidates that differ
from the original input word are emitted — if a rule produces no change
(e.g., `l` applied to an already-lowercase word), the word is suppressed.

## Features

- Multi-threaded rule application with configurable thread count
- Supports multiple rule files in a single invocation
- Match mode: compare generated candidates against a target word list
- Automatic deduplication of output via Bloom filter and Judy arrays
- Handles `$HEX[]` encoded words transparently
- Base64 conversion support via rules
- Rule match statistics and per-rule hit tracking
- Benchmark mode for measuring rule processing throughput
- Streaming I/O — reads wordlists in chunks for constant memory usage
- Supports stdin/stdout as input/output

## Building

Requires [Judy arrays](http://judy.sourceforge.net/) library
(`libJudy-dev` on Debian/Ubuntu, `judy` via MacPorts or Homebrew).

```
make
```

## Usage

```
procrule [options] wordlist
```

### Options

| Option | Description |
|--------|-------------|
| `-r file` | Rule file to apply (may be specified multiple times) |
| `-m file` | Match file — only output candidates found in this file (may be specified multiple times) |
| `-o file` | Redirect output to file (default: stdout) |
| `-l file` | Line match log: writes `word:rule:candidate` for each match |
| `-s file` | Output rule match statistics to file |
| `-t num` | Maximum number of threads |
| `-M size` | Set memory cache size (supports K/M/G suffixes) |
| `-p num` | Set hash prime for deduplication |
| `-B count` | Benchmark mode — apply rules N times and report throughput |
| `-u` | Interpret rules in UTF-32 rather than over bytes — see [UTF-32 Rules](#utf-32-rules) |
| `-L locale` | Pin the locale for case mappings with more than one right answer (`tr`, `az`, `c`, `root`); implies `-u` |
| `-x` | Disable `$HEX[]` encoding on output |
| `-v` | Verbose mode (repeat for more detail) |

### Examples

Generate all candidates from a wordlist with a rule file (only words
actually changed by a rule appear in the output):

```
procrule -r rules.txt wordlist.txt > candidates.txt
```

Find which words in a wordlist can produce known passwords:

```
procrule -r rules.txt -m passwords.txt wordlist.txt
```

Apply multiple rule files with match logging:

```
procrule -r best64.rule -r toggles.rule -m targets.txt -l matches.log wordlist.txt
```

Benchmark rule processing throughput:

```
procrule -r rules.txt -B 100 wordlist.txt
```

## Rule Reference

procrule implements hashcat/JtR-compatible rules.  Positions are encoded as
`0`–`9` for 0–9 and `A`–`Z` for 10–35.

### Case Rules

| Rule | Description |
|------|-------------|
| `l` | Lowercase all characters |
| `u` | Uppercase all characters |
| `c` | Capitalize first letter, lowercase rest |
| `C` | Lowercase first letter, uppercase rest |
| `t` | Toggle case of all characters |
| `TN` | Toggle case at position N |
| `E` | Title case (capitalize after each space) |
| `eX` | Title case with custom separator X |

### Insertion and Deletion

| Rule | Description |
|------|-------------|
| `$X` | Append character X |
| `^X` | Prepend character X |
| `[` | Delete first character |
| `]` | Delete last character |
| `DN` | Delete character at position N |
| `iNX` | Insert character X at position N |
| `oNX` | Overwrite character at position N with X |
| `'N` | Truncate word at length N |
| `xNM` | Extract M characters starting at position N |
| `ONM` | Delete M characters starting at position N |

### Duplication

| Rule | Description |
|------|-------------|
| `d` | Duplicate entire word (`pass` → `passpass`) |
| `f` | Reflect — append reversed copy (`abc` → `abccba`) |
| `pN` | Append duplicated word N times |
| `q` | Duplicate every character (`abc` → `aabbcc`) |
| `zN` | Duplicate first character N times |
| `ZN` | Duplicate last character N times |
| `yN` | Duplicate first N characters, prepend them |
| `YN` | Duplicate last N characters, append them |

### Rearrangement

| Rule | Description |
|------|-------------|
| `r` | Reverse the word |
| `{` | Rotate left — move first character to end |
| `}` | Rotate right — move last character to front |
| `k` | Swap first two characters |
| `K` | Swap last two characters |
| `*NM` | Swap characters at positions N and M |

### Character Manipulation

| Rule | Description |
|------|-------------|
| `sXY` | Replace all occurrences of X with Y |
| `@X` | Purge — remove all occurrences of X |
| `+N` | Increment ASCII value at position N |
| `-N` | Decrement ASCII value at position N |
| `.N` | Replace character at N with character at N+1 |
| `,N` | Replace character at N with character at N-1 |
| `LN` | Bit-shift left character at position N |
| `RN` | Bit-shift right character at position N |
| `vNX` | Insert character X every N characters |

### Encoding

| Rule | Description |
|------|-------------|
| Ctrl-B (`\x02`) | Base64 encode the word |
| `h` | Hex-encode each byte (lowercase) |
| `H` | Hex-encode each byte (uppercase) |

### Memory

| Rule | Description |
|------|-------------|
| `M` | Memorize current word state |
| `4` | Append memorized word |
| `6` | Prepend memorized word |
| `Q` | Reject word if it equals the memorized word |
| `XNMI` | Insert M characters from memorized word at offset N, at position I |

### Rejection and Control

| Rule | Description |
|------|-------------|
| `<N` | Reject if word length is less than N |
| `>N` | Reject if word length is greater than N |
| `_N` | Reject unless original word length equals N |
| `!X` | Reject if word contains character X |
| `/X` | Reject if word does not contain character X |
| `(X` | Reject if first character is not X |
| `)X` | Reject if last character is not X |
| `:` | No-op — pass word through unchanged |
| `#` | Stop processing remaining rules for this word |

### Base64 Output

procrule supports a base64 encoding rule via the Control-B (`0x02`)
character.  When this rule is encountered, the current candidate is
base64-encoded in place.  To create a rule file that base64-encodes
every word, write a single Control-B as the rule:

```
printf '\x02\n' > b64.rule
procrule -r b64.rule wordlist.txt
```

```
password  →  cGFzc3dvcmQ=
hello     →  aGVsbG8=
```

This can be combined with other rules.  For example, to append "123"
and then base64-encode the result:

```
printf '$1$2$3\x02\n' > append123-b64.rule
procrule -r append123-b64.rule wordlist.txt
```

```
password  →  cGFzc3dvcmQxMjM=
hello     →  aGVsbG8xMjM=
```

To base64-encode and strip the trailing `=` padding, combine Control-B
with the `@=` purge rule:

```
printf '\x02@=\n' > b64-nopad.rule
procrule -r b64-nopad.rule wordlist.txt
```

```
password  →  cGFzc3dvcmQ
hello     →  aGVsbG8
```

## UTF-32 Rules

By default a rule operates on **bytes**.  That is fine for ASCII and it is
what every hashcat-compatible rule file assumes, but it mangles anything
else: reversing a word splits multi-byte characters in half, truncating one
cuts a character down the middle, and an operand can only ever be a single
byte, so there is no way to write a rule that appends an emoji.

`-u` runs the whole pipeline in UTF-32.  Input is decoded from UTF-8 to
codepoints, the rule is interpreted against codepoints and grapheme
clusters, and the result is encoded back to UTF-8.  Without `-u` nothing
changes — the byte engine and its exact output are untouched.

Full semantics are in `rules32(7)`.  The short version:

- **A position or a length counts grapheme clusters**, not codepoints or
  bytes.  `'3` keeps three characters as a reader counts them.
- **Marks travel with their base.**  Arabic harakat, Hebrew niqqud, Thai
  vowel signs, Devanagari matras, a decomposed accent, a Yoruba vowel
  carrying both a dot below and a tone mark.
- **Emoji stay whole.**  Joiner sequences, skin-tone modifiers, flags and
  keycaps are each one character.
- **Operands may be quoted strings.**  `$"123"` is one operation, and
  `$"🔥"` is possible at all — the byte engine refuses it, because its
  operand is one byte and an emoji is four.
- **Case mapping is real.**  The eszett uppercases to `SS`, ligatures
  expand, Greek final sigma is positional, and the Turkish dotted/dotless
  I is handled by `-L`.

### Appending and substituting

```
printf '$"🔥"\n' > emoji.rule
procrule -u -r emoji.rule wordlist.txt
```

```
password    →  password🔥
summer2024  →  summer2024🔥
```

A quoted operand is a string, so a whole suffix is one rule rather than a
chain of single-character appends:

```
rule: c $"2024!"          password → Password2024!    hunter → Hunter2024!
rule: i4"-"               password → pass-word
rule: @"ss"               password → paword
rule: v3"-"               password → pas-swo-rd
rule: s"ll" "LL"          hello    → heLLo
rule: s"é" "e"            café     → cafe
```

That last one is worth noting: `é` written as `e` plus a combining acute
has no single-codepoint spelling, so under the byte engine the rule cannot
be written — it is refused.

### Scripts that need the cluster layer

```
rule: r     مَرحَبا  → ابحَرمَ      every haraka stays on its own letter
rule: ]     مَرْ      → مَ           drops the letter AND its sukun
rule: r     한국      → 국한         also correct for decomposed jamo
rule: ]     हिन्दी     → हि           drops the whole conjunct
rule: [     हिन्दी     → न्दी          never leaves a bare vowel sign
rule: u     straße   → STRASSE      the eszett GROWS to two characters
rule: u     grüße    → GRÜSSE
```

### Emoji stay intact

```
rule: r     ok👍🏽  →  👍🏽ko
rule: u     ok👍🏽  →  OK👍🏽
rule: ]     ok👍🏽  →  ok
```

Compare the last one without `-u`, where the byte engine removes one byte
of the skin-tone modifier and leaves a broken sequence:

```
procrule    -r drop.rule  →  ok👍�
procrule -u -r drop.rule  →  ok
```

### Locale

The dotted and dotless I is the only case mapping with more than one right
answer.  Turkish and Azeri lowercase capital I to a dotless one and
uppercase i to a dotted capital; nobody else does.  With no way to know
which is meant, both are emitted:

```
procrule -u       -r upper.rule   istanbul  →  ISTANBUL  İSTANBUL
procrule -u -L tr -r upper.rule   istanbul  →  İSTANBUL
procrule -u -L c  -r upper.rule   istanbul  →  ISTANBUL
```

Emitting both cannot miss a candidate, but on an English wordlist it
inflates the output by 38.7% with forms that can never crack anything, and
on a Turkish list half the output is the wrong locale.  `-L` only ever
narrows, so a wrong declaration costs coverage rather than producing wrong
candidates.

### Discovery honours `-u`

Rule discovery (`-G`) searches with whichever engine is selected.
Without `-u` it can only find rules the byte engine can express, so on
non-ASCII input it may report no rule where one plainly exists:

```
base    مَر        target  رمَ        (the grapheme-correct reversal)

procrule    -D 1 -G target base   ->  0 rules
procrule -u -D 1 -G target base   ->  7 rules:  r  k  K  *01  *10  {  }
```

All seven are correct -- that word is two clusters, so every rule that
swaps or rotates two clusters produces the target.  A three-cluster
case narrows to three.  Reporting zero is the dangerous outcome,
because it is indistinguishable from no rule existing.

### One trap worth knowing

A rule file and a wordlist in **different Unicode normal forms silently
match nothing**, and that looks exactly like an honest negative.  `é` as
one codepoint and `é` as `e` plus a combining acute are different text.
procrule does not normalise either side, and deliberately so: the hash was
computed over exact bytes, so silently recomposing a candidate would
produce a different digest and crack nothing.  Normalise your wordlist
before you start, or generate both forms.

## Benchmarks

Benchmarks were run using the hashcat `best64.rule` ruleset (77 active rules)
against a 29,012,354-line wordlist (304 MB), producing 2,141,402,915 deduplicated
candidates.  Output was redirected to `/dev/null` to measure pure rule-processing
and deduplication throughput independent of downstream I/O.

### Test Systems

| System | CPU | Cores / Threads | RAM |
|--------|-----|-----------------|-----|
| macOS (arm64) | Apple M1 | 8 / 8 | 8 GB |
| Linux (x86_64) | AMD Ryzen 7 1800X | 8 / 16 | 32 GB |
| Linux (x86_64) | 2x Intel Xeon E5-2697 v4 @ 2.30 GHz | 36 / 72 | 992 GB |
| Linux (ppc64le) | IBM POWER8 | 80 / 80 | 128 GB |

### Results

```
procrule -r best64.rule 29m.pass > /dev/null
```

| System | Wall Time | User Time | Sys Time | Peak RSS | Candidates/sec |
|--------|-----------|-----------|----------|----------|----------------|
| Apple M1 (8 cores) | 49.5 s | 225.4 s | 106.4 s | 1,171 MB | 43.3 M/s |
| AMD Ryzen 7 1800X (16 threads) | 48.7 s | 728.5 s | 2.5 s | 1,172 MB | 44.0 M/s |
| 2x Xeon E5-2697 v4 (72 threads) | 45.6 s | 418.8 s | 43.2 s | 1,203 MB | 46.9 M/s |
| IBM POWER8 (80 cores) | 23.2 s | 1,489.9 s | 10.3 s | 1,201 MB | 92.5 M/s |

Memory usage is dominated by the Bloom filter and Judy deduplication structures,
which scale with the number of unique input words rather than the rule count.
All four systems used approximately 1.2 GB peak RSS for the 29M-word input.

The M1's elevated system time reflects memory pressure on an 8 GB system
with a 1.2 GB working set.

## Source Files

| File | Description |
|------|-------------|
| `procrule.c` | Main program — I/O, threading, match/dedup logic |
| `ruleproc.c` | Rule parsing and application engine (shared with mdxfind) |
| `ruleproc32.c` / `ruleproc32.h` | UTF-32 rule engine used by `-u` |
| `rule_ops.h` | Rule opcode numbers, shared by both engines |
| `latin_case.h` | Case tables for 23 script blocks — GENERATED, do not edit |
| `combining.h` | Combining-mark ranges for grapheme clustering — GENERATED, do not edit |
| `mdxfind.h` | Shared header for ruleproc |
| `yarn.c` / `yarn.h` | Thread pool library (shared with rling) |
| `xxh3.h` / `xxhash.h` | xxHash — fast non-cryptographic hash (header-only) |

## License

Copyright (c) Waffle — Cynosureprime