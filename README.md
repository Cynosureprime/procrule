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
| `-R file` | As `-r`, but form the **dot product** with the rules already loaded: every existing rule is concatenated with every new one. Several `-R` files multiply each other |
| `-m file` | Match file — only output candidates found in this file (may be specified multiple times) |
| `-o file` | Redirect output to file (default: stdout) |
| `-l file` | Line match log: writes `word:rule:candidate` for each match |
| `-s file` | Output rule match statistics to file |
| `-t num` | Maximum number of threads |
| `-M size` | Set memory cache size (supports K/M/G suffixes) |
| `-p num` | Set hash prime for deduplication |
| `-B count` | Benchmark mode — apply rules N times and report throughput |
| `-8` | Interpret rules in UTF-32 rather than over bytes — see [UTF-32 Rules](#utf-32-rules) |
| `-L locale` | Pin the locale for case mappings with more than one right answer (`tr`, `az`, `c`, `root`); implies `-8` |
| `-A` | Audit mode — one line per (word, rule), nothing suppressed. Where a line would be absent a marker takes its place: `:SAME`, `:EMPTY`, `:REJECT`, `:BADRULE`, `:NEG`. Both engines report the same marker for the same outcome, so a byte run and a `-8` run can be diffed line for line. Generate mode only; forces `$HEX[]` on so a marker cannot be mistaken for a candidate |
| `-x` | Disable `$HEX[]` encoding on output |
| `-q` | Quiet — suppress progress meters (summaries still print) |
| `-v` | Verbose mode (repeat for more detail) |
| `-h`, `-?` | Print the help message |
| `-V` | Print the version and exit |

### Discovery options

These apply to `-G` (see [Discovery](#discovery)); they do nothing in generate or
match mode.

| Option | Description |
|--------|-------------|
| `-G file` | Discovery mode — find rules that transform base words into the targets in `file`. Honours `-8`: with it, discovery searches in UTF-32 terms and can find rules the byte engine cannot express at all |
| `-D num` | Maximum chain depth (default 3; `1` = single rules only) |
| `-N num` | Phase 2 random chain iterations (default 10000000) |
| `-S rate` | Phase 2 word sample rate, per cent — e.g. `1.0` for 1% (default: auto) |
| `-H num` | Minimum hit count to keep a rule (default 0) |
| `-C list` | Restrict the discovery catalog by rule class: `case`, `affix`, `leet`, `shrink`, `order`, `other` — or `no-shrink` to exclude the length-reducing classes, which otherwise dominate the result while explaining nothing |
| `-Z` | Print the built-in discovery rule catalog and exit. Needs neither `-G` nor a wordlist; honours `-C`. Listing goes to stdout and the one-line summary to stderr. `-8` is accepted but changes nothing here — the two compilers agree on every rule in the built-in catalog (17,320 lines, identical either way). They differ on rule files *you* supply, which is where `-8` matters |

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
`0`–`9` for 0–9, `A`–`Z` for 10–35 and `a`–`z` for 36–61, so a rule can address
characters up to position 61.  hashcat supports 0–35 only.

procrule never emits the source word: a rule whose output is bytewise identical
to its input produces no line at all.  The no-op rule `:` therefore produces no
output, and `-r` over a rule file of only `:` prints nothing.  This is not a
filter that can be switched off — it is how the engine reports "unchanged", and
mdxfind relies on it (mdxfind tries the unmodified word once, from the search
loop rather than from a rule).

### Case Rules

| Rule | Description |
|------|-------------|
| `l` | Lowercase all characters |
| `u` | Uppercase all characters |
| `c` | Uppercase position 0, lowercase the rest |
| `C` | Lowercase position 0, uppercase the rest |
| `t` | Toggle case of all characters |
| `TN` | Toggle case at position N |
| `E` | Title case (capitalize after each space) |
| `eX` | Title case with custom separator X |
| `3NX` | Toggle case of the first letter after the Nth occurrence of X (N counts from 0) |

`c`, `C`, `E` and `eX` act on **position 0**, not on the first alphabetic
character.  If position 0 is not a letter, nothing is capitalised there:
`c` on `!bang` gives `!bang`, not `!Bang`; `C` on `!bang` gives `!BANG`.  For
`E` and `eX` the word start is positional too — the first character after a
separator, letter or not — so `E` on `9999Z999` gives `9999z999`.  John and
hashcat agree here and procrule was the outlier until this was corrected.  It
bites hardest on candidates a rule has *already* made start with a non-letter.

`TN` with N at or past the end of the candidate is a no-op, now by an explicit
bounds check.  `E` and `eX` keep an already-uppercase letter at a word start
rather than re-casing it, so `Hello1` stays `Hello1` and `abc Def` becomes
`Abc Def`, matching hashcat 6.2.5 and John.  For `ea`, where the separator sits
at position 0, hashcat force-uppercases position 0 and John does not — `apple`
is `APple` in hashcat, `aPple` in John, and procrule follows John.

### Insertion and Deletion

| Rule | Description |
|------|-------------|
| `$X` | Append character X |
| `^X` | Prepend character X |
| `[` | Delete first character |
| `[^X` | Overwrite the first character with X — an mdxfind extension, equivalent to `o0X` |
| `]` | Delete last character |
| `DN` | Delete character at position N |
| `iNX` | Insert character X at position N |
| `oNX` | Overwrite character at position N with X |
| `'N` | Truncate word at length N |
| `xNM` | Extract M characters starting at position N, if the whole range fits |
| `ONM` | Delete M characters starting at position N |

Out-of-range positions are not handled uniformly, and the behaviour follows John
rather than being invented here:

- `iNX` appends when N equals the current length — `i1a` on `a` gives `aa`.
  N beyond the length is a no-op.
- `xNM` is a **no-op unless the whole range fits** — both N past the end and
  N + M past the end leave the candidate untouched, and it never extracts a
  partial run.  This follows hashcat's `mangle_extract()`.  John does neither:
  it rejects an out-of-range start and extracts what is available when the count
  overruns.  On `abc`, `x22` and `x23` give `abc` here and `c` in John; `x90`
  gives `abc` here and a rejection in John.  A zero count with an in-range start
  still empties the candidate, which procrule keeps and John rejects.
- `ONM` is the asymmetric twin: out of range it is a silent no-op.
- `oNX` with N = 0 on a zero-length candidate appends X, so `'0 o0Q` gives `Q`.

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
| `.N` | Replace character at N with character at N+1 (`password` → `psssword` with `.1`) |
| `,N` | Replace character at N with character at N-1 (`password` → `ppssword` with `,1`) |
| `LN` | Bit-shift the byte at position N left one bit (`pass1` → `passb` with `L4`) |
| `RN` | Bit-shift the byte at position N right one bit (`password` → `8assword` with `R0`) |
| `BNX` | Add the byte value of X to the byte at position N, unsigned wrap |
| `vNX` | Insert character X after every N characters, including at the end (`password` → `pa-ss-wo-rd-` with `v2-`) |

`.N` is a no-op when there is no character at N+1: `.8` on `abcdefghij` gives
`abcdefghjj`, `.9` leaves the word unchanged.  `,N` is a no-op at N = 0.
`+N`, `-N`, `LN`, `RN` and `BNX` are no-ops when N is at or past the end.

`BNX` tracks hashcat **master** (`RULE_OP_MANGLE_CHR_ADD`, `src/rp_cpu.c`).  It is
not in the hashcat 6.2.5 release and does not exist in John, so a rule file using
it will not run under either.  hashcat's own example: `B50` on `hello0`.
It is refused outright under `-8`; the UTF-32 engine does not implement it.

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
| `XNMI` | Insert M characters of the memorized word, from offset N within it, at position I |

All three `XNMI` operands are used.  On `abcdef`, `MX034` gives `abcdabcef`,
`MX134` gives `abcdbcdef`, `MX234` gives `abcdcdeef` and `MX334` gives
`abcddefef` — the same as John.

**Out of range, `X` rejects the candidate rather than clamping**, following
hashcat's `mangle_insert_multi()`: no memory stored, insert position I past the
current length, offset N past the memorized length, N + M past the memorized
length, M below 1, or a result too long.  John clamps, so `MX049` on `abcdef` is
`abcdefabcd` in John and a rejection here.

hashcat memmoves its own memory buffer while reading it, so a second `X` in one
rule sees shifted memory.  That is a defect and is not replicated: `MX134X134`
on `abcdef` gives `abcdbcdbcdef` here and in John, `abcdcdebcdef` in hashcat.

### Rejection and Control

| Rule | Description |
|------|-------------|
| `<N` | Reject unless the length is **less than** N — that is, reject when length >= N |
| `>N` | Reject unless the length is **greater than** N — reject when length <= N |
| `_N` | Reject unless the length **equals** N |
| `=NX` | Reject unless the character at position N is X |
| `%NX` | Reject unless X occurs **at least** N times |
| `!X` | Reject if word contains character X |
| `/X` | Reject if word does not contain character X |
| `(X` | Reject if first character is not X |
| `)X` | Reject if last character is not X |
| `:` | No-op.  Compiles to an empty program, and produces no output |
| `#` | Comment: discards the **rest of this rule line** at compile time |

All three length tests read the **current** candidate length where the verb sits
in the rule, not the length of the input word.  `$a _5` keeps a four-character
word because the candidate is five characters by then; `$a _4` rejects it.

`<N`, `>N` and `_N` follow John, whose wording is unambiguous and whose engine
will run them.  hashcat's own comments for `<` and `>` read the other way round.

`(X` and `)X` accept a zero-length candidate rather than rejecting it: with
nothing there, there is no first or last character to disagree with X.

A candidate that a rule reduces to zero length is **kept**, and the rest of the
rule still runs.  John rejects it at that point and abandons the rule.  procrule
follows hashcat.  So `'0 $Z` yields `Z` here and nothing in John, and the same
applies to `@a` on the word `a`, to `x00`, and to `]]` on a two-character word.
This is long-standing behaviour, now a deliberate ruled divergence rather than an
accident, and it accounts for every remaining difference from John in the
character-class sweep.

`#` is not a run-time verb.  The compiler stops at the first `#` on the line, so
`c#$1` applies `c` and never sees `$1`.  It does not stop any other rule.

An unassigned verb letter is **silently ignored** — no diagnostic, and the rest of
the rule still runs, so `W$Z` on `password` gives `passwordZ`.  Only a malformed
or missing operand, or a rule truncated mid-verb, is reported and dropped:

```
$ printf 'T!\n' > bad.rule
$ procrule -r bad.rule words.txt
Invalid position ! for T
Invalid rule line. Ignored.: T!
```

A hashcat rule file containing verbs procrule does not implement will therefore
run with those verbs elided rather than being rejected, which is not the same
attack.  `mdxfind -r` reports the same class of error with the file name and line
number; procrule names the rule text instead.

### Character Classes

Nine verbs accept a character class instead of a literal character.  The prefix
selects both the class table and which reference procrule is matching:

| Syntax | Table | Classes | Complement |
|--------|-------|---------|------------|
| `?C` | John's | `?l ?u ?d ?s ?v ?c ?w ?p ?a ?x ?o ?b ?y ?z` | yes — uppercase the letter |
| `~?C` | hashcat's | `?l ?u ?d ?s ?h ?H` | no |

In John's table an uppercase class letter is the complement of the lowercase one,
so `?D` is "not a digit" and `@?D` on `pass1` leaves `1`.  hashcat has no
complement form.

The nine verbs, in either syntax: `s?CY` (replace class C with Y), `@?C` (purge
class C), `e?C` (title case with class C as separator), `!?C` and `/?C` (reject
if it contains / does not contain a member), `(?C` and `)?C` (reject unless the
first / last character is a member), `=N?C` (reject unless position N is a
member) and `%N?C` (reject unless at least N characters are members).

```
procrule: s?dX on Pass1   -> PassX
          @?d  on Pass1   -> Pass
          @?D  on pass1   -> 1
          ~@?H on Pass1 x -> Pass x
```

`??` is the literal-`?` escape, in both syntaxes.  **This breaks existing rule
files**: a rule meaning "purge a literal question mark" must now be written
`@??`, and `s?!` must become `s??!`.  Eight lines across the rule files shipped
with mdxfind stop loading for this reason — four in `HashMob.100k.rule`, three in
`d3ad0ne.rule`, one in `generated.rule` — and John rejects all eight too.  A rule
naming no class is refused at load time with the caret on the operand, so this
fails loudly:

```
  Rule: @?0
          ^
  Error: Invalid character class for command '@'
Invalid rule line. Ignored.: @?0
```

Three decisions, recorded as decisions:

- `?s` is hashcat's `class_sym()` in **both** tables — space plus every printable
  non-alphanumeric, 33 characters.  John's `?s` is narrower.
- John's user classes `?0`–`?9` are not implemented.  Undefined, John refuses
  them as well.
- Hex classes exist only in the hashcat table, which is what forces the tables
  apart: unprefixed, an uppercase letter means "not the lowercase class", so a
  John-table `?h` would make `?H` mean "not lower hex" instead of hashcat's
  "uppercase hex".  Unprefixed `?h` and `?H` therefore name no class and are
  refused — as they are in John.

`e?C` and `~e?C` are genuinely different algorithms, not one algorithm with the
class test swapped.  John's treats a class member as a separator and leaves it
as it stands; hashcat's lowercases every position, then uppercases position 0 and
every position whose *predecessor* was in the class, judged on the original
bytes.  `e?u` on `aBcDe` gives `ABCDE`; `~e?u` gives `AbCdE`.

Classes are **not** implemented under `-8`, but a class rule cannot mean two
different things there: every class form is refused at load time, naming the
rule.  The `??` escape is the exception and works identically in both engines,
so the `@?` → `@??` migration is safe under `-8` too.  A `~`-prefixed rule is
refused under `-8` whatever follows it, including `~@??`.  See `rules32(7)`.

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

`-8` runs the whole pipeline in UTF-32.  Input is decoded from UTF-8 to
codepoints, the rule is interpreted against codepoints and grapheme
clusters, and the result is encoded back to UTF-8.  Without `-8` nothing
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
procrule -8 -r emoji.rule wordlist.txt
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

### Language coverage

The 38 most-spoken languages, each put through a rule that exercises what
its script actually needs.  Every row was produced by running it -- none is
hand-written.  All use `-8`; the byte engine mangles or refuses most of them.

Four rows are worth reading closely, because each shows something a reader
might otherwise take for a bug:

- **German** is the only row whose output is *longer* than its input.  The
  eszett has no single-codepoint uppercase, so it becomes two characters.
- **Tamil** shows a deliberate *non*-action.  The pulli is left attached and
  the conjunct is not joined, because in Tamil a consonant carrying a pulli
  is a normal standalone letter -- which is why Unicode excludes Tamil from
  Indic_Conjunct_Break.  Joining it would merge units a reader sees apart.
- **Korean** is shown decomposed rather than precomposed.  Both spellings
  are the same word, and macOS stores filenames decomposed, so harvested
  Korean arrives either way.
- **Yoruba** carries two marks on one vowel, a dot below and a tone above.
  Both must travel with the letter and stay in canonical order.

| Language | Script | Input | Rule | Output | What it exercises |
|---|---|---|---|---|---|
| English | Latin | `password` | `c` | `Password` | capitalise |
| Mandarin Chinese | Han | `密码123` | `r` | `321码密` | one codepoint per character |
| Hindi | Devanagari | `हिन्दी123` | `]` | `हिन्दी12` | conjunct stays whole |
| Spanish | Latin | `contraseña` | `u` | `CONTRASEÑA` | enye |
| Modern Standard Arabic | Arabic | `كَلِمَة` | `]` | `كَلِمَ` | harakat not stranded |
| French | Latin | `élève2024` | `u` | `ÉLÈVE2024` | acute and grave |
| Bengali | Bengali | `বাংলা` | `r` | `লাবাং` | matra travels |
| Portuguese | Latin | `canção` | `u` | `CANÇÃO` | tilde and cedilla |
| Indonesian | Latin | `katasandi` | `c` | `Katasandi` | capitalise |
| Urdu | Arabic | `کِتاب` | `r` | `باتکِ` | kasra stays on its letter |
| Russian | Cyrillic | `пароль` | `u` | `ПАРОЛЬ` | Cyrillic case |
| Standard German | Latin | `straße` | `u` | `STRASSE` | eszett grows to SS |
| Japanese | Kana | `ｶﾞｷﾞ` | `r` | `ｷﾞｶﾞ` | halfwidth dakuten travels |
| Nigerian Pidgin | Latin | `wetindey` | `c` | `Wetindey` | capitalise |
| Egyptian Arabic | Arabic | `مَصْرِي` | `]` | `مَصْرِ` | whole cluster |
| Marathi | Devanagari | `मराठी` | `r` | `ठीराम` | matras travel |
| Vietnamese | Latin | `mậtkhẩu` | `u` | `MẬTKHẨU` | stacked tone marks |
| Telugu | Telugu | `తెలుగు` | `]` | `తెలు` | vowel signs travel |
| Swahili | Latin | `nenosiri` | `c` | `Nenosiri` | capitalise |
| Hausa | Latin | `kalmarsirri` | `c` | `Kalmarsirri` | capitalise |
| Turkish | Latin | `istanbul` | `u` | `ISTANBUL` | locale: see -L |
| Western Punjabi | Gurmukhi | `ਪੰਜਾਬੀ` | `r` | `ਬੀਜਾਪੰ` | tippi and matras |
| Tagalog | Latin | `hudyat` | `c` | `Hudyat` | capitalise |
| Tamil | Tamil | `தமிழ்` | `]` | `தமி` | pulli is a letter, not joined |
| Yue Chinese | Han | `廣東話` | `r` | `話東廣` | traditional Han |
| Wu Chinese | Han | `上海閒話` | `]` | `上海閒` | drop last |
| Iranian Persian | Arabic | `رمزعبور` | `r` | `روبعزمر` | reverse |
| Korean | Hangul | `한국어` | `r` | `어국한` | decomposed jamo |
| Amharic | Ethiopic | `አማርኛ` | `r` | `ኛርማአ` | syllabary |
| Thai | Thai | `รหัสผ่าน` | `]` | `รหัสผ่า` | vowel sign is a mark |
| Javanese | Latin | `tembung` | `c` | `Tembung` | capitalise |
| Italian | Latin | `perché` | `u` | `PERCHÉ` | acute |
| Gujarati | Gujarati | `ગુજરાતી` | `r` | `તીરાજગુ` | matras travel |
| Kannada | Kannada | `ಕನ್ನಡ` | `]` | `ಕನ್ನ` | drop last |
| Levantine Arabic | Arabic | `شَامِي` | `]` | `شَامِ` | drop last |
| Sudanese Arabic | Arabic | `سُودَانِي` | `r` | `ينِادَوسُ` | reverse |
| Yoruba | Latin | `ẹ̀kọ́` | `r` | `ọ́kẹ̀` | dot below AND tone on one vowel |
| Bhojpuri | Devanagari | `भोजपुरी` | `]` | `भोजपु` | drop last |

Coverage is by *script*, not by language, so the 26 scripts above carry far
more than 38 languages: any language written in Latin, Cyrillic, Arabic,
Devanagari or Han is already covered.  A regression corpus of 165 cases and
an audit across 51 languages and 26 scripts run with the test suite.

### Emoji stay intact

```
rule: r     ok👍🏽  →  👍🏽ko
rule: u     ok👍🏽  →  OK👍🏽
rule: ]     ok👍🏽  →  ok
```

Compare the last one without `-8`, where the byte engine removes one byte
of the skin-tone modifier and leaves a broken sequence:

```
procrule    -r drop.rule  →  ok👍�
procrule -8 -r drop.rule  →  ok
```

### Locale

The dotted and dotless I is the only case mapping with more than one right
answer.  Turkish and Azeri lowercase capital I to a dotless one and
uppercase i to a dotted capital; nobody else does.  With no way to know
which is meant, both are emitted:

```
procrule -8       -r upper.rule   istanbulé  →  ISTANBULÉ  İSTANBULÉ
procrule -8 -L tr -r upper.rule   istanbulé  →  İSTANBULÉ
procrule -8 -L c  -r upper.rule   istanbulé  →  ISTANBULÉ
```

The word carries a non-ASCII character on purpose.  Under `-8` each word is
routed by its own content, and a word that is entirely ASCII is run by the
byte engine — the two engines agree on such a word and the byte engine is
faster.  So `-L`, and every other UTF-32 semantic, cannot change the result
for plain `istanbul`: every locale returns the single line `ISTANBUL`.  That
is correct, not broken, but it makes an all-ASCII wordlist the wrong thing to
test `-8` with.

```
```

Emitting both cannot miss a candidate, but on an English wordlist it
inflates the output by 38.7% with forms that can never crack anything, and
on a Turkish list half the output is the wrong locale.  `-L` only ever
narrows, so a wrong declaration costs coverage rather than producing wrong
candidates.

### Discovery honours `-8`

Rule discovery (`-G`) searches with whichever engine is selected.
Without `-8` it can only find rules the byte engine can express, so on
non-ASCII input it may report no rule where one plainly exists:

```
base    مَر        target  رمَ        (the grapheme-correct reversal)

procrule    -D 1 -G target base   ->  0 rules
procrule -8 -D 1 -G target base   ->  7 rules:  r  k  K  *01  *10  {  }
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
| `ruleproc32.c` / `ruleproc32.h` | UTF-32 rule engine used by `-8` |
| `rule_ops.h` | Rule opcode numbers, shared by both engines |
| `latin_case.h` | Case tables for 23 script blocks — GENERATED, do not edit |
| `combining.h` | Combining-mark ranges for grapheme clustering — GENERATED, do not edit |
| `mdxfind.h` | Shared header for ruleproc |
| `yarn.c` / `yarn.h` | Thread pool library (shared with rling) |
| `xxh3.h` / `xxhash.h` | xxHash — fast non-cryptographic hash (header-only) |

## License

Copyright (c) Waffle — Cynosureprime