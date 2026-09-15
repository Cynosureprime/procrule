# procrule release notes

## v1.34

### Breaking: the UTF-32 rule engine is now selected with `-8`, not `-u`

`-u` has been removed. `procrule -u` exits with `procrule: invalid option -- u`.
Replace it with `-8`; nothing else about the invocation changes.

The rename exists because the flag now means the same thing in two tools.
`mdxfind -u` already loads a userid file, so `-u` could never have carried this
meaning there, and having the same engine selected by different letters in
procrule and mdxfind was a trap worth closing permanently. `-8` was free in both.

If you have scripts, aliases or job files carrying `-u`, they will fail loudly
rather than silently do the wrong thing — the option is gone, not repurposed.

### The engine is chosen per word, not per run

Under `-8` each word is routed by its own content. A word that is entirely
ASCII is run by the byte engine, because both engines agree on such a word and
the byte engine is faster. Only a word that needs UTF-32 gets it.

This is worth knowing before testing the option: on a pure-ASCII wordlist `-8`
appears to do nothing, and that is correct rather than broken. Use a word with
a non-ASCII character in it to see the engine work. In particular `-L`, which
pins the locale for the dotted and dotless I, cannot change the result for an
all-ASCII word — the byte engine has no locale.

A third case exists and is handled: a rule whose own text is not valid UTF-8,
such as one inserting raw high bytes, compiles for the byte engine and is
refused by the UTF-32 one. Those rules run on the byte engine even under `-8`
rather than being dropped. There are 31 of them in HashMob.100k.rule.

### New: `-A`, audit mode

One line per (word, rule) with nothing suppressed. Ordinarily a rule whose
output equals its input prints nothing, so the line count is below the
rules-times-words product and a rejection, an unchanged word and an empty
result are indistinguishable. `-A` prints a marker in place of the absent line:
`:SAME`, `:EMPTY`, `:REJECT`, `:BADRULE` or `:NEG`.

Both engines report the same marker for the same outcome, deliberately, so a
byte run and a `-8` run can be diffed line for line. That is not free: the two
engines number their internal results inversely — a rejection is -1 to one and
-3 to the other — and the UTF-32 engine has no unchanged-output result at all.
Both are reconciled before a marker is chosen, so a difference between two `-A`
streams is a real difference and not an artefact of which engine ran.

Hex encoding is forced on, because a candidate containing a colon is
`$HEX[]`-wrapped and so no ordinary output line can begin with one. That is
what keeps the markers unambiguous. Match mode is unaffected.

### New: `-R`, the rule dot product

`-R` loads rules like `-r`, but forms the dot product with the rules already
loaded: every existing rule is concatenated with every new one. Two files of
100 rules give 10,000. Several `-R` files multiply each other. The
UTF-32-required property propagates through the product, so a plain rule
combined with one needing UTF-32 is itself routed to the UTF-32 engine.

### Fixed: `-G` discovery under `-8`

Discovery read a global to decide the engine rather than asking per word, so
under `-8` it searched in byte terms and could report no rule where one exists.
A word and its grapheme-correct reversal in vocalised Arabic yielded nothing,
because reversing bytes mangles the text. Discovery now chooses per word and
explains that case with `r`, as it should.

### Documentation

The man pages ship inside the release archives for the first time, under
`man/`. `procrule(1)` covers `-8`, `-A` and `-R`; `rules32(7)` carries the
UTF-32 semantics. Both previously documented `-u` throughout — following them
produced an invalid-option error — and `rules32(7)`'s locale example could not
demonstrate what it claimed, because it used an all-ASCII word that the byte
engine handles. Both are corrected.

### Building

`classify_utf8.c` and `classify_utf8.h` are new required sources. The bundled
Makefile lists them; a hand-rolled build must compile and link
`classify_utf8.o` or `procrule` will not link.
