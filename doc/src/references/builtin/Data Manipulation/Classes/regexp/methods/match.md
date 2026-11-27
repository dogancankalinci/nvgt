# match
Determine if the regular expression matches against a particular string or not.

1. `bool regexp::match(const string&in subject, uint64 offset = 0);`
2. `bool regexp::match(const string&in subject, uint64 offset, int options);`

## Arguments (1):
* const string&in subject: the string to compare against.
* uint64 offset = 0: the offset to start the comparison at.

## Arguments (2):
* const string&in subject: the string to compare against.
* uint64 offset: the offset to start the comparison at.
* int options: any combination of the values found in the `regexp_options` enum.

## Returns:
bool: true if the regular expression matches the given string, false if not.

## Remarks:
The comparison takes the first match the pattern finds at the offset, trying its alternatives and repetitions in their order, and is true when that match covers the rest of the subject: `regexp("a|ab").match("ab")` is false, as the pattern first matches `a`, while `regexp("ab|a").match("ab")` and `regexp("(?:a|ab)$").match("ab")` are true. End the pattern with `$` (or `\z`) to have every way of matching tried against the whole rest of the subject.

The first form never matches an empty subject, or an offset at the end of the subject, even for a pattern that matches nothing, such as `a*` or `^$`; the second matches there unless its options include RE_NOT_EMPTY.

Unless the options set another newline, a newline is CR (`\r`), as RE_NEWLINE_CR describes, so `.` also matches LF (`\n`), and `$` matches at the very end or before a final CR, not before a final LF.
