package web

import (
	"strings"
	"testing"
)

// No string literal in a script is left open at the end of a line.
//
// A page whose script does not parse is a page with no report on it, and every
// test here reads the script as text. One was shipped for the length of a
// browser reload on 2026-09-20, because a value edited into a string carried a
// real newline, and nothing in this package could tell: the tests grep, and a
// broken file greps exactly like a working one.
//
// Go cannot parse JavaScript, this project has no toolchain that can, and
// writing a parser for four files would be worse than the defect. What is
// cheap is the shape the mistake takes — a quote opened on one line and closed
// on the next — and that is what this reads, walking each line character by
// character so that a quote inside a comment, or an apostrophe inside a
// double-quoted sentence, is what it is rather than a literal being opened.
func TestNoStringLiteralInAScriptIsLeftOpen(t *testing.T) {
	for _, name := range []string{"assets/app.js", "assets/session.js", "assets/theme.js", "assets/hero.js"} {
		inBlock := false
		for i, line := range strings.Split(asset(t, name), "\n") {
			open, block := unterminated(line, inBlock)
			inBlock = block
			if open {
				t.Errorf("%s:%d opens a string and does not close it on the same line: %s",
					name, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// unterminated walks one line and says whether it ends inside a string, and
// whether a block comment is still open after it.
func unterminated(line string, inBlock bool) (open, block bool) {
	var quote byte
	escaped := false

	for i := 0; i < len(line); i++ {
		c := line[i]

		switch {
		case inBlock:
			if c == '*' && i+1 < len(line) && line[i+1] == '/' {
				inBlock = false
				i++
			}

		case quote != 0:
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == quote:
				quote = 0
			}

		case c == '/' && i+1 < len(line) && line[i+1] == '/':
			return false, false

		case c == '/' && i+1 < len(line) && line[i+1] == '*':
			inBlock = true
			i++

		case c == '"' || c == '\'':
			quote = c
		}
	}
	return quote != 0, inBlock
}
