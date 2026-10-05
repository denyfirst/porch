// Package displaytest checks that a value read from somebody else's server
// carries nothing that acts on a display.
//
// display.Mark is applied where a remote string enters a report, one source at
// a time, and a source that skips it is invisible until somebody prints a
// report with an escape sequence in it. A fuzz target that hands a parser
// arbitrary bytes and then walks everything it returned asks the question for
// every field at once, including fields added after the target was written.
package displaytest

import (
	"fmt"
	"reflect"
	"testing"
	"unicode/utf8"

	"github.com/denyfirst/porch/internal/display"
)

// Clean fails t for every string reachable from v that display.Mark would
// change: a control character, a C1 control or a format character such as
// U+202E, which reverses the text after it.
func Clean(t testing.TB, v any) {
	t.Helper()
	walk(t, reflect.ValueOf(v), "value")
}

func walk(t testing.TB, v reflect.Value, path string) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		// Asked independently of Mark as well as through it, so that a Mark
		// that stopped replacing a byte would not be the judge of itself.
		if s := v.String(); !utf8.ValidString(s) || display.Mark(s) != s {
			t.Errorf("%s carries a character that acts on a display: %q", path, s)
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			walk(t, v.Elem(), path)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				walk(t, v.Field(i), path+"."+v.Type().Field(i).Name)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			walk(t, v.Index(i), fmt.Sprintf("%s[%d]", path, i))
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			walk(t, iter.Key(), path+" key")
			walk(t, iter.Value(), fmt.Sprintf("%s[%v]", path, iter.Key()))
		}
	}
}
