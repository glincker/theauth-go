package toolguard

import (
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/glincker/theauth-go/v2/policy"
)

// CallLabelsKey is the Call.Provenance key whose labels cover the whole call.
const CallLabelsKey = policy.CallLabelsKey

// Labels is a set of provenance labels such as "user", "untrusted_web" or
// "tool_output:fetch_page". The zero value is an empty set.
type Labels map[string]struct{}

// NewLabels returns a set of the non empty labels.
func NewLabels(labels ...string) Labels {
	l := Labels{}
	l.Add(labels...)
	return l
}

// Add puts labels in the set and returns it. Empty labels are ignored. Add on
// a nil set is a no-op, so build sets with NewLabels.
func (l Labels) Add(labels ...string) Labels {
	if l == nil {
		return l
	}
	for _, s := range labels {
		if s != "" {
			l[s] = struct{}{}
		}
	}
	return l
}

// Union returns a new set holding the labels of l and others.
func (l Labels) Union(others ...Labels) Labels {
	out := NewLabels(l.Slice()...)
	for _, o := range others {
		out.Add(o.Slice()...)
	}
	return out
}

// Has reports whether any label matches pattern. A trailing * is a prefix
// wildcard and "*" matches any label.
func (l Labels) Has(pattern string) bool {
	for s := range l {
		if policy.MatchLabel(pattern, s) {
			return true
		}
	}
	return false
}

// Slice returns the labels sorted.
func (l Labels) Slice() []string {
	out := make([]string, 0, len(l))
	for s := range l {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// LabelProvider is implemented by host types that carry their own labels.
type LabelProvider interface{ Labels() []string }

// DeriveLabels returns the union of the labels of sources. A derived value is
// as sensitive as its most sensitive source, so the union is the safe default.
// A source is a Labels set, a []string, a string (one label), a
// map[string][]string (every label in it), a LabelProvider or a nil.
func DeriveLabels(sources ...any) []string {
	out := Labels{}
	for _, src := range sources {
		switch v := src.(type) {
		case nil:
		case Labels:
			out.Add(v.Slice()...)
		case []string:
			out.Add(v...)
		case string:
			out.Add(v)
		case map[string][]string:
			for _, ls := range v {
				out.Add(ls...)
			}
		case LabelProvider:
			out.Add(v.Labels()...)
		}
	}
	return out.Slice()
}

// MergeProvenance unions several provenance maps per key. The result holds
// sorted, deduplicated labels and omits empty keys. It is nil when empty.
func MergeProvenance(maps ...map[string][]string) map[string][]string {
	sets := map[string]Labels{}
	for _, m := range maps {
		for arg, ls := range m {
			s, ok := sets[arg]
			if !ok {
				s = Labels{}
				sets[arg] = s
			}
			s.Add(ls...)
		}
	}
	var out map[string][]string
	for arg, s := range sets {
		if len(s) == 0 {
			continue
		}
		if out == nil {
			out = map[string][]string{}
		}
		out[arg] = s.Slice()
	}
	return out
}

const maxTrackDepth = 8

// TrackerOption configures a ProvenanceTracker.
type TrackerOption func(*ProvenanceTracker)

// WithSubstringMatch sets whether an argument string found inside a tracked
// string also picks up its labels (an address lifted out of a fetched page).
// It is a heuristic. Default true.
func WithSubstringMatch(on bool) TrackerOption {
	return func(t *ProvenanceTracker) { t.substring = on }
}

// WithMinTextLength sets the shortest string remembered or matched. Default 4.
func WithMinTextLength(n int) TrackerOption {
	return func(t *ProvenanceTracker) { t.minLen = n }
}

// WithMaxTextEntries bounds the remembered strings, dropping the oldest first.
// Default 1000.
func WithMaxTextEntries(n int) TrackerOption {
	return func(t *ProvenanceTracker) { t.maxEntries = n }
}

// ProvenanceTracker remembers labels for tool outputs so they flow into the
// arguments of later calls. Go has no per object tags, so the tracker works on
// string content: every string inside a tracked value is remembered, and an
// argument string equal to one (or, by default, contained in one) inherits its
// labels. It is safe for concurrent use.
type ProvenanceTracker struct {
	mu         sync.Mutex
	texts      map[string]Labels
	order      []string
	substring  bool
	minLen     int
	maxEntries int
}

// NewProvenanceTracker returns an empty tracker.
func NewProvenanceTracker(opts ...TrackerOption) *ProvenanceTracker {
	t := &ProvenanceTracker{texts: map[string]Labels{}, substring: true, minLen: 4, maxEntries: 1000}
	for _, o := range opts {
		o(t)
	}
	return t
}

// Track registers labels for the strings inside value and returns value.
func (t *ProvenanceTracker) Track(value any, labels ...string) any {
	set := NewLabels(labels...)
	if len(set) == 0 {
		return value
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	walkStrings(reflect.ValueOf(value), 0, func(s string) { t.remember(s, set) })
	return value
}

// TrackResult registers a tool result as "tool_output:<tool>" plus any
// inherited labels.
func (t *ProvenanceTracker) TrackResult(tool string, result any, inherited ...string) {
	t.Track(result, append([]string{"tool_output:" + tool}, inherited...)...)
}

// LabelsOf returns the labels of the tracked strings found in value.
func (t *ProvenanceTracker) LabelsOf(value any) []string {
	out := Labels{}
	t.mu.Lock()
	defer t.mu.Unlock()
	walkStrings(reflect.ValueOf(value), 0, func(s string) { t.collect(s, out) })
	return out.Slice()
}

// ArgLabels returns per argument labels for args, a map with string keys or a
// struct (keys are json tag names, else field names).
func (t *ProvenanceTracker) ArgLabels(args any) map[string][]string {
	out := map[string][]string{}
	for name, v := range argValues(reflect.ValueOf(args)) {
		if ls := t.LabelsOf(v); len(ls) > 0 {
			out[name] = ls
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (t *ProvenanceTracker) remember(s string, labels Labels) {
	if len(s) < t.minLen {
		return
	}
	cur, ok := t.texts[s]
	if ok {
		for i, k := range t.order {
			if k == s {
				t.order = append(t.order[:i], t.order[i+1:]...)
				break
			}
		}
	} else {
		cur = Labels{}
		t.texts[s] = cur
	}
	cur.Add(labels.Slice()...)
	t.order = append(t.order, s)
	for len(t.order) > t.maxEntries {
		delete(t.texts, t.order[0])
		t.order = t.order[1:]
	}
}

func (t *ProvenanceTracker) collect(s string, into Labels) {
	if len(s) < t.minLen {
		return
	}
	if ls, ok := t.texts[s]; ok {
		into.Add(ls.Slice()...)
	}
	if t.substring {
		for text, ls := range t.texts {
			if text != s && strings.Contains(text, s) {
				into.Add(ls.Slice()...)
			}
		}
	}
}

// walkStrings calls fn for every string reachable from v: map values, slice
// and array elements, exported struct fields, through pointers and interfaces,
// to a bounded depth.
func walkStrings(v reflect.Value, depth int, fn func(string)) {
	if !v.IsValid() || depth > maxTrackDepth {
		return
	}
	switch v.Kind() {
	case reflect.String:
		fn(v.String())
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			walkStrings(v.Elem(), depth+1, fn)
		}
	case reflect.Map:
		for it := v.MapRange(); it.Next(); {
			walkStrings(it.Value(), depth+1, fn)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			walkStrings(v.Index(i), depth+1, fn)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				walkStrings(v.Field(i), depth+1, fn)
			}
		}
	}
}

func argValues(v reflect.Value) map[string]any {
	for v.IsValid() && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return nil
	}
	out := map[string]any{}
	switch v.Kind() {
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return nil
		}
		for it := v.MapRange(); it.Next(); {
			out[it.Key().String()] = it.Value().Interface()
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			name := f.Name
			if tag, _, _ := strings.Cut(f.Tag.Get("json"), ","); tag != "" && tag != "-" {
				name = tag
			}
			out[name] = v.Field(i).Interface()
		}
	}
	return out
}
