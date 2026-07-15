package mysql

import "testing"

// TestSplitStatements_KeepsStatementPrecededByCommentLines is a regression
// test: splitStatements used to check whether the *whole* trimmed segment
// started with "--" before stripping comment lines, which silently
// discarded the entire statement whenever a segment began with one or more
// leading "--" comment lines (exactly the shape of every migration file's
// header comment followed by its first CREATE TABLE).
func TestSplitStatements_KeepsStatementPrecededByCommentLines(t *testing.T) {
	body := "-- header line one\n-- header line two\nCREATE TABLE t (id INT)"
	got := splitStatements(body)
	if len(got) != 1 {
		t.Fatalf("want 1 statement, got %d: %#v", len(got), got)
	}
	if got[0] != "CREATE TABLE t (id INT)" {
		t.Fatalf("comment lines should be stripped, got %q", got[0])
	}
}

func TestSplitStatements_MultipleStatementsAndBlankSegments(t *testing.T) {
	body := "CREATE TABLE a (id INT);\n\n-- just a comment\nCREATE TABLE b (id INT);;  "
	got := splitStatements(body)
	if len(got) != 2 {
		t.Fatalf("want 2 statements, got %d: %#v", len(got), got)
	}
	if got[0] != "CREATE TABLE a (id INT)" || got[1] != "CREATE TABLE b (id INT)" {
		t.Fatalf("unexpected statements: %#v", got)
	}
}

func TestSplitStatements_CommentOnlySegmentDropped(t *testing.T) {
	body := "-- only a comment, no statement"
	got := splitStatements(body)
	if len(got) != 0 {
		t.Fatalf("want 0 statements, got %d: %#v", len(got), got)
	}
}

// TestSplitStatements_SemicolonInsideCommentIgnored is a regression test
// for 0004_webauthn_credentials.up.sql's actual header comment, which
// contains a semicolon ("-- ... monotonic counter; checked ..."). A
// naive split-on-";" before comment stripping mistakes that for a
// statement terminator and corrupts both the preceding and following
// statement.
func TestSplitStatements_SemicolonInsideCommentIgnored(t *testing.T) {
	body := "-- sign_count is BIGINT for monotonic counter; checked strictly-greater at\n" +
		"-- application layer for replay detection.\n\n" +
		"CREATE TABLE t (id INT)"
	got := splitStatements(body)
	if len(got) != 1 {
		t.Fatalf("want 1 statement, got %d: %#v", len(got), got)
	}
	if got[0] != "CREATE TABLE t (id INT)" {
		t.Fatalf("comment with embedded semicolon leaked into the statement, got %q", got[0])
	}
}
