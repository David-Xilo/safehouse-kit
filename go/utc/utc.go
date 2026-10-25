// Package utc formats times as the safehouse contract and OCSF events expect: UTC, with
// nanoseconds for RFC 3339 strings and milliseconds for OCSF epoch fields.
package utc

import "time"

// Format returns t as RFC 3339 in UTC with nanoseconds, always ending in "Z".
func Format(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// Millis returns t as milliseconds since the Unix epoch, the unit of OCSF time fields.
func Millis(t time.Time) int64 {
	return t.UTC().UnixMilli()
}
