package ocsf

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewMetadata(t *testing.T) {
	processed := time.Date(2026, 9, 29, 8, 30, 0, 123456789, time.FixedZone("EDT", -4*3600))
	m := NewMetadata("secret-hygiene", "0.1.0", []string{"datetime", "host"}, processed)

	if m.Version != Version || m.Product != (Product{Name: "secret-hygiene", VendorName: Vendor, Version: "0.1.0"}) {
		t.Fatalf("metadata = %+v", m)
	}
	if m.ProcessedTimeDT != "2026-09-29T12:30:00.123456789Z" {
		t.Errorf("processed_time_dt = %q, want UTC with nanoseconds and Z", m.ProcessedTimeDT)
	}
	if m.ProcessedTime != processed.UnixMilli() {
		t.Errorf("processed_time = %d, want %d", m.ProcessedTime, processed.UnixMilli())
	}
	id, err := uuid.Parse(m.UID)
	if err != nil || id.Version() != 7 {
		t.Errorf("uid %q is not a UUIDv7", m.UID)
	}
	if NewUID() == m.UID || !strings.Contains(m.UID, "-") {
		t.Errorf("uids are not unique: %q", m.UID)
	}
}
