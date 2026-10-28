// Package ocsf holds the OCSF 1.9.0 envelope every safehouse module writes: metadata with
// the writing product, and the device. Class types stay in the module that writes them.
package ocsf

import (
	"time"

	"github.com/David-Xilo/safehouse-kit/go/utc"
	"github.com/google/uuid"
)

const (
	// Version is the OCSF schema version of every safehouse event.
	Version = "1.9.0"
	// Vendor is metadata.product.vendor_name for every safehouse module.
	Vendor = "safehouse"
)

type Product struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
}

type Metadata struct {
	UID             string   `json:"uid"`
	Version         string   `json:"version"`
	Product         Product  `json:"product"`
	Profiles        []string `json:"profiles"`
	Labels          []string `json:"labels,omitempty"` // at most one Label* value
	ProcessedTime   int64    `json:"processed_time"`
	ProcessedTimeDT string   `json:"processed_time_dt"`
}

type Device struct {
	TypeID   int    `json:"type_id"`
	Hostname string `json:"hostname"`
}

// NewMetadata returns the metadata of one event written by module name at version, with
// a new UUIDv7 uid. processed is when the event was made, not when the fact was observed.
func NewMetadata(name, version string, profiles []string, processed time.Time) Metadata {
	return Metadata{
		UID:             NewUID(),
		Version:         Version,
		Product:         Product{Name: name, VendorName: Vendor, Version: version},
		Profiles:        profiles,
		ProcessedTime:   utc.Millis(processed),
		ProcessedTimeDT: utc.Format(processed),
	}
}

// NewUID returns a UUIDv7 for metadata.uid, or a random UUID if the clock cannot be read.
func NewUID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}
