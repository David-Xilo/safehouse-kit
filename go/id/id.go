// Package id holds the identities that writers in several languages must derive alike.
package id

import (
	"fmt"

	"github.com/google/uuid"
)

// processUIDNamespace is the namespace of Rust's id::process_uid. Changing it breaks joins
// with stored events.
var processUIDNamespace = uuid.MustParse("85b56229-910c-4309-8415-ad67a9107337")

// ProcessUID returns the stable identity of one process instance, OCSF process.uid: pids
// are reused, so the boot (/proc/sys/kernel/random/boot_id) and the start time (clock
// ticks since boot, /proc/<pid>/stat field 22) disambiguate. It equals Rust's
// id::process_uid for the same inputs; contract/ids/process-uid.json holds the cases.
func ProcessUID(bootID string, pid uint32, startTicks uint64) string {
	name := fmt.Sprintf("%s:%d:%d", bootID, pid, startTicks)
	return uuid.NewSHA1(processUIDNamespace, []byte(name)).String()
}
