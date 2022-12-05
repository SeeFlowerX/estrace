package module

import "fmt"

type Timespec struct {
	TvSec  uint64 /* seconds */
	TvNsec uint64 /* nanoseconds */
}

func (this *Timespec) String() string {
	return fmt.Sprintf("seconds=%d,nanoseconds=%d", this.TvSec, this.TvNsec)
}
