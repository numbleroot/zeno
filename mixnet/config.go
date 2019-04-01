package mixnet

import "time"

// RoundTime specifies the per-mix
// duration of accepting messages.
const RoundTime = 2 * time.Second

// ExitMsgOverhead specifies the amount
// of overhead in bytes for an end user
// message after it has been serialized
// by Cap'n Proto.
const ExitMsgOverhead = 48

// MixMsgOverhead specifies the amount
// of overhead in bytes for an onionized
// message after it has been serialized
// by Cap'n Proto.
const MixMsgOverhead = 104
