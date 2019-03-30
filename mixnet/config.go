package mixnet

import "time"

// RoundTime specifies the per-mix
// duration of accepting messages.
const RoundTime = 2 * time.Second

// MsgOverhead specifies the amount
// of overhead in bytes for a message
// after it has been serialized by
// Cap'n Proto.
// TODO: Add number.
const MsgOverhead = 0
