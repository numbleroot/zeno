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

// BatchSizeVariance defines the maximum
// amount of messages added additionally
// to half of the number of messages in
// a pool to append to the outgoing pool.
const BatchSizeVariance = 5

// NumCascades defines the number of
// distinct cascades that make up the
// chain matrix.
const NumCascades = 2

// LenCascade defines the number of mixes
// required to form one mix cascade.
const LenCascade = 3
