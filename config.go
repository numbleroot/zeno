package main

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

// Msg is the conversation message that
// is sent between participants of the
// mix-net infrastructure.
const Msg = "All human beings are born free and equal in dignity and rights. They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood. Everyone is entitled to all the rights and freedoms set forth in this Declaration, without distinction of any kind, such as race, colour, sex, language, religion, political or other opinion, national or social origin, property, birth or other status. Furthermore, no distinction shall be made on the basis of the political, jurisdictional or international status of the country or territory to which a person belongs, whether it be independent, trust, non-self-governing or under any other limitation of sovereignty."
