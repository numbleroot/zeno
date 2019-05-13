package main

import "time"

// EpochBrick is the smallest building
// block for durations in epochs.
const EpochBrick = 5 * time.Second

// RoundTime specifies the per-mix
// duration of accepting messages.
const RoundTime = 2 * time.Second

// BatchSizeVariance defines the maximum
// amount of messages added additionally
// to half of the number of messages in
// a pool to append to the outgoing pool.
const BatchSizeVariance = 5

// NumCascades defines the number of
// distinct cascades that make up the
// cascades matrix.
const NumCascades = 1

// LenCascade defines the number of mixes
// required to form one mix cascade.
const LenCascade = 7

// MsgLength defines the number of bytes
// the content of each conversation message
// will take up in space.
const MsgLength = 224

// MsgExitOverhead defines the number of
// additional bytes for a conversation
// message to be processed by the exit
// mix and send to the final recipient.
const MsgExitOverhead = 96

// MsgCascadeOverhead defines the number
// of bytes of overhead each mix layer
// adds to the original message for
// proper processing.
const MsgCascadeOverhead = 104

// Msg is the conversation message that
// is sent between participants of the
// mix-net infrastructure.
const Msg = "All human beings are born free and equal in dignity and rights. They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood. Everyone is entitled to all the rights and freedoms set forth in this Declaration, without distinction of any kind, such as race, colour, sex, language, religion, political or other opinion, national or social origin, property, birth or other status. Furthermore, no distinction shall be made on the basis of the political, jurisdictional or international status of the country or territory to which a person belongs, whether it be independent, trust, non-self-governing or under any other limitation of sovereignty."
