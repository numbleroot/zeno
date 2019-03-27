package mixnet

import (
	"crypto/rand"
	"io"

	"github.com/numbleroot/zeno/rpc"
	"golang.org/x/crypto/nacl/box"
)

// InitNewRound on clients takes care of
// rotating the current round state to be
// the previous one and bootstraps key
// material and auxiliary data for the new
// current one.
func (cl *Client) InitNewRound() error {

	// Shift current round state to previous.
	cl.PrevRound = cl.CurRound

	// Initialize new current round state.
	cl.CurRound = make([][]*OnionKeyState, len(cl.ChainMatrix))

	for chain := range cl.ChainMatrix {

		cl.CurRound[chain] = make([]*OnionKeyState, len(cl.ChainMatrix[chain]))

		for mix := range cl.ChainMatrix[chain] {

			cl.CurRound[chain][mix] = &OnionKeyState{
				Nonce:  new([24]byte),
				PubKey: new([32]byte),
				SymKey: new([32]byte),
			}

			// Create new random nonce.
			_, err := io.ReadFull(rand.Reader, cl.CurRound[chain][mix].Nonce[:])
			if err != nil {
				return err
			}

			// Generate public-private key pair.
			msgSecKey := new([32]byte)
			cl.CurRound[chain][mix].PubKey, msgSecKey, err = box.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}

			// Calculate shared key between ephemeral
			// secret key and receive public key of each mix.
			box.Precompute(cl.CurRound[chain][mix].SymKey, cl.ChainMatrix[chain][mix].PubKey, msgSecKey)
		}
	}

	return nil
}

// InitNewRound on mixes takes care of moving
// message pools from previous rounds to higher
// delay slots and prepares the first delay slot
// for incoming messages.
func (mix *Mix) InitNewRound() error {

	if len(mix.MsgPoolsByIncWait) < 3 {

		// Initialize message pools in case they
		// do not yet exist (e.g., in first round).
		mix.MsgPoolsByIncWait = make([][]*rpc.ConvoMixMsg, 3)

	} else {

		for i := (len(mix.MsgPoolsByIncWait) - 1); i >= 0; i-- {

			// Move message pools from previous rounds
			// up in list of message pools sorted by
			// increasing delayed rounds.
			mix.MsgPoolsByIncWait[i] = mix.MsgPoolsByIncWait[(i - 1)]
		}
	}

	numClients := len(mix.KnownClients)
	numSamples := numClients / 10
	if numSamples < 100 {
		numSamples = numClients
	}
	maxNumMsg := numClients + numSamples + 10

	// Prepare space in first pool for round
	// that is about to start to already offer
	// a rough approximation of the expected
	// total number of messages in that round.
	mix.MsgPoolsByIncWait[0] = make([]*rpc.ConvoMixMsg, 0, maxNumMsg)

	// Add basis of cover traffic to first pool.
	err := mix.AddCoverMsgsToPool()
	if err != nil {
		return err
	}

	return nil
}
