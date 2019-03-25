package mixnet

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/nacl/box"
)

func (cl *Client) InitNewRound() error {

	// Shift current round state to previous.
	cl.PrevRound = cl.CurRound

	// Initialize new current round state.
	cl.CurRound = &RoundClient{
		Nonce:   new([24]byte),
		MsgKeys: make([][]*OnionKeyPair, len(cl.ChainMatrix)),
	}

	// Create new random nonce.
	_, err := io.ReadFull(rand.Reader, cl.CurRound.Nonce[:])
	if err != nil {
		return err
	}

	for chain := range cl.ChainMatrix {

		cl.CurRound.MsgKeys[chain] = make([]*OnionKeyPair, len(cl.ChainMatrix[chain]))

		for mix := range cl.ChainMatrix[chain] {

			// Generate public-private key pair.
			msgPubKey, msgSecKey, err := box.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}

			// Insert appropriate new key struct.
			cl.CurRound.MsgKeys[chain][mix] = &OnionKeyPair{
				PubKey: msgPubKey,
				SymKey: new([32]byte),
			}

			// Calculate shared key between ephemeral
			// secret key and receive public key of each mix.
			box.Precompute(cl.CurRound.MsgKeys[chain][mix].SymKey, cl.ChainMatrix[chain][mix].PubKey, msgSecKey)
		}
	}

	return nil
}
