package mixnet

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"

	"github.com/numbleroot/zeno/rpc"
	"golang.org/x/crypto/nacl/box"
	capnp "zombiezen.com/go/capnproto2"
	capnprpc "zombiezen.com/go/capnproto2/rpc"
)

// AddCoverMsgsToPool ensures that a reasonable
// (usually, #clients / 10) amount of generated
// cover messages is prepopulated in the message
// pool of each mix. We aim to thwart n - 1 attacks
// by choosing forward batch messages uniformly
// at random from that pool with the exception of
// old messages.
func (mix *Mix) AddCoverMsgsToPool() error {

	// Determine number of clients and
	// respective sample size.
	numClients := len(mix.KnownClients)
	numMixesToEnd := len(mix.ChainMatrix[mix.OwnChain]) - (mix.OwnIndex + 1)
	numSamples := numClients / 10
	if numSamples < 100 {
		numSamples = numClients
	}

	// Randomly select k clients to generate
	// cover messages to.
	for i := 0; i < numSamples; i++ {

		// Select a user index uniformly at random.
		chosenBig, err := rand.Int(rand.Reader, big.NewInt(int64(numClients)))
		if err != nil {
			return err
		}
		chosen := int(chosenBig.Int64())

		// Prepare mostly random cover message.
		msgPadded := new([280]byte)
		_, err = io.ReadFull(rand.Reader, msgPadded[:])
		if err != nil {
			return err
		}
		copy(msgPadded[:], "COVER MESSAGE, PLEASE DISCARD")

		// Create empty Cap'n Proto messsage.
		protoMsg, protoMsgSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
		if err != nil {
			return err
		}

		// Fill ConvoExitMsg.
		convoExitMsg, err := rpc.NewRootConvoExitMsg(protoMsgSeg)
		if err != nil {
			return err
		}
		convoExitMsg.SetClientAddr(mix.KnownClients[chosen].Addr)
		convoExitMsg.SetContent(msgPadded[:])

		if mix.IsExit {

			// This is an exit mix, thus simply add the
			// cover message directly to message pool in
			// first time slot.
			mix.ExitMsgsByIncWait[0] = append(mix.ExitMsgsByIncWait[0], &convoExitMsg)

		} else {

			// This is not an exit mix, thus we
			// want to onion-encrypt. Prepare key
			// material.

			// Prepare key chain for this participant.
			keys := make([]*OnionKeyState, numMixesToEnd)

			for otherMix := 0; otherMix < numMixesToEnd; otherMix++ {

				keys[otherMix] = &OnionKeyState{
					Nonce:  new([24]byte),
					PubKey: new([32]byte),
					SymKey: new([32]byte),
				}

				// Create new random nonce.
				_, err = io.ReadFull(rand.Reader, keys[otherMix].Nonce[:])
				if err != nil {
					return err
				}

				// Generate public-private key pair.
				msgSecKey := new([32]byte)
				keys[otherMix].PubKey, msgSecKey, err = box.GenerateKey(rand.Reader)
				if err != nil {
					return err
				}

				origIdx := mix.OwnIndex + otherMix + 1

				// Calculate shared key between ephemeral
				// secret key and receive public key of each mix.
				box.Precompute(keys[otherMix].SymKey, mix.ChainMatrix[mix.OwnChain][origIdx].PubKey, msgSecKey)
			}

			// Marshal final ConvoExitMsg to byte slice.
			msg, err := protoMsg.Marshal()
			if err != nil {
				return err
			}

			fmt.Printf("len(convoExitMsg) = %d\n", len(msg))

			// Going through chains in reverse, encrypt
			// ConvoExitMsg symmetrically as content. Pack
			// into ConvoMixMsg and prepend with used public
			// key and nonce.
			for mix := (len(keys) - 1); mix > 0; mix-- {

				// Use precomputed nonce and shared key to
				// symmetrically encrypt the current message.
				encMsg := box.SealAfterPrecomputation(keys[mix].Nonce[:], msg, keys[mix].Nonce, keys[mix].SymKey)

				// Create empty Cap'n Proto messsage.
				protoMsg, protoMsgSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
				if err != nil {
					fmt.Printf("Failed creating empty Cap'n Proto message: %v\n", err)
					os.Exit(1)
				}

				// Create new ConvoMixMsg and insert values.
				convoMixMsg, err := rpc.NewRootConvoMixMsg(protoMsgSeg)
				if err != nil {
					fmt.Printf("Failed creating new root ConvoMixMsg: %v\n", err)
					os.Exit(1)
				}
				convoMixMsg.SetPubKey(keys[mix].PubKey[:])
				convoMixMsg.SetNonce(keys[mix].Nonce[:])
				convoMixMsg.SetContent(encMsg)

				// Marshal final ConvoMixMsg to byte slice.
				msg, err = protoMsg.Marshal()
				if err != nil {
					fmt.Printf("Failed marshalling final ConvoMixMsg to []byte: %v\n", err)
					os.Exit(1)
				}

				fmt.Printf("len(msg) = %d\n", len(msg))
			}

			// Use precomputed nonce and shared key to
			// symmetrically encrypt the current message
			// finally for the subsequent of the current mix.
			encMsg := box.SealAfterPrecomputation(keys[0].Nonce[:], msg, keys[0].Nonce, keys[0].SymKey)

			// Create empty Cap'n Proto messsage.
			protoMsg, protoMsgSeg, err = capnp.NewMessage(capnp.SingleSegment(nil))
			if err != nil {
				fmt.Printf("Failed creating empty Cap'n Proto message: %v\n", err)
				os.Exit(1)
			}

			// Create new ConvoMixMsg and insert values.
			convoMixMsg, err := rpc.NewRootConvoMixMsg(protoMsgSeg)
			if err != nil {
				fmt.Printf("Failed creating new root ConvoMixMsg: %v\n", err)
				os.Exit(1)
			}
			convoMixMsg.SetPubKey(keys[0].PubKey[:])
			convoMixMsg.SetNonce(keys[0].Nonce[:])
			convoMixMsg.SetContent(encMsg)

			// Add layered ConvoMixMsg to pool in first time slot.
			mix.MixMsgsByIncWait[0] = append(mix.MixMsgsByIncWait[0], &convoMixMsg)
		}
	}

	return nil
}

func (mix *Mix) AddBatch(call rpc.Mix_addBatch) error {

	data, err := call.Params.Batch()
	if err != nil {
		return err
	}

	fmt.Printf("\nAddBatch req: '%#v'\n", data)

	call.Results.SetStatus(0)

	return nil
}

func (mix *Mix) GetMixnetConfig(call rpc.Mix_getMixnetConfig) error {

	fmt.Printf("\nGetMixnetConfig req.\n")

	call.Results.SetMeta(rpc.MixnetConfig{})

	return nil
}

func (mix *Mix) AddConvoMsg(call rpc.Mix_addConvoMsg) error {

	msg, err := call.Params.Msg()
	if err != nil {
		return err
	}

	fmt.Printf("\nAddConvoMsg req: '%#v'\n", msg)

	call.Results.SetStatus(0)

	return nil
}

// HandleMsg accepts incoming Cap'n Proto
// messages, constructs appropriate wrappers,
// and handles the request.
func (mix *Mix) HandleMsg(c net.Conn) {

	main := rpc.Mix_ServerToClient(mix)
	conn := capnprpc.NewConn(capnprpc.StreamTransport(c), capnprpc.MainInterface(main.Client))

	err := conn.Wait()
	if err != nil {
		fmt.Printf("Error waiting for public connection: %v\n", err)
	}
}
