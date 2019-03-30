package mixnet

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/numbleroot/zeno/rpc"
	"golang.org/x/crypto/nacl/box"
	capnp "zombiezen.com/go/capnproto2"
	capnprpc "zombiezen.com/go/capnproto2/rpc"
)

// SetOwnPlace sets important indices into
// chain matrix for a just elected mix.
func (mix *Mix) SetOwnPlace() {

	breakHere := false

	for chain := range mix.ChainMatrix {

		for m := range mix.ChainMatrix[chain] {

			if bytes.Equal(mix.ChainMatrix[chain][m].PubKey[:], mix.RecvPubKey[:]) {

				// If we found this mix' place in the
				// chain matrix, set values and signal
				// to break from loops.
				mix.OwnChain = chain
				mix.OwnIndex = m

				if m == 0 {
					mix.IsEntry = true
				} else if m == (len(mix.ChainMatrix[chain]) - 1) {
					mix.IsExit = true
				}

				breakHere = true
				break
			}
		}

		if breakHere {
			break
		}
	}
}

// AddCoverMsgsToPool ensures that a reasonable
// (usually, #clients / 100) amount of generated
// cover messages is prepopulated in the message
// pool of each mix. We aim to thwart n - 1 attacks
// by choosing forward batch messages uniformly
// at random from that pool with the exception of
// old messages.
func (mix *Mix) AddCoverMsgsToPool(initFirst bool, numClients int, numSamples int) error {

	mixPoolToInit := mix.NextPoolMix
	exitPoolToInit := mix.NextPoolExit

	if initFirst {
		mixPoolToInit = mix.FirstPoolMix
		exitPoolToInit = mix.FirstPoolExit
	}

	// Number of mixes in own cascade until exit.
	numMixesToEnd := len(mix.ChainMatrix[mix.OwnChain]) - (mix.OwnIndex + 1)

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
			// cover message directly to respective pool.
			exitPoolToInit = append(exitPoolToInit, &convoExitMsg)

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

			// Add layered ConvoMixMsg to respective pool.
			mixPoolToInit = append(mixPoolToInit, &convoMixMsg)
		}
	}

	return nil
}

// InitNewRound on mixes takes care of moving
// message pools from previous rounds to higher
// delay slots and prepares the first delay slot
// for incoming messages.
func (mix *Mix) InitNewRound() error {

	numClients := len(mix.KnownClients)
	numSamples := numClients / 100
	if numSamples < 100 {
		numSamples = numClients
	}
	maxNumMsg := numClients + numSamples + 10

	mix.muFirstPool = &sync.Mutex{}

	if mix.IsExit {

		// Prepare pools for conversation messages
		// at exit mixes.
		mix.FirstPoolExit = make([]*rpc.ConvoExitMsg, 0, maxNumMsg)
		mix.SecPoolExit = make([]*rpc.ConvoExitMsg, 0, (2 * (maxNumMsg / 3)))
		mix.ThirdPoolExit = make([]*rpc.ConvoExitMsg, 0, (maxNumMsg / 2))
		mix.NextPoolExit = make([]*rpc.ConvoExitMsg, 0, maxNumMsg)
		mix.OutPoolExit = make([]*rpc.ConvoExitMsg, 0, maxNumMsg)

	} else {

		// Prepare pools for conversation messages
		// at entry or common mixes.
		mix.FirstPoolMix = make([]*rpc.ConvoMixMsg, 0, maxNumMsg)
		mix.SecPoolMix = make([]*rpc.ConvoMixMsg, 0, (2 * (maxNumMsg / 3)))
		mix.ThirdPoolMix = make([]*rpc.ConvoMixMsg, 0, (maxNumMsg / 2))
		mix.NextPoolMix = make([]*rpc.ConvoMixMsg, 0, maxNumMsg)
		mix.OutPoolMix = make([]*rpc.ConvoMixMsg, 0, maxNumMsg)
	}

	// Add basis of cover traffic to first pool.
	err := mix.AddCoverMsgsToPool(true, numClients, numSamples)
	if err != nil {
		return err
	}

	// Add basis of cover traffic to upcoming pool.
	err = mix.AddCoverMsgsToPool(false, numClients, numSamples)
	if err != nil {
		return err
	}

	// Start timer.
	mix.RoundTimer = time.NewTimer(RoundTime)

	return nil
}

func (mix *Mix) SendOutMsg(msgChan chan *rpc.ConvoExitMsg) {

	for msg := range msgChan {

		// Extract network address of outside client.
		addr, err := msg.ClientAddr()
		if err != nil {
			fmt.Printf("Failed to extract client address of outgoing message: %v\n", err)
		}

		// Connect to client node.
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			fmt.Printf("Failed sending message to final client '%s': %v\n", msg.ClientAddr, err)
			continue
		}

		// Send message content and close connection.
		fmt.Fprintf(conn, "%v\n", msg.Content)
		conn.Close()
	}
}

func (mix *Mix) RotateRoundState() error {

	numClients := len(mix.KnownClients)
	numSamples := numClients / 100
	if numSamples < 100 {
		numSamples = numClients
	}

	// Use channel later to communicate end
	// of cover traffic generation in background.
	coverGenErrChan := make(chan error)

	if mix.IsExit {

		// Prepare parallel sending of outgoing
		// messages to clients.
		msgChan := make(chan *rpc.ConvoExitMsg, 10000)
		for i := 0; i < 10000; i++ {
			go mix.SendOutMsg(msgChan)
		}

		// Acquire lock on first pool.
		mix.muFirstPool.Lock()

		// Rotate first to second, second to third,
		// and third to outgoing message pool.
		mix.OutPoolExit = mix.ThirdPoolExit
		mix.ThirdPoolExit = mix.SecPoolExit
		mix.SecPoolExit = mix.FirstPoolExit

		// Rotate prepared background message pool
		// prepopulated with cover messages to
		// first slot.
		mix.FirstPoolExit = mix.NextPoolExit

		// Unlock first pool so that the regular
		// message handlers can continue to insert
		// mix messages.
		mix.muFirstPool.Unlock()

		go func(numClients int, numSamples int) {

			// Add basis of cover traffic to background
			// pool that will become the first pool next
			// round rotation.
			err := mix.AddCoverMsgsToPool(false, numClients, numSamples)
			if err != nil {
				coverGenErrChan <- err
			}

			coverGenErrChan <- nil

		}(numClients, numSamples)

		// Hand over outgoing messages to goroutines
		// performing the actual sending.
		for i := range mix.OutPoolExit {
			msgChan <- mix.OutPoolExit[i]
		}
		close(msgChan)

	} else {

		// Acquire lock on first pool.
		mix.muFirstPool.Lock()

		// Rotate first to second, second to third,
		// and third to outgoing message pool.
		mix.OutPoolMix = mix.ThirdPoolMix
		mix.ThirdPoolMix = mix.SecPoolMix
		mix.SecPoolMix = mix.FirstPoolMix

		// Rotate prepared background message pool
		// prepopulated with cover messages to
		// first slot.
		mix.FirstPoolMix = mix.NextPoolMix

		// Unlock first pool so that the regular
		// message handlers can continue to insert
		// mix messages.
		mix.muFirstPool.Unlock()

		go func(numClients int, numSamples int) {

			// Add basis of cover traffic to background
			// pool that will become the first pool next
			// round rotation.
			err := mix.AddCoverMsgsToPool(false, numClients, numSamples)
			if err != nil {
				coverGenErrChan <- err
			}

			coverGenErrChan <- nil

		}(numClients, numSamples)
	}

	// Wait for cover traffic generation to finish.
	err := <-coverGenErrChan
	if err != nil {
		return err
	}

	return nil
}

// AddConvoMsg enables a client to deliver
// a conversation message to an entry mix.
func (mix *Mix) AddConvoMsg(call rpc.Mix_addConvoMsg) error {

	// Extract convo message to append to
	// mix node's message pools from request.
	convoMsgRaw, err := call.Params.Msg()
	if err != nil {
		call.Results.SetStatus(1)
		return err
	}

	// Acknowledge client.
	call.Results.SetStatus(0)

	// Prepare byte slice to fit message.
	// TODO: Fix size.
	convoMsgBytes := make([]byte, 500)

	// Extract public key used during encryption
	// of onionized message from convo message.
	pubKey := new([32]byte)
	pubKeyRaw, err := convoMsgRaw.PubKey()
	if err != nil {
		return err
	}
	copy(pubKey[:], pubKeyRaw)

	// Extract nonce used during encryption
	// of onionized message from convo message.
	nonce := new([24]byte)
	nonceRaw, err := convoMsgRaw.Nonce()
	if err != nil {
		return err
	}
	copy(nonce[:], nonceRaw)

	// Extract packed forward message from
	// received convo message.
	encConvoMsg, err := convoMsgRaw.Content()
	if err != nil {
		return err
	}

	// Decrypt message content.
	out, ok := box.Open(convoMsgBytes, encConvoMsg, nonce, pubKey, mix.RecvSecKey)
	if !ok {
		return fmt.Errorf("Decryption of conversation message failed\n")
	}

	fmt.Printf("AddConvoMsg: out of box.Open: %v\n", out)

	// Unmarshal packed convo message from
	// byte slice to Cap'n Proto message.
	convoMsgProto, err := capnp.Unmarshal(convoMsgBytes)
	if err != nil {
		return err
	}

	// Convert raw Cap'n Proto message to the
	// conversation message we defined.
	convoMsg, err := rpc.ReadRootConvoMixMsg(convoMsgProto)
	if err != nil {
		return err
	}

	// Lock first message pool, append
	// message, and unlock.
	mix.muFirstPool.Lock()
	mix.FirstPoolMix = append(mix.FirstPoolMix, &convoMsg)
	mix.muFirstPool.Unlock()

	return nil
}

// AddBatch performs the necessary steps for
// a mix node to forward a batch of messages
// to a subsequent mix node.
func (mix *Mix) AddBatch(call rpc.Mix_addBatch) error {

	data, err := call.Params.Batch()
	if err != nil {
		return err
	}

	fmt.Printf("\nAddBatch req: '%#v'\n", data)

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
		fmt.Printf("Error waiting for public connection to complete: %v\n", err)
	}
}
