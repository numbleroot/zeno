package mixnet

import (
	"bytes"
	"context"
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

// ReconnectToSuccessor connects from one mix
// to its successor mix in the cascade.
func (mix *Mix) ReconnectToSuccessor() error {

	if !mix.IsExit {

		// Connect to successor mix over TCP.
		conn, err := net.Dial("tcp", string(mix.ChainMatrix[mix.OwnChain][(mix.OwnIndex+1)].Addr))
		if err != nil {
			return err
		}

		// Wrap TCP connection in Cap'n Proto RPC.
		connRCP := capnprpc.NewConn(capnprpc.StreamTransport(conn))

		// Bundle RPC connection in struct on
		// which to call methods later on.
		mix.Successor = &rpc.Mix{
			Client: connRCP.Bootstrap(context.Background()),
		}
	}

	return nil
}

// AddCoverMsgsToPool ensures that a reasonable
// (usually, #clients / 100) amount of generated
// cover messages is prepopulated in the message
// pool of each mix. We aim to thwart n - 1 attacks
// by choosing forward batch messages uniformly
// at random from that pool with the exception of
// old messages.
func (mix *Mix) AddCoverMsgsToPool(initFirst bool, numClients int, numSamples int) error {

	poolToInit := mix.NextPool
	if initFirst {
		poolToInit = mix.FirstPool
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
		convoExitMsg, err := rpc.NewRootConvoMsg(protoMsgSeg)
		if err != nil {
			return err
		}
		convoExitMsg.SetPubKeyOrAddr(mix.KnownClients[chosen].Addr)
		convoExitMsg.SetContent(msgPadded[:])

		if mix.IsExit {

			// This is an exit mix, thus simply add the
			// cover message directly to respective pool.
			poolToInit = append(poolToInit, &convoExitMsg)

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
				convoMixMsg, err := rpc.NewRootConvoMsg(protoMsgSeg)
				if err != nil {
					fmt.Printf("Failed creating new root ConvoMixMsg: %v\n", err)
					os.Exit(1)
				}
				convoMixMsg.SetPubKeyOrAddr(keys[mix].PubKey[:])
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
			convoMixMsg, err := rpc.NewRootConvoMsg(protoMsgSeg)
			if err != nil {
				fmt.Printf("Failed creating new root ConvoMixMsg: %v\n", err)
				os.Exit(1)
			}
			convoMixMsg.SetPubKeyOrAddr(keys[0].PubKey[:])
			convoMixMsg.SetContent(encMsg)

			// Add layered ConvoMixMsg to respective pool.
			poolToInit = append(poolToInit, &convoMixMsg)
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

	// Prepare pools for conversation messages.
	mix.muFirstPool = &sync.Mutex{}
	mix.FirstPool = make([]*rpc.ConvoMsg, 0, maxNumMsg)
	mix.SecPool = make([]*rpc.ConvoMsg, 0, (2 * (maxNumMsg / 3)))
	mix.ThirdPool = make([]*rpc.ConvoMsg, 0, (maxNumMsg / 2))
	mix.NextPool = make([]*rpc.ConvoMsg, 0, maxNumMsg)
	mix.OutPool = make([]*rpc.ConvoMsg, 0, maxNumMsg)

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

// SendOutMsg is the goroutine worker function
// that expects messages via a channel and sends
// them to the final outside client.
func (mix *Mix) SendOutMsg(msgChan chan *rpc.ConvoMsg) {

	for exitMsg := range msgChan {

		// Extract network address of outside client.
		addr, err := exitMsg.PubKeyOrAddr()
		if err != nil {
			fmt.Printf("Failed to extract client address of outgoing message: %v\n", err)
			continue
		}

		// Extract message to send.
		msg, err := exitMsg.Content()
		if err != nil {
			fmt.Printf("Failed to extract outgoing message: %v\n", err)
			continue
		}

		// Connect to client node.
		conn, err := net.Dial("tcp", string(addr))
		if err != nil {
			fmt.Printf("Failed sending message to final client '%s': %v\n", addr, err)
			continue
		}

		// Send message content and close connection.
		fmt.Fprintf(conn, "%v\n", msg)
		conn.Close()
	}
}

// RotateRoundState performs the necessary
// operations to switch from one round to
// the next. This involves appropriately
// rotating message pools, forwarding the
// batch of messages chosen in this round,
// and preparing the subsequent replacement
// message pool with cover messages.
func (mix *Mix) RotateRoundState() error {

	numClients := len(mix.KnownClients)
	numSamples := numClients / 100
	if numSamples < 100 {
		numSamples = numClients
	}

	// Use channel later to communicate end
	// of cover traffic generation in background.
	coverGenErrChan := make(chan error)

	// Acquire lock on first pool.
	mix.muFirstPool.Lock()

	// Rotate first to second, second to third,
	// and third to outgoing message pool.
	mix.OutPool = mix.ThirdPool
	mix.ThirdPool = mix.SecPool
	mix.SecPool = mix.FirstPool

	// Rotate prepared background message pool
	// prepopulated with cover messages to
	// first slot.
	mix.FirstPool = mix.NextPool

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

	if mix.IsExit {

		// Prepare parallel sending of outgoing
		// messages to clients.
		msgChan := make(chan *rpc.ConvoMsg, 10000)
		for i := 0; i < 10000; i++ {
			go mix.SendOutMsg(msgChan)
		}

		// Hand over outgoing messages to goroutines
		// performing the actual sending.
		for i := range mix.OutPool {
			msgChan <- mix.OutPool[i]
		}
		close(msgChan)

	} else {

		// Send batch of conversation messages
		// to subsequent mix in cascade.
		status, err := mix.Successor.AddBatch(context.Background(), func(p rpc.Mix_addBatch_Params) error {

			// Create new batch and set its messages.
			batch, err := p.NewBatch()
			if err != nil {
				return err
			}

			msgs, err := batch.NewMsgs(int32(len(mix.OutPool)))
			if err != nil {
				return err
			}

			for i := range mix.OutPool {
				msgs.Set(i, *mix.OutPool[i])
			}

			return nil

		}).Struct()
		if err != nil {
			return err
		}

		if status.Status() != 0 {
			return fmt.Errorf("successor mix returned non-zero response: %d", status.Status())
		}
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
	encConvoMsgRaw, err := call.Params.Msg()
	if err != nil {

		fmt.Printf("Error extracting AddConvoMsg request parameters: %v\n", err)
		call.Results.SetStatus(1)

		return nil
	}

	// Extract public key used during encryption
	// of onionized message from convo message.
	pubKey := new([32]byte)
	pubKeyRaw, err := encConvoMsgRaw.PubKeyOrAddr()
	if err != nil {

		fmt.Printf("Error extracting public key from request: %v\n", err)
		call.Results.SetStatus(1)

		return err
	}
	copy(pubKey[:], pubKeyRaw)

	// Extract packed forward message from
	// received convo message.
	encConvoMsg, err := encConvoMsgRaw.Content()
	if err != nil {

		fmt.Printf("Error extracting message from request: %v\n", err)
		call.Results.SetStatus(1)

		return err
	}

	// Extract nonce used during encryption
	// of onionized message from convo message.
	nonce := new([24]byte)
	copy(nonce[:], encConvoMsg[:24])

	// Decrypt message content.
	convoMsgRaw, ok := box.Open(nil, encConvoMsg[24:], nonce, pubKey, mix.RecvSecKey)
	if !ok {

		fmt.Printf("Error decrypting received message.\n")
		call.Results.SetStatus(1)

		return nil
	}

	// Unmarshal packed convo message from
	// byte slice to Cap'n Proto message.
	convoMsgProto, err := capnp.Unmarshal(convoMsgRaw)
	if err != nil {

		fmt.Printf("Error unmarshaling received message: %v\n", err)
		call.Results.SetStatus(1)

		return err
	}

	// Convert raw Cap'n Proto message to the
	// conversation message we defined.
	convoMsg, err := rpc.ReadRootConvoMsg(convoMsgProto)
	if err != nil {

		fmt.Printf("Error reading conversation message from received message: %v\n", err)
		call.Results.SetStatus(1)

		return err
	}

	// Lock first message pool, append
	// message, and unlock.
	mix.muFirstPool.Lock()
	mix.FirstPool = append(mix.FirstPool, &convoMsg)
	mix.muFirstPool.Unlock()

	// Acknowledge client.
	call.Results.SetStatus(0)

	return nil
}

// AddBatch performs the necessary steps for
// a mix node to forward a batch of messages
// to a subsequent mix node.
func (mix *Mix) AddBatch(call rpc.Mix_addBatch) error {

	batch, err := call.Params.Batch()
	if err != nil {

		fmt.Printf("Error extracting batch of mix messages from request: %v\n", err)
		call.Results.SetStatus(1)

		return err
	}

	fmt.Printf("\nAddBatch req: '%#v'\n", batch)

	// Acknowledge predecessor mix.
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
