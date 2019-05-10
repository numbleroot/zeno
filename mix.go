package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/numbleroot/zeno/rpc"
	"golang.org/x/crypto/nacl/box"
	capnp "zombiezen.com/go/capnproto2"
)

// SetOwnPlace sets important indices into
// cascades matrix for a just elected mix.
func (mix *Mix) SetOwnPlace() {

	breakHere := false

	for chain := range mix.CurCascadesMatrix {

		for m := range mix.CurCascadesMatrix[chain] {

			if bytes.Equal(mix.CurCascadesMatrix[chain][m].PubKey[:], mix.CurRecvPubKey[:]) {

				// If we found this mix' place in the
				// cascades matrix, set values and signal
				// to break from loops.
				mix.OwnChain = chain
				mix.OwnIndex = m

				if m == 0 {
					mix.IsEntry = true
				} else if m == (len(mix.CurCascadesMatrix[chain]) - 1) {
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

	fmt.Printf("%s:  OwnChain=%v, OwnIndex=%v, IsEntry=%v, IsExit=%v\n", mix.PubLisAddr, mix.OwnChain, mix.OwnIndex, mix.IsEntry, mix.IsExit)
}

// ReconnectToSuccessor establishes a connection
// from a non-exit mix to its successor mix.
func (mix *Mix) ReconnectToSuccessor() error {

	if !mix.IsExit {

		// Extract next-in-cascade mix.
		successor := mix.CurCascadesMatrix[mix.OwnChain][(mix.OwnIndex + 1)]

		// Prepare TLS config to use for QUIC.
		tlsConf := &tls.Config{
			RootCAs:            successor.PubCertPool,
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS13,
			CurvePreferences:   []tls.CurveID{tls.X25519},
		}

		// Dial successor mix via TLS-over-QUIC.
		session, err := quic.DialAddr(successor.Addr, tlsConf, nil)
		for err != nil {

			fmt.Printf("Reconnecting to successor failed with: %v\n", err)
			fmt.Printf("Trying again...\n")

			session, err = quic.DialAddr(successor.Addr, tlsConf, nil)
		}

		fmt.Printf("Success! Reconnected to %s!\n", successor.Addr)

		// Upgrade session to blocking stream.
		stream, err := session.OpenStreamSync()
		if err != nil {
			return err
		}

		mix.Successor = stream
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

	// Number of mixes in own cascade until exit.
	numMixesToEnd := len(mix.CurCascadesMatrix[mix.OwnChain]) - (mix.OwnIndex + 1)

	// Randomly select k clients to generate
	// cover messages to.
	for i := 0; i < numSamples; i++ {

		// Select a user index uniformly at random.
		chosenBig, err := rand.Int(rand.Reader, big.NewInt(int64(numClients)))
		if err != nil {
			return err
		}
		chosen := int(chosenBig.Int64())

		// Prepare cover message.
		msgPadded := make([]byte, MsgLength)
		_, err = io.ReadFull(rand.Reader, msgPadded)
		if err != nil {
			return err
		}
		copy(msgPadded[:], "COVER MESSAGE PLEASE DISCARD")

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
		convoExitMsg.SetPubKeyOrAddr([]byte(mix.CurClients[chosen].Addr))
		convoExitMsg.SetContent(msgPadded[:])

		if mix.IsExit {

			// This is an exit mix, thus simply add the
			// cover message directly to respective pool.
			if initFirst {

				// If we are manipulating the first pool which
				// is shared, we have to acquire the lock first.
				mix.muAddMsgs.Lock()
				mix.FirstPool = append(mix.FirstPool, &convoExitMsg)
				mix.muAddMsgs.Unlock()

			} else {
				mix.NextPool = append(mix.NextPool, &convoExitMsg)
			}

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
				box.Precompute(keys[otherMix].SymKey, mix.CurCascadesMatrix[mix.OwnChain][origIdx].PubKey, msgSecKey)
			}

			// Marshal final ConvoExitMsg to byte slice.
			msg, err := protoMsg.Marshal()
			if err != nil {
				return err
			}

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
			if initFirst {

				// If we are manipulating the first pool which
				// is shared, we have to acquire the lock first.
				mix.muAddMsgs.Lock()
				mix.FirstPool = append(mix.FirstPool, &convoMixMsg)
				mix.muAddMsgs.Unlock()

			} else {
				mix.NextPool = append(mix.NextPool, &convoMixMsg)
			}
		}
	}

	return nil
}

// InitNewRound on mixes takes care of moving
// message pools from previous rounds to higher
// delay slots and prepares the first delay slot
// for incoming messages.
func (mix *Mix) InitNewRound() error {

	numClients := len(mix.CurClients)
	numSamples := numClients / 100
	if numSamples < 100 {
		numSamples = numClients
	}
	maxNumMsg := numClients + numSamples + 10

	// Prepare map to keep track of the clients
	// that have already participated in a round.
	mix.ClientsSeen = make(map[string]bool)

	// Prepare pools for conversation messages.
	mix.FirstPool = make([]*rpc.ConvoMsg, 0, maxNumMsg)
	mix.SecPool = make([]*rpc.ConvoMsg, 0, maxNumMsg)
	mix.ThirdPool = make([]*rpc.ConvoMsg, 0, maxNumMsg)
	mix.NextPool = make([]*rpc.ConvoMsg, 0, maxNumMsg)
	mix.OutPool = make([]*rpc.ConvoMsg, 0, maxNumMsg)

	// Prepare mutex restricting manipulation
	// access to all shared round state elements.
	mix.muAddMsgs = &sync.Mutex{}

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
	mix.RoundTicker = time.NewTicker(RoundTime)

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

		// Find local endpoint mapped to address.
		clIdx, found := mix.CurClientsByAddress[string(addr)]
		if !found {
			fmt.Printf("Client to contact not known (no TLS certificate available).\n")
			continue
		}
		client := mix.CurClients[clIdx]

		// Extract message to send.
		msg, err := exitMsg.Content()
		if err != nil {
			fmt.Printf("Failed to extract outgoing message: %v\n", err)
			continue
		}

		// Connect to client node.
		session, err := quic.DialAddr(string(addr), &tls.Config{
			RootCAs:            client.PubCertPool,
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS13,
			CurvePreferences:   []tls.CurveID{tls.X25519},
		}, nil)
		if err != nil {

			if err.Error() != "NO_ERROR" {
				fmt.Printf("Could not connect to client %s via QUIC: %v\n", string(addr), err)
			}

			continue
		}

		// Upgrade session to blocking stream.
		stream, err := session.OpenStreamSync()
		if err != nil {

			if err.Error() != "NO_ERROR" {
				fmt.Printf("Failed to upgrade QUIC session to stream: %v\n", err)
			}

			continue
		}

		encoder := gob.NewEncoder(stream)

		// Send message content.
		err = encoder.Encode(msg)
		if err != nil {

			if err.Error() != "NO_ERROR" {
				fmt.Printf("Failed sending message to client %s: %v\n", addr, err)
			}

			continue
		}

		// Close connection to client.
		err = stream.Close()
		if err != nil {

			if err.Error() != "NO_ERROR" {
				fmt.Printf("Error while closing stream to %s: %v\n", addr, err)
			}
		}
	}
}

// RotateRoundState performs the necessary
// operations to switch from one round to
// the next. This involves appropriately
// rotating message pools, forwarding the
// batch of messages chosen in this round,
// and preparing the subsequent replacement
// message pool with cover messages.
func (mix *Mix) RotateRoundState() {

	for {

		select {
		case <-mix.SigCloseEpoch:

			fmt.Printf("\nSIG @ ROTATE! Closing epoch\n")

			// In case the current epoch is wrapping
			// up, return from this function to stop
			// rotating rounds.
			return

		default:

			<-mix.RoundTicker.C

			numClients := len(mix.CurClients)
			numSamples := numClients / 100
			if numSamples < 100 {
				numSamples = numClients
			}
			maxNumMsg := numClients + numSamples + 10

			// Use channel later to communicate end
			// of cover traffic generation in background.
			coverGenErrChan := make(chan error)

			// Acquire lock on first pool.
			mix.muAddMsgs.Lock()

			if mix.IsEval {
				// If we are conducting an evaluation,
				// send pool sizes to collector sidecar.
				fmt.Fprintf(mix.MetricsPipe, "1st:%d 2nd:%d 3rd:%d out:%d\n", len(mix.FirstPool), len(mix.SecPool), len(mix.ThirdPool), len(mix.OutPool))
			}

			// Reset participation tracking map.
			mix.ClientsSeen = make(map[string]bool)

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
			mix.muAddMsgs.Unlock()

			go func(numClients int, numSamples int) {

				// Create new empty slice for upcoming round.
				mix.NextPool = make([]*rpc.ConvoMsg, 0, maxNumMsg)

				// Add basis of cover traffic to background
				// pool that will become the first pool next
				// round rotation.
				err := mix.AddCoverMsgsToPool(false, numClients, numSamples)
				if err != nil {
					coverGenErrChan <- err
				}

				coverGenErrChan <- nil

			}(numClients, numSamples)

			// Truly randomly permute messages in SecPool.
			for i := (len(mix.SecPool) - 1); i > 0; i-- {

				// Generate new CSPRNG number smaller than i.
				jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i)))
				if err != nil {
					fmt.Printf("Rotating round state failed: %v\n", err)
					os.Exit(1)
				}
				j := int(jBig.Int64())

				// Swap places i and j in second pool.
				mix.SecPool[i], mix.SecPool[j] = mix.SecPool[j], mix.SecPool[i]
			}

			// Choose variance value randomly.
			varianceBig, err := rand.Int(rand.Reader, big.NewInt(BatchSizeVariance))
			if err != nil {
				fmt.Printf("Rotating round state failed: %v\n", err)
				os.Exit(1)
			}
			variance := int(varianceBig.Int64())

			// Calculate appropriate pool indices. Start is set to half
			// of the SecPool's length minus the randomly chosen variance
			// value to introduce some randomness. End is set to include
			// all elements from start until the end of the pool.
			end := len(mix.SecPool)
			start := (end / 2) - variance
			if start < 0 {
				start = 0
			}

			// Append last (end - start) messages from SecPool to OutPool.
			mix.OutPool = append(mix.OutPool, mix.SecPool[start:end]...)

			// Shrink size of SecPool by (end - start).
			mix.SecPool = mix.SecPool[:start]

			end = len(mix.ThirdPool)
			start = (end / 2) - variance
			if start < 0 {
				start = 0
			}

			// Append last (end - start) messages from ThirdPool to OutPool.
			mix.OutPool = append(mix.OutPool, mix.ThirdPool[start:end]...)

			// Shrink size of ThirdPool by (end - start).
			mix.ThirdPool = mix.ThirdPool[:start]

			// Randomly permute OutPool once more to destroy any potential
			// for linking the order in the outgoing message batch to a
			// message's relationship to one of the pools.
			for i := (len(mix.OutPool) - 1); i > 0; i-- {

				// Generate new CSPRNG number smaller than i.
				jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i)))
				if err != nil {
					fmt.Printf("Rotating round state failed: %v\n", err)
					os.Exit(1)
				}
				j := int(jBig.Int64())

				// Swap places i and j in outgoing message pool.
				mix.OutPool[i], mix.OutPool[j] = mix.OutPool[j], mix.OutPool[i]
			}

			if mix.IsExit {

				// Prepare parallel sending of outgoing
				// messages to clients.
				msgChan := make(chan *rpc.ConvoMsg, 500)
				for i := 0; i < 500; i++ {
					go mix.SendOutMsg(msgChan)
				}

				// Hand over outgoing messages to goroutines
				// performing the actual sending.
				for i := range mix.OutPool {
					msgChan <- mix.OutPool[i]
				}
				close(msgChan)

			} else {

				// Create new empty Cap'n Proto message.
				protoMsg, protoMsgSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
				if err != nil {
					fmt.Printf("Rotating round state failed: %v\n", err)
					os.Exit(1)
				}

				// Create new empty batch message.
				batch, err := rpc.NewRootBatch(protoMsgSeg)
				if err != nil {
					fmt.Printf("Rotating round state failed: %v\n", err)
					os.Exit(1)
				}

				// Prepare a list of messages of fitting size.
				msgs, err := batch.NewMsgs(int32(len(mix.OutPool)))
				if err != nil {
					fmt.Printf("Rotating round state failed: %v\n", err)
					os.Exit(1)
				}

				for i := range mix.OutPool {
					msgs.Set(i, *mix.OutPool[i])
				}

				// Encode message in packed mode and send it via stream.
				err = capnp.NewPackedEncoder(mix.Successor).Encode(protoMsg)
				if err != nil {

					if err.Error() != "NO_ERROR" {
						fmt.Printf("Rotating round state failed: %v\n", err)
						os.Exit(1)
					}
				}
			}

			// Wait for cover traffic generation to finish.
			err = <-coverGenErrChan
			if err != nil {
				fmt.Printf("Rotating round state failed: %v\n", err)
				os.Exit(1)
			}
		}
	}
}

// AddConvoMsg enables a client to deliver
// a conversation message to an entry mix.
func (mix *Mix) AddConvoMsg(connWrite quic.Stream, sender string) {

	// Decode message in packed format from stream.
	encConvoMsgWire, err := capnp.NewPackedDecoder(connWrite).Decode()
	if err != nil {

		if err.Error() != "NO_ERROR" {
			fmt.Printf("Error decoding packed message from client: %v\n", err)
			fmt.Fprintf(connWrite, "1\n")
		}

		return
	}

	// Extract contained encrypted conversation message.
	encConvoMsgRaw, err := rpc.ReadRootConvoMsg(encConvoMsgWire)
	if err != nil {

		fmt.Printf("Failed reading root conversation message from client message: %v\n", err)
		fmt.Fprintf(connWrite, "1\n")

		return
	}

	// Extract public key used during encryption
	// of onionized message from convo message.
	pubKey := new([32]byte)
	pubKeyRaw, err := encConvoMsgRaw.PubKeyOrAddr()
	if err != nil {

		fmt.Printf("Failed to extract public key from conversation message: %v\n", err)
		fmt.Fprintf(connWrite, "1\n")

		return
	}
	copy(pubKey[:], pubKeyRaw)

	// Extract forward message from
	// received convo message.
	encConvoMsg, err := encConvoMsgRaw.Content()
	if err != nil {

		fmt.Printf("Failed to extract content from conversation message: %v\n", err)
		fmt.Fprintf(connWrite, "1\n")

		return
	}

	// Calculate expected length of message.
	expLen := MsgLength + ((LenCascade - 1) * MsgCascadeOverhead) + MsgExitOverhead

	// Enforce message to be of correct length.
	if len(encConvoMsg) != expLen {

		fmt.Printf("Message received from %s was of unexpected size %d bytes (expected %d), discarding.\n", sender, len(encConvoMsg), expLen)
		fmt.Fprintf(connWrite, "1\n")

		return
	}

	// Extract nonce used during encryption
	// of onionized message from convo message.
	nonce := new([24]byte)
	copy(nonce[:], encConvoMsg[:24])

	// Decrypt message content.
	convoMsgRaw, ok := box.Open(nil, encConvoMsg[24:], nonce, pubKey, mix.CurRecvSecKey)
	if !ok {

		fmt.Printf("Failed to decrypt received conversation message by client %s\n", sender)
		fmt.Fprintf(connWrite, "1\n")

		return
	}

	// Unmarshal convo message from byte
	// slice to Cap'n Proto message.
	convoMsgProto, err := capnp.Unmarshal(convoMsgRaw)
	if err != nil {

		fmt.Printf("Error unmarshaling received contained message by client %s: %v\n", sender, err)
		fmt.Fprintf(connWrite, "1\n")

		return
	}

	// Convert raw Cap'n Proto message to the
	// conversation message we defined.
	convoMsg, err := rpc.ReadRootConvoMsg(convoMsgProto)
	if err != nil {

		fmt.Printf("Error reading conversation message from contained message by client %s: %v\n", sender, err)
		fmt.Fprintf(connWrite, "1\n")

		return
	}

	mix.muAddMsgs.Lock()
	defer mix.muAddMsgs.Unlock()

	// Check participation map for an entry for
	// this sender address.
	alreadySentInRound, _ := mix.ClientsSeen[sender]
	if alreadySentInRound {

		// Respond to client with 'wait' code.
		fmt.Fprintf(connWrite, "2\n")

		return
	}

	mix.ClientsSeen[sender] = true
	mix.FirstPool = append(mix.FirstPool, &convoMsg)

	// Acknowledge client.
	fmt.Fprintf(connWrite, "0\n")
}

// HandleBatchMsgs performs the necessary steps of
// a mix node forwarding a batch of messages to a
// subsequent mix node.
func (mix *Mix) HandleBatchMsgs(connWrite quic.Stream, sender string) error {

	// Ensure only the predecessor mix is able to
	// take up this mix node's compute ressources.
	if sender != strings.Split(mix.CurCascadesMatrix[mix.OwnChain][(mix.OwnIndex-1)].Addr, ":")[0] {
		return fmt.Errorf("node at %s tried to send a message batch but we expect predecessor %s", sender, mix.CurCascadesMatrix[mix.OwnChain][(mix.OwnIndex-1)].Addr)
	}

	for {

		select {
		case <-mix.SigCloseEpoch:

			fmt.Printf("\nSIG @ BATCH! Closing epoch\n")

			// In case the current epoch is wrapping
			// up, return from this function to stop
			// processing non-entry mix messages.
			return nil

		default:

			// Decode message batch in packed format from stream.
			batchProto, err := capnp.NewPackedDecoder(connWrite).Decode()
			if err != nil {

				if err.Error() == "NO_ERROR" {
					return nil
				}

				return err
			}

			// Read batch from wire message.
			batch, err := rpc.ReadRootBatch(batchProto)
			if err != nil {
				return err
			}

			// Retrieve list of messages from batch struct.
			encConvoMsgsRaw, err := batch.Msgs()
			if err != nil {
				return err
			}

			numMsgs := encConvoMsgsRaw.Len()

			for i := 0; i < numMsgs; i++ {

				encConvoMsgRaw := encConvoMsgsRaw.At(i)

				// Extract public key used during encryption
				// of onionized message from convo message.
				pubKey := new([32]byte)
				pubKeyRaw, err := encConvoMsgRaw.PubKeyOrAddr()
				if err != nil {
					return err
				}
				copy(pubKey[:], pubKeyRaw)

				// Extract forward message from
				// received convo message.
				encConvoMsg, err := encConvoMsgRaw.Content()
				if err != nil {
					return err
				}

				// Calculate expected length of message.
				expLen := MsgLength + ((LenCascade - mix.OwnIndex - 1) * MsgCascadeOverhead) + MsgExitOverhead

				// Enforce message to be of correct length.
				if len(encConvoMsg) != expLen {
					return fmt.Errorf("message received from %s was of unexpected size %d bytes (expected %d), discarding", sender, len(encConvoMsg), expLen)
				}

				// Extract nonce used during encryption
				// of onionized message from convo message.
				nonce := new([24]byte)
				copy(nonce[:], encConvoMsg[:24])

				// Decrypt message content.
				convoMsgRaw, ok := box.Open(nil, encConvoMsg[24:], nonce, pubKey, mix.CurRecvSecKey)
				if !ok {
					return err
				}

				// Unmarshal convo message from byte
				// slice to Cap'n Proto message.
				convoMsgProto, err := capnp.Unmarshal(convoMsgRaw)
				if err != nil {
					return err
				}

				// Convert raw Cap'n Proto message to the
				// conversation message we defined.
				convoMsg, err := rpc.ReadRootConvoMsg(convoMsgProto)
				if err != nil {
					return err
				}

				// Lock first message pool, append
				// message, and unlock.
				mix.muAddMsgs.Lock()
				mix.FirstPool = append(mix.FirstPool, &convoMsg)
				mix.muAddMsgs.Unlock()
			}
		}
	}
}

// RunRounds executes all relevant components
// of regular mix-net rounds on a mix node
// during one epoch's time.
func (mix *Mix) RunRounds() {

	// Determine this mix node's place in cascades matrix.
	mix.SetOwnPlace()

	// Connect to each mix node's successor mix.
	err := mix.ReconnectToSuccessor()
	if err != nil {
		fmt.Printf("Failed to connect to mix node's successor mix: %v\n", err)
		os.Exit(1)
	}

	// Initialize state on mix for upcoming round.
	err = mix.InitNewRound()
	if err != nil {
		fmt.Printf("Failed generating cover traffic messages for pool: %v\n", err)
		os.Exit(1)
	}

	// Run mix node part of mix-net round
	// protocol in background.
	go mix.RotateRoundState()

	if mix.IsEntry {

		for {

			select {
			case <-mix.SigCloseEpoch:

				fmt.Printf("\nSIG @ ENTRY! Closing epoch\n")

				// In case the current epoch is wrapping
				// up, return from this function to stop
				// executing this epoch's rounds.
				return

			default:

				// Wait for incoming connections on public socket.
				session, err := mix.PubListener.Accept()
				if err != nil {
					fmt.Printf("Public connection error: %v\n", err)
					continue
				}

				// Upgrade session to stream.
				connWrite, err := session.AcceptStream()
				if err != nil {
					fmt.Printf("Failed accepting incoming stream: %v\n", err)
					continue
				}

				sender := strings.Split(session.RemoteAddr().String(), ":")[0]

				// At entry mixes we only receive single
				// conversation messages from clients.
				// We handle them directly.
				go mix.AddConvoMsg(connWrite, sender)
			}
		}
	} else {

		// Wait for incoming connections on public socket.
		session, err := mix.PubListener.Accept()
		if err != nil {
			fmt.Printf("Public connection error: %v\n", err)
			os.Exit(1)
		}

		// Upgrade session to stream.
		connWrite, err := session.AcceptStream()
		if err != nil {
			fmt.Printf("Failed accepting incoming stream: %v\n", err)
			os.Exit(1)
		}

		sender := strings.Split(session.RemoteAddr().String(), ":")[0]

		// At non-entry mixes we only expect to receive
		// Cap'n Proto batch messages.
		err = mix.HandleBatchMsgs(connWrite, sender)
		if err != nil {
			fmt.Printf("Failed to handle batch messages: %v\n", err)
			os.Exit(1)
		}
	}
}
