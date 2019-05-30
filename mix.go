package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

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

	fmt.Printf("%s@%s:  OwnChain=%v, OwnIndex=%v, IsEntry=%v, IsExit=%v\n", mix.Name, mix.PubLisAddr, mix.OwnChain, mix.OwnIndex, mix.IsEntry, mix.IsExit)
}

// ReconnectToSuccessor establishes a connection
// from a non-exit mix to its successor mix.
func (mix *Mix) ReconnectToSuccessor() error {

	// Extract next-in-cascade mix.
	successor := mix.CurCascadesMatrix[mix.OwnChain][(mix.OwnIndex + 1)]

	// Prepare TLS config.
	tlsConf := &tls.Config{
		RootCAs:            successor.PubCertPool,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519},
	}

	// Dial successor mix.
	conn, err := tls.Dial("tcp", successor.Addr, tlsConf)
	for err != nil {

		// If attempt at reaching succeeding mix failed,
		// wait a short amount of time and try again.
		fmt.Printf("Reconnecting to successor failed with (will try again): %v\n", err)
		time.Sleep(150 * time.Millisecond)

		conn, err = tls.Dial("tcp", successor.Addr, tlsConf)
	}

	fmt.Printf("Success! Reconnected to %s!\n", successor.Addr)

	mix.Successor = conn

	return nil
}

// SendMsgToClient is the dedicated process tasked
// with first connecting to one specific client via
// TLS-over-TCP and second to send the client all
// messages passed in via the supplied channel.
func (mix *Mix) SendMsgToClient(client *Endpoint, msgChan chan []byte) {

	tlsConf := &tls.Config{
		RootCAs:            client.PubCertPool,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519},
	}

	// Connect to client node.
Reconnect:
	connWrite, err := tls.Dial("tcp", client.Addr, tlsConf)
	for err != nil {

		fmt.Printf("Exit mix unable to reach %s (will try again)\n", client.Addr)

		// If attempt at reaching client failed,
		// wait a short amount of time and try again.
		time.Sleep(150 * time.Millisecond)

		connWrite, err = tls.Dial("tcp", client.Addr, tlsConf)
	}
	encoder := gob.NewEncoder(connWrite)

	for msg := range msgChan {

		// Send message to client via previously
		// established connection.
		err := encoder.Encode(msg)
		if err != nil {

			fmt.Printf("Failed to send msg to client %s: %v\n", client.Addr, err)

			if strings.Contains(err.Error(), "connection reset by peer") ||
				strings.Contains(err.Error(), "broken pipe") {

				fmt.Printf("Detected broken pipe to client %s. Will reconnect.\n", client.Addr)
				goto Reconnect
			}
		}
	}
}

// ReconnectToClients quickly creates a channel
// that a dedicated sending goroutine acts upon
// into which outgoing messages are placed by
// ForwardMsgToSender.
func (mix *Mix) ReconnectToClients() {

	mix.CurClientsByAddress = make(map[string]chan []byte)

	for i := range mix.CurClients {

		// Create a channel that messages can be
		// passed over intended for delivery to
		// this specific client.
		clientConnChan := make(chan []byte)

		// Stash channel in map that allows SendOutMsg
		// to find the goroutine tasked with sending
		// messages to clients quickly.
		mix.CurClientsByAddress[mix.CurClients[i].Addr] = clientConnChan

		go mix.SendMsgToClient(mix.CurClients[i], clientConnChan)
	}
}

// ForwardMsgToSender hands off an outgoing message
// to the routine responsible for that client based
// on the recipient address attached to it.
func (mix *Mix) ForwardMsgToSender(msgChan chan *rpc.ConvoMsg) {

	for exitMsg := range msgChan {

		// Extract network address of outside client.
		addrRaw, err := exitMsg.PubKeyOrAddr()
		if err != nil {
			fmt.Printf("Failed to extract client address of outgoing message: %v\n", err)
			continue
		}
		addr := strings.Split(string(addrRaw), "#")[0]

		// Extract message to send.
		msg, err := exitMsg.Content()
		if err != nil {
			fmt.Printf("Failed to extract outgoing message: %v\n", err)
			continue
		}

		// Pass message to correct client channel.
		mix.CurClientsByAddress[addr] <- msg
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

	// Randomly select k clients to generate
	// cover messages to.
	for i := 0; i < numSamples; i++ {

		// Select a user index uniformly at random.
		chosenBig, err := rand.Int(rand.Reader, big.NewInt(int64(numClients)))
		if err != nil {
			return err
		}
		chosen := int(chosenBig.Int64())

		// Pad recipient to fixed length.
		recipientPadded := make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, recipientPadded)
		if err != nil {
			return err
		}
		copy(recipientPadded[:], mix.CurClients[chosen].Addr)
		recipientPadded[len(mix.CurClients[chosen].Addr)] = '#'

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
		convoExitMsg.SetPubKeyOrAddr(recipientPadded)
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

			// This is not an exit mix, thus we want
			// to onion-encrypt. Prepare key material.

			// Number of mixes in own cascade until exit.
			numMixesToEnd := len(mix.CurCascadesMatrix[mix.OwnChain]) - (mix.OwnIndex + 1)

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

// CreateEvalDoneBatch has the purpose of constructing
// a Batch of size one with the single message telling
// the succeeding mix to complete the evaluation.
func (mix *Mix) CreateEvalDoneBatch() (*capnp.Message, error) {

	// Create new empty Cap'n Proto message.
	protoMsg, protoMsgSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, err
	}

	// Create new empty batch message.
	batch, err := rpc.NewRootBatch(protoMsgSeg)
	if err != nil {
		return nil, err
	}

	// Prepare empty recipient and stop message.
	emptyRecipient := make([]byte, 32)
	evalDoneMsg := make([]byte, MsgLength)
	copy(evalDoneMsg[:], "EVAL DONE")

	// Create empty Cap'n Proto messsage.
	_, protoMsgSeg, err = capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, err
	}

	// Fill stopper message.
	evalDoneConvoMsg, err := rpc.NewRootConvoMsg(protoMsgSeg)
	if err != nil {
		return nil, err
	}
	evalDoneConvoMsg.SetPubKeyOrAddr(emptyRecipient)
	evalDoneConvoMsg.SetContent(evalDoneMsg[:])

	// Prepare a list of messages size one.
	msgs, err := batch.NewMsgs(1)
	if err != nil {
		return nil, err
	}

	// Add as only message the stop message.
	msgs.Set(0, evalDoneConvoMsg)

	return protoMsg, nil
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

			// Move round counter to next round.
			mix.RoundCounter++
			if (mix.KillMixesInRound != -1) && (mix.RoundCounter >= mix.KillMixesInRound) &&
				(mix.OwnChain > 0) && (mix.OwnIndex == 1) {

				// Crash second-in-cascade mixes in all but first cascade
				// when configured round to crash was reached.
				fmt.Printf("This is a second-in-cascade mix in a non-first cascade - exiting!\n")
				os.Exit(0)
			}

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
				fmt.Fprintf(mix.MetricsPipe, "%d 1st:%d 2nd:%d 3rd:%d out:%d\n", mix.RoundCounter,
					len(mix.FirstPool), len(mix.SecPool), len(mix.ThirdPool), len(mix.OutPool))

				if mix.IsEntry && len(mix.ClientsSeen) < 10 {

					fmt.Printf("len(ClientsSeen) = %d\n", len(mix.ClientsSeen))
					for i := range mix.ClientsSeen {
						fmt.Printf("\t%s => %v\n", i, mix.ClientsSeen[i])
					}
					fmt.Println()
				}

				if mix.IsEntry && (len(mix.ClientsSeen) == 0) {

					// In case the clients have ceased sending due to
					// having seen the amount of messages they were
					// configured to await, signal collector sidecar
					// that we are done sending metrics.
					fmt.Printf("Entry mix detected no further client messages, completing metrics collection.\n")
					fmt.Fprintf(mix.MetricsPipe, "done\n")

					// Prepare message batch of size one with the
					// sole purpose of telling downstream mixes
					// to complete their evaluation and exit.
					protoMsg, err := mix.CreateEvalDoneBatch()
					if err != nil {
						fmt.Printf("Preparing evaluation done batch failed: %v\n", err)
						os.Exit(1)
					}

					// Encode message and send it via stream.
					err = capnp.NewEncoder(mix.Successor).Encode(protoMsg)
					if err != nil {
						fmt.Printf("Failed sending evaluation done batch to downstream mix: %v\n", err)
					} else {
						fmt.Printf("Entry mix signaled downstream mix to stop evaluating.\n")
					}

					fmt.Printf("Entry mix has detected end of evaluation. Exiting.\n")
					os.Exit(0)
				}
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
				msgChan := make(chan *rpc.ConvoMsg, len(mix.OutPool))
				for i := 0; i < len(mix.OutPool); i++ {
					go mix.ForwardMsgToSender(msgChan)
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

				// Encode message and send it via stream.
				err = capnp.NewEncoder(mix.Successor).Encode(protoMsg)
				if err != nil {

					if strings.Contains(err.Error(), "broken pipe") {
						continue
					}

					fmt.Printf("Rotating round state failed: %v\n", err)
					os.Exit(1)
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
func (mix *Mix) AddConvoMsg(connWrite net.Conn, sender string) {

	// Decode message from stream.
	encConvoMsgWire, err := capnp.NewDecoder(connWrite).Decode()
	if err != nil {
		fmt.Printf("Error decoding message from client: %v\n", err)
		fmt.Fprintf(connWrite, "1\n")
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

	// Enforce message to be of correct length.
	expLen := MsgLength + ((LenCascade - 1) * MsgCascadeOverhead) + MsgExitOverhead
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
func (mix *Mix) HandleBatchMsgs(connWrite net.Conn, sender string) error {

	if sender != strings.Split(mix.CurCascadesMatrix[mix.OwnChain][(mix.OwnIndex-1)].Addr, ":")[0] {

		// Ensure only the predecessor mix is able to
		// take up this mix node's compute resources.
		return fmt.Errorf("node at %s tried to send a message batch but we expect predecessor %s", sender,
			mix.CurCascadesMatrix[mix.OwnChain][(mix.OwnIndex-1)].Addr)
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

			// Decode message batch from stream.
			batchProto, err := capnp.NewDecoder(connWrite).Decode()
			if err != nil {
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

				if mix.IsEval && (numMsgs == 1) && bytes.HasPrefix(encConvoMsg, []byte("EVAL DONE")) {

					// Special case: the preceding mix signaled
					// that the evaluation has completed.

					fmt.Printf("Non-entry mix received stop message, completing metrics collection.\n")
					fmt.Fprintf(mix.MetricsPipe, "done\n")

					// Prepare message batch of size one with the
					// sole purpose of telling downstream mixes
					// to complete their evaluation and exit.
					protoMsg, err := mix.CreateEvalDoneBatch()
					if err != nil {
						return err
					}

					// Encode message and send it via stream.
					err = capnp.NewEncoder(mix.Successor).Encode(protoMsg)
					if err != nil {
						return err
					}

					fmt.Printf("Non-entry mix has detected end of evaluation and sent all signals. Exiting.\n")
					os.Exit(0)
				}

				// Enforce message to be of correct length.
				expLen := MsgLength + ((LenCascade - mix.OwnIndex - 1) * MsgCascadeOverhead) + MsgExitOverhead
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

	// Connect to all known clients.
	if mix.IsExit {
		mix.ReconnectToClients()
	} else {

		// Connect to each mix node's successor mix.
		err := mix.ReconnectToSuccessor()
		if err != nil {
			fmt.Printf("Failed to connect to mix node's successor mix: %v\n", err)
			os.Exit(1)
		}
	}

	// Initialize state on mix for upcoming round.
	err := mix.InitNewRound()
	if err != nil {
		fmt.Printf("Failed generating cover traffic messages for pool: %v\n", err)
		os.Exit(1)
	}

	if mix.IsEval {

		// If we are conducting an evaluation, send pool
		// size for first round to collector sidecar. For
		// subsequent rounds, RotateRoundState will take
		// care of sending out the metrics.
		fmt.Fprintf(mix.MetricsPipe, "%d 1st:%d 2nd:%d 3rd:%d out:%d\n", mix.RoundCounter,
			len(mix.FirstPool), len(mix.SecPool), len(mix.ThirdPool), len(mix.OutPool))
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
				connWrite, err := mix.PubListener.Accept()
				if err != nil {
					fmt.Printf("Accepting connection from a client failed: %v\n", err)
					continue
				}

				sender := strings.Split(connWrite.RemoteAddr().String(), ":")[0]

				// At entry mixes we only receive single
				// conversation messages from clients.
				// We handle them directly.
				go mix.AddConvoMsg(connWrite, sender)
			}
		}
	} else {

		// Wait for incoming connections on public socket.
		connWrite, err := mix.PubListener.Accept()
		if err != nil {
			fmt.Printf("Accepting connection from a fellow mix failed: %v\n", err)
			os.Exit(1)
		}

		sender := strings.Split(connWrite.RemoteAddr().String(), ":")[0]

		// At non-entry mixes we only expect to receive
		// Cap'n Proto batch messages.
		err = mix.HandleBatchMsgs(connWrite, sender)
		if err != nil {
			fmt.Printf("Failed to handle batch messages: %v\n", err)
			os.Exit(1)
		}
	}
}
