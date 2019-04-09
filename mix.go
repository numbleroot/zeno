package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/numbleroot/zeno/rpc"
	"golang.org/x/crypto/nacl/box"
	capnp "zombiezen.com/go/capnproto2"
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

// ReconnectToSuccessor establishes a connection
// from a non-exit mix to its successor mix.
func (mix *Mix) ReconnectToSuccessor() error {

	if !mix.IsExit {

		// Dial successor mix via TLS-over-QUIC.
		session, err := quic.DialAddr(mix.ChainMatrix[mix.OwnChain][(mix.OwnIndex+1)].Addr, &tls.Config{
			RootCAs:            mix.ChainMatrix[mix.OwnChain][(mix.OwnIndex + 1)].PubCertPool,
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS13,
			CurvePreferences:   []tls.CurveID{tls.X25519},
		}, nil)
		if err != nil {
			return err
		}

		fmt.Printf("Connected to successor!\n")

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

		// Prepare cover message.
		// TODO: Think hard about fill-up with random bytes again.
		//       Any attacker advantage if we only use zeros to fill up?
		msgPadded := new([280]byte)
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
		convoExitMsg.SetPubKeyOrAddr([]byte(mix.KnownClients[mix.ChooseClients[chosen]].Addr))
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
				box.Precompute(keys[otherMix].SymKey, mix.ChainMatrix[mix.OwnChain][origIdx].PubKey, msgSecKey)
			}

			// Marshal final ConvoExitMsg to byte slice.
			msg, err := protoMsg.MarshalPacked()
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
				msg, err = protoMsg.MarshalPacked()
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

	numClients := len(mix.KnownClients)
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
		client, found := mix.KnownClients[string(addr)]
		if !found {
			fmt.Printf("Client to contact not known (no TLS certificate available).\n")
			continue
		}

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
			fmt.Printf("Could not connect to client via QUIC: %v\n", err)
			continue
		}
		defer session.Close()

		// Upgrade session to blocking stream.
		stream, err := session.OpenStreamSync()
		if err != nil {
			fmt.Printf("Failed to upgrade QUIC session to stream: %v\n", err)
			continue
		}
		defer stream.Close()

		encoder := gob.NewEncoder(stream)

		// Send message content and close connection.
		err = encoder.Encode(msg)
		if err != nil {
			fmt.Printf("Failed sending message to client '%s': %v\n", addr, err)
			continue
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

		<-mix.RoundTicker.C

		mix.printPools()

		numClients := len(mix.KnownClients)
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

		fmt.Printf("[ROTATE] A\n")

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

		fmt.Printf("[ROTATE] B\n")

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

		fmt.Printf("[ROTATE] C\n")

		if mix.IsExit {

			fmt.Printf("[ROTATE] D\n")

			// Prepare parallel sending of outgoing
			// messages to clients.
			msgChan := make(chan *rpc.ConvoMsg, 10000)
			for i := 0; i < 10000; i++ {
				go mix.SendOutMsg(msgChan)
			}

			fmt.Printf("[ROTATE] E\n")

			// Hand over outgoing messages to goroutines
			// performing the actual sending.
			for i := range mix.OutPool {
				msgChan <- mix.OutPool[i]
			}
			fmt.Printf("[ROTATE] F\n")
			close(msgChan)

		} else {

			fmt.Printf("[ROTATE] G\n")

			protoMsg, protoMsgSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
			if err != nil {
				fmt.Printf("Rotating round state failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("[ROTATE] I\n")

			batch, err := rpc.NewBatch(protoMsgSeg)
			if err != nil {
				fmt.Printf("Rotating round state failed: %v\n", err)
				os.Exit(1)
			}

			msgs, err := batch.NewMsgs(int32(len(mix.OutPool)))
			if err != nil {
				fmt.Printf("Rotating round state failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("[ROTATE] J\n")

			for i := range mix.OutPool {
				msgs.Set(i, *mix.OutPool[i])
			}

			data, err := protoMsg.MarshalPacked()
			if err != nil {
				fmt.Printf("Rotating round state failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Marshaled batch of length: %d and num msgs: %d\n", len(data), msgs.Len())
			fmt.Printf("[ROTATE] K\n")

			// Create buffered I/O reader from connection.
			connRead := bufio.NewReader(mix.Successor)

			fmt.Printf("Opened synchronous stream!\n")

			// Send length of byte slice that will follow.
			fmt.Fprintf(mix.Successor, "%d\n", len(data))

			fmt.Printf("[ROTATE] L\n")

			// Send marshaled batch.
			fmt.Fprintf(mix.Successor, "%v", data)

			fmt.Printf("[ROTATE] M\n")

			// Expect status response.
			status, err := connRead.ReadString('\n')
			if err != nil {
				fmt.Printf("Rotating round state failed: %v\n", err)
				os.Exit(1)
			}
			status = strings.ToLower(strings.Trim(status, "\n "))

			if status != "0" {
				fmt.Printf("Rotating round state failed: successor mix returned non-zero response: %s\n", status)
				os.Exit(1)
			}
		}

		fmt.Printf("[ROTATE] K\n")

		// Wait for cover traffic generation to finish.
		err = <-coverGenErrChan
		if err != nil {
			fmt.Printf("Rotating round state failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[ROTATE] L\n")
	}
}

// AddConvoMsg enables a client to deliver
// a conversation message to an entry mix.
func (mix *Mix) AddConvoMsg(connRead *bufio.Reader, connWrite quic.Stream, sender string) {

	defer connWrite.Close()

	// Wrap connection from client in efficient
	// decoder for ConvoMsg structs.
	decoder := gob.NewDecoder(connWrite)

	// Expect to receive a ConvoMsg struct.
	encConvoMsg := &ConvoMsg{}
	err := decoder.Decode(encConvoMsg)
	if err != nil {

		fmt.Printf("Error decoding struct received from client: %v\n", err)
		fmt.Fprintf(connWrite, "%v\n", err)

		return
	}

	// Extract nonce used during encryption
	// of onionized message from convo message.
	nonce := new([24]byte)
	copy(nonce[:], encConvoMsg.Content[:24])

	// Decrypt message content.
	convoMsgRaw, ok := box.Open(nil, encConvoMsg.Content[24:], nonce, encConvoMsg.PubKey, mix.RecvSecKey)
	if !ok {
		fmt.Printf("Failed to decrypt received conversation message by client %s\n", sender)
		fmt.Fprintf(connWrite, "1\n")
		return
	}

	// Unmarshal packed convo message from
	// byte slice to Cap'n Proto message.
	convoMsgProto, err := capnp.UnmarshalPacked(convoMsgRaw)
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

	// Check participation map for an entry for
	// this sender address.
	alreadySentInRound, _ := mix.ClientsSeen[sender]
	if alreadySentInRound {

		mix.muAddMsgs.Unlock()

		// Respond to client with 'wait' code.
		fmt.Fprintf(connWrite, "2\n")

		return
	}

	mix.ClientsSeen[sender] = true
	mix.FirstPool = append(mix.FirstPool, &convoMsg)

	mix.muAddMsgs.Unlock()

	// Acknowledge client.
	fmt.Fprintf(connWrite, "0\n")
}

// HandleBatchMsgs performs the necessary steps of
// a mix node forwarding a batch of messages to a
// subsequent mix node.
func (mix *Mix) HandleBatchMsgs(connRead *bufio.Reader, connWrite quic.Stream, sender string) {

	// Ensure only the predecessor mix is able to
	// take up this mix node's compute ressources.
	if sender != mix.ChainMatrix[mix.OwnChain][(mix.OwnIndex-1)].Addr {
		fmt.Printf("Node at '%s' tried to send a message batch but we expect predecessor '%s'.\n", sender, string(mix.ChainMatrix[mix.OwnChain][(mix.OwnIndex-1)].Addr))
		return
	}

	// Extract length of byte slice required to
	// store the following message.
	lengthRaw, err := connRead.ReadString('\n')
	if err != nil {
		fmt.Printf("Failed to extract length of upcoming bytes message: %v\n", err)
		os.Exit(1)
	}
	lengthRaw = strings.ToLower(strings.Trim(lengthRaw, "\n "))

	// Convert length from string to integer.
	length, err := strconv.Atoi(lengthRaw)
	if err != nil {
		fmt.Printf("Failed to convert extracted length from string to integer: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Message about to be sent is of size '%d'\n", length)

	// Prepare slice of appropriate size.
	batchRaw := make([]byte, length)

	// Read full the prepared slice.
	_, err = io.ReadFull(connWrite, batchRaw)
	if err != nil {
		fmt.Printf("Error while reading message batch from connection: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Read message batch of size '%d' bytes from connection\n", len(batchRaw))

	batchProto, err := capnp.UnmarshalPacked(batchRaw)
	if err != nil {
		fmt.Printf("Error unmarshaling received message batch: %v\n", err)
		os.Exit(1)
	}

	batch, err := rpc.ReadRootBatch(batchProto)
	if err != nil {
		fmt.Printf("Error reading message batch from unmarshaled batch message: %v\n", err)
		os.Exit(1)
	}

	// Retrieve list of messages from batch struct.
	encConvoMsgsRaw, err := batch.Msgs()
	if err != nil {
		fmt.Printf("Error extracting envelope messages from batch: %v\n", err)
		os.Exit(1)
	}

	numMsgs := encConvoMsgsRaw.Len()

	for i := 0; i < numMsgs; i++ {

		encConvoMsgRaw := encConvoMsgsRaw.At(i)

		// Extract public key used during encryption
		// of onionized message from convo message.
		pubKey := new([32]byte)
		pubKeyRaw, err := encConvoMsgRaw.PubKeyOrAddr()
		if err != nil {
			fmt.Printf("Error extracting public key from envelope message: %v\n", err)
			os.Exit(1)
		}
		copy(pubKey[:], pubKeyRaw)

		// Extract packed forward message from
		// received convo message.
		encConvoMsg, err := encConvoMsgRaw.Content()
		if err != nil {
			fmt.Printf("Error extracting message from envelope message: %v\n", err)
			os.Exit(1)
		}

		// Extract nonce used during encryption
		// of onionized message from convo message.
		nonce := new([24]byte)
		copy(nonce[:], encConvoMsg[:24])

		// Decrypt message content.
		convoMsgRaw, ok := box.Open(nil, encConvoMsg[24:], nonce, pubKey, mix.RecvSecKey)
		if !ok {
			fmt.Printf("Error decrypting received envelope message.\n")
			os.Exit(1)
		}

		// Unmarshal packed convo message from
		// byte slice to Cap'n Proto message.
		convoMsgProto, err := capnp.UnmarshalPacked(convoMsgRaw)
		if err != nil {
			fmt.Printf("Error unmarshaling received contained message: %v\n", err)
			os.Exit(1)
		}

		// Convert raw Cap'n Proto message to the
		// conversation message we defined.
		convoMsg, err := rpc.ReadRootConvoMsg(convoMsgProto)
		if err != nil {
			fmt.Printf("Error reading conversation message from contained message: %v\n", err)
			os.Exit(1)
		}

		// Lock first message pool, append
		// message, and unlock.
		mix.muAddMsgs.Lock()
		mix.FirstPool = append(mix.FirstPool, &convoMsg)
		mix.muAddMsgs.Unlock()
	}

	// Acknowledge mix.
	fmt.Fprintf(connWrite, "0\n")
}