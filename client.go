package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/numbleroot/zeno/rpc"
	"golang.org/x/crypto/nacl/box"
	capnp "zombiezen.com/go/capnproto2"
)

// InitNewRound on clients takes care of
// rotating the current round state to be
// the previous one and bootstraps key
// material and auxiliary data for the new
// current one.
func InitNewRound(cascadesMatrix [][]*FlatEndpoint) ([][]*OnionKeyState, error) {

	// Initialize new current round state.
	keyState := make([][]*OnionKeyState, NumCascades)

	for chain := range cascadesMatrix {

		keyState[chain] = make([]*OnionKeyState, LenCascade)

		for mix := range cascadesMatrix[chain] {

			keyState[chain][mix] = &OnionKeyState{
				Nonce:  new([24]byte),
				PubKey: new([32]byte),
				SymKey: new([32]byte),
			}

			// Create new random nonce.
			_, err := io.ReadFull(rand.Reader, keyState[chain][mix].Nonce[:])
			if err != nil {
				return nil, err
			}

			// Generate public-private key pair.
			msgSecKey := new([32]byte)
			keyState[chain][mix].PubKey, msgSecKey, err = box.GenerateKey(rand.Reader)
			if err != nil {
				return nil, err
			}

			// Calculate shared key between ephemeral
			// secret key and receive public key of each mix.
			box.Precompute(keyState[chain][mix].SymKey, &cascadesMatrix[chain][mix].PubKey, msgSecKey)
		}
	}

	return keyState, nil
}

// OnionEncryptAndSend is the dedicated goroutine
// run in parallel for all chains in the cascades matrix.
// A client uses this function to reverse-encrypt
// a message for the assigned chain and send it off
// to each respective entry mix.
func OnionEncryptAndSend(retChan chan *ClientSendResult, text []byte, recipient string, chain []*FlatEndpoint, keyState []*OnionKeyState) {

	// Pad recipient to fixed length.
	recipientPadded := make([]byte, 21)
	_, err := io.ReadFull(rand.Reader, recipientPadded)
	if err != nil {
		fmt.Printf("Failed to prepare random padded recipient: %v\n", err)
		retChan <- &ClientSendResult{Status: 1, Time: -1}
		return
	}
	copy(recipientPadded[:], recipient)
	recipientPadded[len(recipient)] = '#'

	// Pad random message to fixed length.
	msgPadded := make([]byte, MsgLength)
	_, err = io.ReadFull(rand.Reader, msgPadded)
	if err != nil {
		fmt.Printf("Failed to prepare random padded message: %v\n", err)
		retChan <- &ClientSendResult{Status: 1, Time: -1}
		return
	}
	copy(msgPadded[:], text)

	// Create empty Cap'n Proto messsage.
	protoMsg, protoMsgSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		fmt.Printf("Failed creating empty Cap'n Proto message: %v\n", err)
		retChan <- &ClientSendResult{Status: 1, Time: -1}
		return
	}

	// Fill message with used values.
	convoMsg, err := rpc.NewRootConvoMsg(protoMsgSeg)
	if err != nil {
		fmt.Printf("Failed creating new root ConvoMsg: %v\n", err)
		retChan <- &ClientSendResult{Status: 1, Time: -1}
		return
	}
	convoMsg.SetPubKeyOrAddr(recipientPadded)
	convoMsg.SetContent(msgPadded[:])

	// Marshal final convoMsg to byte slice.
	msg, err := protoMsg.Marshal()
	if err != nil {
		fmt.Printf("Failed marshalling ConvoMsg to []byte: %v\n", err)
		retChan <- &ClientSendResult{Status: 1, Time: -1}
		return
	}

	// Going through chains in reverse, encrypt the
	// message symmetrically as content. Pack into
	// ConvoMsg and prepend with used public key.
	for mix := (LenCascade - 1); mix > 0; mix-- {

		// Use precomputed nonce and shared key to
		// symmetrically encrypt the current message.
		encMsg := box.SealAfterPrecomputation(keyState[mix].Nonce[:], msg, keyState[mix].Nonce, keyState[mix].SymKey)

		// Create empty Cap'n Proto messsage.
		protoMsg, protoMsgSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
		if err != nil {
			fmt.Printf("Failed creating empty Cap'n Proto message: %v\n", err)
			retChan <- &ClientSendResult{Status: 1, Time: -1}
			return
		}

		// Create new ConvoMsg and insert values.
		onionMsg, err := rpc.NewRootConvoMsg(protoMsgSeg)
		if err != nil {
			fmt.Printf("Failed creating new root ConvoMsg: %v\n", err)
			retChan <- &ClientSendResult{Status: 1, Time: -1}
			return
		}
		onionMsg.SetPubKeyOrAddr(keyState[mix].PubKey[:])
		onionMsg.SetContent(encMsg)

		// Marshal final ConvoMsg to byte slice.
		msg, err = protoMsg.Marshal()
		if err != nil {
			fmt.Printf("Failed marshalling ConvoMsg to []byte: %v\n", err)
			retChan <- &ClientSendResult{Status: 1, Time: -1}
			return
		}
	}

	// Use precomputed nonce and shared key to
	// symmetrically encrypt the current message.
	encMsg := box.SealAfterPrecomputation(keyState[0].Nonce[:], msg, keyState[0].Nonce, keyState[0].SymKey)

	// Create empty Cap'n Proto messsage.
	protoMsg, protoMsgSeg, err = capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		fmt.Printf("Failed creating empty Cap'n Proto message: %v\n", err)
		retChan <- &ClientSendResult{Status: 1, Time: -1}
		return
	}

	// Create new ConvoMsg and insert values.
	onionMsg, err := rpc.NewRootConvoMsg(protoMsgSeg)
	if err != nil {
		fmt.Printf("Failed creating new root ConvoMsg: %v\n", err)
		retChan <- &ClientSendResult{Status: 1, Time: -1}
		return
	}
	onionMsg.SetPubKeyOrAddr(keyState[0].PubKey[:])
	onionMsg.SetContent(encMsg)

	// Connect to this cascade's entry mix
	// via TLS-over-QUIC.
	session, err := quic.DialAddr(chain[0].Addr, &tls.Config{
		RootCAs:            &chain[0].PubCertPool,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519},
	}, nil)
	if err != nil {

		if err.Error() != "NO_ERROR" {
			fmt.Printf("Failed connecting to entry mix %s via QUIC: %v\n", chain[0].Addr, err)
		}

		retChan <- &ClientSendResult{Status: 1, Time: -1}
		return
	}

	// Upgrade session to blocking stream.
	stream, err := session.OpenStreamSync()
	if err != nil {

		if err.Error() != "NO_ERROR" {
			fmt.Printf("Failed to upgrade QUIC session to stream: %v\n", err)
		}

		retChan <- &ClientSendResult{Status: 1, Time: -1}
		return
	}

	// Create buffered I/O reader from connection.
	connRead := bufio.NewReader(stream)

	// Encode message and send it via stream.
	err = capnp.NewEncoder(stream).Encode(protoMsg)
	if err != nil {

		if err.Error() != "NO_ERROR" {
			fmt.Printf("Failed to encode and send onion-encrypted message to entry mix %s: %v\n", chain[0].Addr, err)
		}

		retChan <- &ClientSendResult{Status: 1, Time: -1}
		return
	}

	// Save send time.
	sendTime := time.Now().UnixNano()

	// Wait for acknowledgement.
	statusRaw, err := connRead.ReadString('\n')
	if err != nil {

		if err.Error() != "NO_ERROR" {
			fmt.Printf("Failed to receive response to delivery of conversation message: %v\n", err)
		}

		retChan <- &ClientSendResult{Status: 1, Time: -1}
		return
	}

	// Clean up and convert received status string.
	status, err := strconv.ParseUint(strings.ToLower(strings.Trim(statusRaw, "\n ")), 10, 8)
	if err != nil {
		fmt.Printf("Converting response from entry mix to number failed: %v\n", err)
		retChan <- &ClientSendResult{Status: 1, Time: -1}
		return
	}

	retChan <- &ClientSendResult{Status: uint8(status), Time: sendTime}
}

// SendMsg is the main user input loop on a
// zeno client. It accepts lines typed by the user,
// times and pads them properly, onion-encrypts
// and transmits them to each cascade. If no
// user message is available in a round, cover
// traffic is encrypted and sent in its place.
func (cl *Client) SendMsg() {

	msgID := 0
	isSecTransmission := false

	for {

		// Read-lock current cascades state.
		cl.muUpdState.RLock()

		// Check if this node is still a client.
		// If not, return from function.
		if !cl.IsClient {
			cl.muUpdState.RUnlock()
			break
		}

		// Deep-copy cascades matrix.
		cascadesMatrix := make([][]*FlatEndpoint, NumCascades)

		for chain := range cl.CurCascadesMatrix {

			cascadesMatrix[chain] = make([]*FlatEndpoint, LenCascade)

			for mix := range cl.CurCascadesMatrix[chain] {

				cascadesMatrix[chain][mix] = &FlatEndpoint{
					cl.CurCascadesMatrix[chain][mix].Addr,
					*cl.CurCascadesMatrix[chain][mix].PubKey,
					*cl.CurCascadesMatrix[chain][mix].PubCertPool,
				}
			}
		}

		// Extract values for this message transmission.
		var partner string
		var convoID string

		for i := range cl.CurClients {

			if cl.CurClients[i].Addr == cl.PubLisAddr {

				// If own index is even, partnering client
				// is the next one. If it is odd, the partner
				// is the preceding client.
				if (i % 2) == 0 {
					partner = cl.CurClients[(i + 1)].Addr
					convoID = fmt.Sprintf("%06d=>%06d", i, (i + 1))
				} else {
					partner = cl.CurClients[(i - 1)].Addr
					convoID = fmt.Sprintf("%06d=>%06d", i, (i - 1))
				}
			}
		}

		// Read-unlock state.
		cl.muUpdState.RUnlock()

		// Prepare the needed new round state,
		// primarily including fresh key material.
		keyState, err := InitNewRound(cascadesMatrix)
		if err != nil {
			cl.muUpdState.RUnlock()
			fmt.Printf("Initiating new round failed: %v\n", err)
			os.Exit(1)
		}

		// Prepare message to send.
		msg := make([]byte, MsgLength)
		_, err = io.ReadFull(rand.Reader, msg)
		if err != nil {
			fmt.Printf("Failed to prepare random original message: %v\n", err)
			os.Exit(1)
		}

		// First 14 bytes will be conversation ID.
		copy(msg[:], convoID)

		// Bytes 15 - 20 are the message sequence number.
		copy(msg[14:], fmt.Sprintf("%06d", msgID))

		// Bytes 21 - MsgLength are the actual message.
		copy(msg[20:], Msg)

		retChan := make(chan *ClientSendResult)

		// In parallel, reverse onion-encrypt the
		// message and send to all entry mixes.
		for chain := range cascadesMatrix {
			go OnionEncryptAndSend(retChan, msg, partner, cascadesMatrix[chain], keyState[chain])
		}

		succeeded := false
		var retState = &ClientSendResult{}

		for range cascadesMatrix {

			// Collect results from the individual goroutines
			// sending out the message to each entry mix.
			retState = <-retChan
			if retState.Status == 0 {
				succeeded = true
				break
			}
		}

		go func(retChan chan *ClientSendResult) {

			// Drain result state channel, such that
			// it can be used in the next loop iteration.
			for range retChan {
			}

		}(retChan)

		if succeeded {

			if isSecTransmission {

				// Increment message counter and reset
				// flag for redundant transmission.
				msgID++
				isSecTransmission = false

			} else {

				// If the first transmission was successful,
				// send message a second time (same msgID).
				isSecTransmission = true

				// In case we are evaluating this client, send
				// the measurement line to collector sidecar.
				if cl.IsEval {
					fmt.Fprintf(cl.MetricsPipe, "send;%s %d\n", msg[:20], retState.Time)
				}
			}
		}

		if retState.Status == 0 || retState.Status == 2 {
			time.Sleep(((RoundTime) / 5))
		} else {
			time.Sleep(((RoundTime) / 15))
		}
	}
}

// RunRounds executes all relevant components
// of regular mix-net rounds on a client node
// during one epoch's time.
func (cl *Client) RunRounds() {

	// Use map to deduplicate incoming messages.
	// We only forward messages to application layer
	// that we have not already passed on before.
	recvdMsgs := make(map[string]bool)

	// Handle messaging loop.
	go cl.SendMsg()

	for {

		select {
		case <-cl.SigCloseEpoch:

			fmt.Printf("\nSIG @ CLIENT RECV! Closing epoch\n")

			// In case the current epoch is wrapping
			// up, return from this function to stop
			// listening for client messages.
			return

		default:

			// Wait for incoming connections on public socket.
			session, err := cl.PubListener.Accept()
			if err != nil {

				if err.Error() != "NO_ERROR" {
					fmt.Printf("Public connection error: %v\n", err)
				}

				continue
			}

			// Upgrade session to stream.
			connWrite, err := session.AcceptStream()
			if err != nil {

				if err.Error() != "NO_ERROR" {
					fmt.Printf("Failed accepting incoming stream: %v\n", err)
				}

				continue
			}
			decoder := gob.NewDecoder(connWrite)

			// Wait for a message.
			var msg []byte
			err = decoder.Decode(&msg)
			if err != nil {

				if err.Error() != "NO_ERROR" {
					fmt.Printf("Failed decoding incoming message as slice of bytes: %v\n", err)
				}

				continue
			}

			// Save receive time.
			recvTime := time.Now().UnixNano()

			// Do not consider cover traffic messages.
			if !bytes.Equal(msg[0:28], []byte("COVER MESSAGE PLEASE DISCARD")) {

				// Check dedup map for previous encounter.
				_, seenBefore := recvdMsgs[string(msg[:20])]
				if !seenBefore {

					// Update message tracker.
					recvdMsgs[string(msg[:20])] = true

					// Finally, print received message.
					fmt.Printf("\n@%s> %s\n", msg[14:20], msg[20:])

					// Send prepared measurement log line to
					// collector sidecar.
					if cl.IsEval {
						fmt.Fprintf(cl.MetricsPipe, "recv;%s %d\n", string(msg[:20]), recvTime)
					}

					// When we hit the number of messages to
					// receive that was specified, wait and exit.
					if len(recvdMsgs) == cl.NumMsgToRecv {
						fmt.Printf("Number of messages to receive reached, exiting.\n")
						fmt.Fprint(cl.MetricsPipe, "done")
						time.Sleep(2 * time.Second)
						os.Exit(0)
					}
				}
			}
		}
	}
}
