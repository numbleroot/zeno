package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/numbleroot/zeno/rpc"
	"golang.org/x/crypto/nacl/box"
	capnp "zombiezen.com/go/capnproto2"
)

// InitNewRound on clients bootstraps key
// material and auxiliary data to be used
// in the upcoming round.
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
func OnionEncryptAndSend(retChan chan *ClientSendResult, sender string, text []byte, recipient string, chain []*FlatEndpoint, keyState []*OnionKeyState) {

	// Pad recipient to fixed length.
	recipientPadded := make([]byte, 32)
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

	// Create new EntryConvoMsg and insert values.
	onionMsg, err := rpc.NewRootEntryConvoMsg(protoMsgSeg)
	if err != nil {
		fmt.Printf("Failed creating new root EntryConvoMsg: %v\n", err)
		retChan <- &ClientSendResult{Status: 1, Time: -1}
		return
	}
	onionMsg.SetPubKeyOrAddr(keyState[0].PubKey[:])
	onionMsg.SetContent(encMsg)

	// Set sender of message to this client's
	// name in order for the entry mix to ensure
	// constant-bandwidth traffic.
	// TODO: Might be inappropriate to use name
	//       of client as identifier.
	onionMsg.SetSender(sender)

	// Connect to this cascade's entry mix.
	connWrite, err := tls.DialWithDialer(&net.Dialer{
		Deadline: time.Now().Add(RoundTime),
	}, "tcp", chain[0].Addr, &tls.Config{
		RootCAs:            &chain[0].PubCertPool,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519},
	})
	if err != nil {
		fmt.Printf("Failed connecting to entry mix %s via TLS: %v\n", chain[0].Addr, err)
		retChan <- &ClientSendResult{Status: 1, Time: -1}
		return
	}
	defer connWrite.Close()
	connRead := bufio.NewReader(connWrite)

	// Encode message and send it via stream.
	err = capnp.NewEncoder(connWrite).Encode(protoMsg)
	if err != nil {
		fmt.Printf("Failed to encode and send onion-encrypted message to entry mix %s: %v\n", chain[0].Addr, err)
		retChan <- &ClientSendResult{Status: 1, Time: -1}
		return
	}

	// Save send time.
	sendTime := time.Now().UnixNano()

	// Wait for acknowledgement.
	statusRaw, err := connRead.ReadString('\n')
	if err != nil {
		fmt.Printf("Failed to receive response to delivery of conversation message: %v\n", err)
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

	msgID := 1
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
					Name:        cl.CurCascadesMatrix[chain][mix].Name,
					Addr:        cl.CurCascadesMatrix[chain][mix].Addr,
					PubKey:      *cl.CurCascadesMatrix[chain][mix].PubKey,
					PubCertPool: *cl.CurCascadesMatrix[chain][mix].PubCertPool,
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

		// Bytes [0, 25] will be conversation ID.
		copy(msg[:], fmt.Sprintf("%s=>%s", cl.Name, cl.Partner.Name))

		// Bytes [26, 30] are the message sequence number.
		copy(msg[26:], fmt.Sprintf("%05d", msgID))

		// Bytes [31, MsgLength] are the actual message.
		copy(msg[31:], Msg)

		retChan := make(chan *ClientSendResult)

		// In parallel, reverse onion-encrypt the
		// message and send to all entry mixes.
		for chain := range cascadesMatrix {
			go OnionEncryptAndSend(retChan, cl.Name, msg, cl.Partner.Addr, cascadesMatrix[chain], keyState[chain])
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
					fmt.Fprintf(cl.MetricsPipe, "send;%s %s\n", msg[:26], msg[26:31])
					fmt.Fprintf(cl.MetricsPipe, "send;%d\n", retState.Time)
				}
			}
		}

		if retState.Status == 0 {
			time.Sleep(ClientsWaitBetweenMsgsSuccess)
		} else {
			time.Sleep(ClientsWaitBetweenMsgsRetry)
		}
	}
}

// HandleExitMixConn handles the TLS connection
// from one exit mix to this client.
func (cl *Client) HandleExitMixConn(connWrite net.Conn) {

	decoder := gob.NewDecoder(connWrite)
	failedDecodingMsg := 0

	for {

		select {
		case <-cl.SigCloseEpoch:

			fmt.Printf("\nSIG @ CLIENT HANDLE EXIT MIX! Closing epoch\n")

			// In case the current epoch is wrapping
			// up, return from this function to stop
			// handling messages.
			return

		default:

			// Wait for a message.
			var msg []byte
			err := decoder.Decode(&msg)
			if err != nil {

				fmt.Printf("Failed decoding incoming message from %s: %v\n", connWrite.RemoteAddr(), err)

				if failedDecodingMsg >= 20 {
					fmt.Printf("Exit mix at %s seems to have disappeared, closing connection.\n", connWrite.RemoteAddr())
					connWrite.Close()
					return
				}

				if err.Error() == "EOF" {
					failedDecodingMsg++
				}

				continue
			}

			// Save receive time.
			recvTime := time.Now().UnixNano()

			// Reset decoding error counter.
			failedDecodingMsg = 0

			cl.muNewMsg.Lock()

			// Do not consider cover traffic messages.
			if !bytes.Equal(msg[0:28], []byte("COVER MESSAGE PLEASE DISCARD")) {

				// Check dedup map for previous encounter.
				_, seenBefore := cl.RecvdMsgs[string(msg[:31])]
				if !seenBefore {

					// Update message tracker.
					cl.RecvdMsgs[string(msg[:31])] = true

					// Print received message.
					fmt.Printf("@%s> %s\n", msg[26:31], msg[31:])

					// Send prepared measurement log line to
					// collector sidecar.
					if cl.IsEval {
						fmt.Fprintf(cl.MetricsPipe, "recv;%d\n", recvTime)
						fmt.Fprintf(cl.MetricsPipe, "recv;%s %s\n", string(msg[:26]), string(msg[26:31]))
					}
				}
			}

			// When we hit the number of messages set to
			// receive, decrease shutdown grace period counter.
			if len(cl.RecvdMsgs) >= cl.NumMsgToRecv {
				cl.DoneCounter--
			}

			// As soon as the grace period counter has reached
			// zero, send out metrics stop signal and exit.
			if cl.DoneCounter == 0 {

				if cl.IsEval {
					fmt.Fprintf(cl.MetricsPipe, "done\n")
				}

				fmt.Printf("Number of messages to receive reached (want: %d, saw: %d), exiting.\n", cl.NumMsgToRecv, len(cl.RecvdMsgs))
				cl.muNewMsg.Unlock()

				time.Sleep(2 * time.Second)
				os.Exit(0)
			}

			cl.muNewMsg.Unlock()
		}
	}
}

// RunRounds executes all relevant components
// of regular mix-net rounds on a client node
// during one epoch's time.
func (cl *Client) RunRounds() {

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

			// Wait for incoming connection on public socket.
			connWrite, err := cl.PubListener.Accept()
			if err != nil {
				fmt.Printf("Accepting connection from an exit mix failed: %v\n", err)
				continue
			}

			go cl.HandleExitMixConn(connWrite)
		}
	}
}
