package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"os"
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

// OnionEncryptAndSend is the dedicated goroutine
// run in parallel for all chains in the chain matrix.
// A client uses this function to reverse-encrypt
// a message for the assigned chain and send it off
// to each respective entry mix.
func (cl *Client) OnionEncryptAndSend(text []byte, recipient string, chain int) {

	// Pad message to fixed length.
	msgPadded := new([360]byte)
	copy(msgPadded[:], text)

	// Create empty Cap'n Proto messsage.
	protoMsg, protoMsgSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		fmt.Printf("Failed creating empty Cap'n Proto message: %v\n", err)
		os.Exit(1)
	}

	// Fill message with used values.
	convoMsg, err := rpc.NewRootConvoMsg(protoMsgSeg)
	if err != nil {
		fmt.Printf("Failed creating new root ConvoMsg: %v\n", err)
		os.Exit(1)
	}
	convoMsg.SetPubKeyOrAddr([]byte(recipient))
	convoMsg.SetContent(msgPadded[:])

	// Marshal final convoMsg to byte slice.
	origMsg, err := protoMsg.MarshalPacked()
	if err != nil {
		fmt.Printf("Failed marshalling ConvoMsg to []byte: %v\n", err)
		os.Exit(1)
	}

	var status string

	for status != "0" {

		msg := origMsg

		// Going through chains in reverse, encrypt the
		// message symmetrically as content. Pack into
		// ConvoMsg and prepend with used public key.
		for mix := (len(cl.ChainMatrix[chain]) - 1); mix > 0; mix-- {

			// Use precomputed nonce and shared key to
			// symmetrically encrypt the current message.
			encMsg := box.SealAfterPrecomputation(cl.CurRound[chain][mix].Nonce[:], msg, cl.CurRound[chain][mix].Nonce, cl.CurRound[chain][mix].SymKey)

			// Create empty Cap'n Proto messsage.
			protoMsg, protoMsgSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
			if err != nil {
				fmt.Printf("Failed creating empty Cap'n Proto message: %v\n", err)
				os.Exit(1)
			}

			// Create new ConvoMsg and insert values.
			onionMsg, err := rpc.NewRootConvoMsg(protoMsgSeg)
			if err != nil {
				fmt.Printf("Failed creating new root ConvoMsg: %v\n", err)
				os.Exit(1)
			}
			onionMsg.SetPubKeyOrAddr(cl.CurRound[chain][mix].PubKey[:])
			onionMsg.SetContent(encMsg)

			// Marshal final ConvoMsg to byte slice.
			msg, err = protoMsg.MarshalPacked()
			if err != nil {
				fmt.Printf("Failed marshalling ConvoMsg to []byte: %v\n", err)
				os.Exit(1)
			}
		}

		// Use precomputed nonce and shared key to
		// symmetrically encrypt the current message.
		encMsg := box.SealAfterPrecomputation(cl.CurRound[chain][0].Nonce[:], msg, cl.CurRound[chain][0].Nonce, cl.CurRound[chain][0].SymKey)

		// Create empty Cap'n Proto messsage.
		protoMsg, protoMsgSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
		if err != nil {
			fmt.Printf("Failed creating empty Cap'n Proto message: %v\n", err)
			os.Exit(1)
		}

		// Create new ConvoMsg and insert values.
		onionMsg, err := rpc.NewRootConvoMsg(protoMsgSeg)
		if err != nil {
			fmt.Printf("Failed creating new root ConvoMsg: %v\n", err)
			os.Exit(1)
		}
		onionMsg.SetPubKeyOrAddr(cl.CurRound[chain][0].PubKey[:])
		onionMsg.SetContent(encMsg)

		// Connect to this cascade's entry mix
		// via TLS-over-QUIC.
		session, err := quic.DialAddr(string(cl.ChainMatrix[chain][0].Addr), &tls.Config{
			RootCAs:            cl.ChainMatrix[chain][0].PubCertPool,
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS13,
			CurvePreferences:   []tls.CurveID{tls.X25519},
		}, nil)
		if err != nil {
			fmt.Printf("Failed connecting to entry mix of cascade %d via QUIC: %v\n", chain, err)
			os.Exit(1)
		}

		// Upgrade session to blocking stream.
		stream, err := session.OpenStreamSync()
		if err != nil {
			fmt.Printf("Failed to upgrade QUIC session to stream: %v\n", err)
			os.Exit(1)
		}

		// Create buffered I/O reader from connection.
		connRead := bufio.NewReader(stream)

		// Encode message in packed format and send it via stream.
		err = capnp.NewPackedEncoder(stream).Encode(protoMsg)
		if err != nil {
			fmt.Printf("Failed to encode and send onion-encrypted message to entry mix %s: %v\n", cl.ChainMatrix[chain][0].Addr, err)
			os.Exit(1)
		}

		// Wait for acknowledgement.
		status, err = connRead.ReadString('\n')
		if err != nil {
			fmt.Printf("Failed to receive response to delivery of conversation message: %v\n", err)
			os.Exit(1)
		}

		// Clean up received status string.
		status = strings.ToLower(strings.Trim(status, "\n "))

		if status != "0" {
			time.Sleep((((RoundTime) / 2) + (50 * time.Millisecond)))
		}
	}

	cl.SendWG.Done()
}

// SendMsg is the main user input loop on a
// zeno client. It accepts lines typed by the user,
// times and pads them properly, onion-encrypts
// and transmits them to each cascade. If no
// user message is available in a round, cover
// traffic is encrypted and sent in its place.
func (cl *Client) SendMsg() {

	var partner string
	var convoID string

	for i := range cl.Clients {

		if cl.Clients[i].Addr == cl.PubLisAddr {

			// If own index is even, partnering client
			// is the next one. If it is odd, the partner
			// is the preceding client.
			if (i % 2) == 0 {
				partner = cl.Clients[(i + 1)].Addr
				convoID = fmt.Sprintf("%06d => %06d;", i, (i + 1))
			} else {
				partner = cl.Clients[(i - 1)].Addr
				convoID = fmt.Sprintf("%06d => %06d;", i, (i - 1))
			}

			fmt.Printf("%s's partner is %s, convoID: '%s'\n", cl.Clients[i].Addr, partner, convoID)
		}
	}

	var msgID uint16
	for msgID = 0; msgID <= 65535; msgID++ {

		// Prepare the needed new round state,
		// primarily including fresh key material.
		err := cl.InitNewRound()
		if err != nil {
			fmt.Printf("Initiating new round failed: %v\n", err)
			os.Exit(1)
		}

		// Prepare message to send.
		msg := new([360]byte)

		// First 17 bytes will be conversation ID.
		copy(msg[:], convoID)

		// Bytes 18 - 23 are the message sequence number.
		copy(msg[17:], fmt.Sprintf("%05d;", msgID))

		// Bytes 24 - 360 are the actual message.
		copy(msg[23:], Msg)

		cl.SendWG.Add(len(cl.ChainMatrix))

		// In parallel, reverse onion-encrypt the
		// message and send to all entry mixes.
		for chain := range cl.ChainMatrix {
			go cl.OnionEncryptAndSend(msg[:], partner, chain)
		}

		// Wait for all entry messages to be sent.
		cl.SendWG.Wait()
	}
}
