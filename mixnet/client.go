package mixnet

import (
	"bufio"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/nacl/box"

	"github.com/numbleroot/zeno/rpc"
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
func (cl *Client) OnionEncryptAndSend(text string, recipient string, chain int) {

	// Pad message to fixed length.
	msgPadded := new([280]byte)
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
	msg, err := protoMsg.Marshal()
	if err != nil {
		fmt.Printf("Failed marshalling ConvoMsg to []byte: %v\n", err)
		os.Exit(1)
	}

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
		msg, err = protoMsg.Marshal()
		if err != nil {
			fmt.Printf("Failed marshalling ConvoMsg to []byte: %v\n", err)
			os.Exit(1)
		}
	}

	// Use precomputed nonce and shared key to
	// symmetrically encrypt the current message.
	encMsg := box.SealAfterPrecomputation(cl.CurRound[chain][0].Nonce[:], msg, cl.CurRound[chain][0].Nonce, cl.CurRound[chain][0].SymKey)

	// Connect to this cascade's entry mix over TCP.
	connWrite, err := net.Dial("tcp", string(cl.ChainMatrix[chain][0].Addr))
	if err != nil {
		fmt.Printf("Failed connecting to entry mix of cascade %d: %v\n", chain, err)
		os.Exit(1)
	}
	defer connWrite.Close()

	// Create buffered I/O reader from connection.
	connRead := bufio.NewReader(connWrite)

	// Wrap TCP connection in efficient encoder
	// for transmitting structs.
	encoder := gob.NewEncoder(connWrite)

	// Encode and send conversation message to
	// this cascade's entry mix.
	err = encoder.Encode(ConvoMsg{
		PublicKey: cl.CurRound[chain][0].PubKey,
		Content:   encMsg,
	})
	if err != nil {
		fmt.Printf("Error while sending onion-encrypted message to entry mix %s: %v\n", cl.ChainMatrix[chain][0].Addr, err)
		os.Exit(1)
	}

	// Wait for acknowledgement.
	statusRaw, err := connRead.ReadString('\n')
	if err != nil {
		fmt.Printf("Failed to receive response to delivery of conversation message: %v\n", err)
		os.Exit(1)
	}

	// Parse string into slice of Endpoint.
	status := strings.ToLower(strings.Trim(statusRaw, "\n "))

	if status != "0" {
		fmt.Printf("Received error code %v from entry mix '%s'\n\n", status, cl.ChainMatrix[chain][0].Addr)
	} else {
		fmt.Printf("Successfully delivered message to entry mix '%s'\n\n", cl.ChainMatrix[chain][0].Addr)
	}

	cl.SendWG.Done()
}

// SendMsg is the main user input loop on a
// zeno client. It accepts lines typed by the user,
// times and pads them properly, onion-encrypts
// and transmits them to each cascade. If no
// user message is available in a round, cover
// traffic is encrypted and sent in its place.
func (cl *Client) SendMsg() error {

	tests := []string{
		"Good morning, New York!",
		"@$°%___!!!#### <- symbols much?",
		"lorem ipsum dolor sit cannot be missing of course",
		"TweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweet",
		"All human beings are born free and equal in dignity and rights. They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood. Everyone is entitled to all the rights and freedoms set forth in this Declaration, without distinction of any kind, such as race, colour, sex, language, religion, political or other opinion, national or social origin, property, birth or other status. Furthermore, no distinction shall be made on the basis of the political, jurisdictional or international status of the country or territory to which a person belongs, whether it be independent, trust, non-self-governing or under any other limitation of sovereignty.",
	}

	for msg := range tests {

		// Prepare the needed new round state,
		// primarily including fresh key material.
		err := cl.InitNewRound()
		if err != nil {
			return err
		}

		cl.SendWG.Add(len(cl.ChainMatrix))

		// In parallel, reverse onion-encrypt the
		// message and send to all entry mixes.
		for chain := range cl.ChainMatrix {
			go cl.OnionEncryptAndSend(tests[msg], "127.0.0.1:11111", chain)
		}

		// Wait for all entry messages to be sent.
		cl.SendWG.Wait()
	}

	return nil
}
