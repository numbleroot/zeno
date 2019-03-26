package mixnet

import (
	"context"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/nacl/box"

	"github.com/numbleroot/zeno/rpc"
	capnp "zombiezen.com/go/capnproto2"
	capnprpc "zombiezen.com/go/capnproto2/rpc"
)

// ReconnectToEntries opens up new RPC connections
// over TCP to each entry mix in the chain matrix.
func (cl *Client) ReconnectToEntries() error {

	for c := range cl.EntryConns {

		// Close all entry mix connections from last epoch.
		err := cl.EntryConns[c].Client.Close()
		if err != nil {
			fmt.Printf("Error while closing old entry mix connections: %v\n", err)
		}
	}

	// Make space for the ones from this epoch.
	cl.EntryConns = make([]*rpc.Mix, len(cl.ChainMatrix))

	for chain := 0; chain < len(cl.ChainMatrix); chain++ {

		// Connect to each entry mix over TCP.
		conn, err := net.Dial("tcp", cl.ChainMatrix[chain][0].Addr)
		if err != nil {
			return err
		}

		// Wrap TCP connection in Cap'n Proto RPC.
		connRCP := capnprpc.NewConn(capnprpc.StreamTransport(conn))

		// Bundle RPC connection in struct on
		// which to call methods later on.
		entryMix := &rpc.Mix{
			Client: connRCP.Bootstrap(context.Background()),
		}

		// Stash bundle in client.
		cl.EntryConns[chain] = entryMix
	}

	fmt.Printf("Connected to entry mixes\n\n")

	return nil
}

// OnionEncryptAndSend is the dedicated goroutine
// run in parallel for all chains in the chain matrix.
// A client uses this function to reverse-encrypt
// a message for the assigned chain and send it off
// to each respective entry mix.
func (cl *Client) OnionEncryptAndSend(convoExitMsg []byte, chain int) {

	fmt.Printf("Encrypting message now\n")

	msg := convoExitMsg

	// Going through chains in reverse, encrypt
	// ConvoExitMsg symmetrically as content. Pack
	// into ConvoMixMsg and prepend with used public key.
	for mix := (len(cl.ChainMatrix[chain]) - 1); mix > 0; mix-- {

		// Use precomputed nonce and shared key to
		// symmetrically encrypt the current message.
		encMsg := box.SealAfterPrecomputation(cl.CurRound.Nonce[:], msg, cl.CurRound.Nonce, cl.CurRound.MsgKeys[chain][mix].SymKey)

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
		convoMixMsg.SetPubKey(cl.CurRound.MsgKeys[chain][mix].PubKey[:])
		convoMixMsg.SetNonce(cl.CurRound.Nonce[:])
		convoMixMsg.SetContent(encMsg)

		// Marshal final ConvoMixMsg to byte slice.
		msg, err = protoMsg.Marshal()
		if err != nil {
			fmt.Printf("Failed marshalling final ConvoMixMsg to []byte: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("len(msg) = %d\n", len(msg))
	}

	fmt.Printf("\nlen(finalMessage) = %d\n", len(msg))

	// Send final layered message to entry mix.
	status, err := cl.EntryConns[chain].AddConvoMsg(context.Background(), func(p rpc.Mix_addConvoMsg_Params) error {

		// Create new entry message and set values.
		entryConvoMixMsg, err := p.NewMsg()
		if err != nil {
			return err
		}
		entryConvoMixMsg.SetPubKey(cl.CurRound.MsgKeys[chain][0].PubKey[:])
		entryConvoMixMsg.SetNonce(cl.CurRound.Nonce[:])
		entryConvoMixMsg.SetContent(msg)

		return nil

	}).Struct()
	if err != nil {
		fmt.Printf("Error while sending onion-encrypted message to entry mix %s: %v\n", cl.ChainMatrix[chain][0].Addr, err)
	}

	if status.Status() != 0 {
		fmt.Printf("Received error code %d from entry mix '%s'\n", status.Status(), cl.ChainMatrix[chain][0].Addr)
	} else {
		fmt.Printf("Successfully delivered message to entry mix '%s'\n", cl.ChainMatrix[chain][0].Addr)
	}

	cl.SendWG.Done()
}

// HandleMsgs is the main user input loop on a
// zeno client. It accepts lines typed by the user,
// times and pads them properly, onion-encrypts
// and transmits them to each cascade. If no
// user message is available in a round, cover
// traffic is encrypted and sent in its place.
func (cl *Client) HandleMsgs() error {

	tests := []string{
		"Good morning, New York!",
		"@$°%___!!!#### <- symbols much?",
		"lorem ipsum dolor sit cannot be missing of course",
		"TweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweet",
		"All human beings are born free and equal in dignity and rights. They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood. Everyone is entitled to all the rights and freedoms set forth in this Declaration, without distinction of any kind, such as race, colour, sex, language, religion, political or other opinion, national or social origin, property, birth or other status. Furthermore, no distinction shall be made on the basis of the political, jurisdictional or international status of the country or territory to which a person belongs, whether it be independent, trust, non-self-governing or under any other limitation of sovereignty.",
	}

	for msg := range tests {

		fmt.Printf("Handling a user message now\n")

		// Prepare the needed new round state,
		// primarily including fresh key material.
		err := cl.InitNewRound()
		if err != nil {
			return err
		}

		// Pad message to fixed length.
		var msgPadded [280]byte
		copy(msgPadded[:], tests[msg])

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
		convoExitMsg.SetClientAddr("127.0.0.1")
		convoExitMsg.SetContent(msgPadded[:])

		// Marshal final ConvoExitMsg to byte slice.
		protoMsgBytes, err := protoMsg.Marshal()
		if err != nil {
			return err
		}

		fmt.Printf("len(convoExitMsg) = %d\n", len(protoMsgBytes))

		cl.SendWG.Add(len(cl.ChainMatrix))

		// In parallel, reverse onion-encrypt the
		// ConvoExitMsg and send to all entry mixes.
		for chain := range cl.ChainMatrix {
			go cl.OnionEncryptAndSend(protoMsgBytes, chain)
		}

		// Wait for all entry messages to be sent.
		cl.SendWG.Wait()
	}

	return nil
}
