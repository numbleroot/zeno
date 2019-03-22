package mixnet

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"

	"golang.org/x/crypto/nacl/box"

	"github.com/numbleroot/zeno/rpc"
	capnprpc "zombiezen.com/go/capnproto2/rpc"
)

// ReconnectToEntries opens up new RPC connections
// over TCP to each entry mix in chainMatrix.
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

	return nil
}

func (cl *Client) HandleMsgs() error {

	tests := []string{
		"Good morning, New York!",
		"@$°%___!!!#### <- symbols much?",
		"lorem ipsum dolor sit cannot be missing of course",
		"TweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweetLengthTweet",
		"All human beings are born free and equal in dignity and rights. They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood. Everyone is entitled to all the rights and freedoms set forth in this Declaration, without distinction of any kind, such as race, colour, sex, language, religion, political or other opinion, national or social origin, property, birth or other status. Furthermore, no distinction shall be made on the basis of the political, jurisdictional or international status of the country or territory to which a person belongs, whether it be independent, trust, non-self-governing or under any other limitation of sovereignty.",
	}

	for msg := range tests {

		// Key material.

		msgKeys := make([][]*[32]byte, len(cl.ChainMatrix))

		for chain := range cl.ChainMatrix {

			msgKeys[chain] = make([]*[32]byte, len(cl.ChainMatrix[chain]))

			for mix := range cl.ChainMatrix[chain] {

				// Generate public-private key pair.
				// msgPubKey, msgSecKey, err := box.GenerateKey(rand.Reader)
				_, msgSecKey, err := box.GenerateKey(rand.Reader)
				if err != nil {
					return err
				}

				// Calculate shared key between ephemeral
				// secret key and receive public key of each mix.
				box.Precompute(msgKeys[chain][mix], cl.ChainMatrix[chain][mix].PubKey, msgSecKey)
			}
		}

		// Pad message to fixed length.
		var msgPadded [240]byte
		copy(msgPadded[:], tests[msg])

		fmt.Printf("msg: '%#v', msgPadded: '%#v'\n", tests[msg], msgPadded)

		/*
			status, err := entry.AddConvoMsg(ctx, func(p rpc.Mix_addConvoMsg_Params) error {

				msg, err := p.NewMsg()
				if err != nil {
					return err
				}

				msg.SetContent([]byte("test payload!"))

				return nil

			}).Struct()
			if err != nil {
				return err
			}

			fmt.Printf("\nReceived status reply: '%#v'\n", status)
		*/
	}

	return nil
}
