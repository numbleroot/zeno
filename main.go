package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/numbleroot/zeno/mixnet"
	"golang.org/x/crypto/nacl/box"
)

func main() {

	// Allow for and require various arguments.
	isClientFlag := flag.Bool("client", false, "Append this flag on a node representing a client of the mix-net.")
	isMixFlag := flag.Bool("mix", false, "Append this flag on a node taking up mix responsibilities.")
	pkiAddrFlag := flag.String("pki", "127.0.0.1:10001", "Provide ip:port address string of PKI for mix-net.")
	msgLisAddrFlag := flag.String("msgLisAddr", "", "Specify on which ip:port address for this node to listen for messages.")
	pkiLisAddrFlag := flag.String("pkiLisAddr", "", "Specify on which ip:port address for this node to listen for PKI information.")

	flag.Parse()

	// Enforce either client or mix designation.
	if *isClientFlag == *isMixFlag {
		fmt.Printf("Please identify node as either '-client' or '-mix'.\n")
		os.Exit(1)
	}

	// Require a listen address for messages to be set.
	if *msgLisAddrFlag == "" {
		fmt.Printf("Please specify on which ip:port address for this node to listen for messages.\n")
		os.Exit(1)
	}

	// Require a listen address for information from
	// PKI to be set.
	if *pkiLisAddrFlag == "" {
		fmt.Printf("Please specify on which ip:port address for this node to listen for PKI information.\n")
		os.Exit(1)
	}

	isClient := *isClientFlag
	isMix := *isMixFlag
	pkiAddr := *pkiAddrFlag
	msgLisAddr := *msgLisAddrFlag
	pkiLisAddr := *pkiLisAddrFlag

	fmt.Printf("Params:  isClient='%v'  &&  isMix='%v'  &&  pkiAddr='%v'  &&  msgLisAddr='%v'  &&  pkiLisAddr='%v'\n\n", isClient, isMix, pkiAddr, msgLisAddr, pkiLisAddr)

	// Generate a public-private key pair used
	// ONLY for receiving messages. Based on
	// Curve25519 via NaCl library.
	recvPubKey, recvSecKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate public-private key pair for receiving messages: %v\n", err)
		os.Exit(1)
	}

	// Construct common node characteristics.
	node := &mixnet.Node{
		RecvPubKey:       recvPubKey,
		RecvSecKey:       recvSecKey,
		ChainMatrixBuilt: make(chan struct{}),
	}

	if isMix {

		// TODO: Nodes that offer to become part of
		//       the cascades (become mixes), register
		//       their intent with the PKI.
		//       As response, they receive the last stable
		//       list of nodes that are participating in
		//       cascades election.

		// Open up socket for eventual chain matrix
		// election data from PKI.
		pkiSock, err := net.Listen("tcp", pkiLisAddr)
		if err != nil {
			fmt.Printf("Failed to listen for PKI information on socket %s: %v\n", pkiLisAddr, err)
			os.Exit(1)
		}
		defer pkiSock.Close()

		node.PKIListener = pkiSock

		// Handle messages from PKI.
		go node.HandlePKIMsgs()

		// Wait until chainMatrix has been built.
		<-node.ChainMatrixBuilt

		// Determine whether this node is an entry
		// or a common mix node.

		// Start listening for incoming mix-net messages.
		msgSock, err := net.Listen("tcp", msgLisAddr)
		if err != nil {
			fmt.Printf("Failed to listen for mix-net messages on socket %s: %v\n", msgLisAddr, err)
			os.Exit(1)
		}
		defer msgSock.Close()

		mix := &mixnet.EntryMix{
			Node:        node,
			PubListener: msgSock,
		}

		for {

			// Wait for incoming connections on public socket.
			conn, err := mix.PubListener.Accept()
			if err != nil {
				fmt.Printf("Public connection error: %v\n", err)
				continue
			}

			go mix.HandleMsg(conn)
		}

	} else if isClient {

		// TODO: Clients register with their publicly
		//       reachable address and public key for
		//       receiving messages at the PKI.
		//       As response, they receive the last stable
		//       list of nodes that are participating in
		//       cascades election.

		// TODO: Clients run the deterministic, offline
		//       sequence computation for all cascades
		//       in the system. Output is the chain matrix.

		client := &mixnet.Client{
			node,
		}

		err := client.Run()
		if err != nil {
			fmt.Printf("Error while running client: %v\n", err)
		}
	}

	fmt.Printf("\nAll shut down, exiting.\n")
}
