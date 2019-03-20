package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"crypto/rand"

	"github.com/numbleroot/zeno/mixnet"
	"golang.org/x/crypto/nacl/box"
)

func main() {

	// Allow for and require various arguments.
	isClientFlag := flag.Bool("client", false, "Append this flag on a node representing a client of the mix-net.")
	isMixFlag := flag.Bool("mix", false, "Append this flag on a node taking up mix responsibilities.")
	pkiAddrFlag := flag.String("pki", "127.0.0.1:10001", "Provide ip:port address string of PKI for mix-net.")
	nameFlag := flag.String("name", "", "Specify human-readable name of this node.")
	listenAddrFlag := flag.String("listenAddr", "", "Specify on which ip:port address for this node to listen for messages.")
	flag.Parse()

	// Enforce either client or mix designation.
	if *isClientFlag == *isMixFlag {
		fmt.Printf("Please identify node as either '-client' or '-mix'.\n")
		os.Exit(1)
	}

	// Expect a name set for the node.
	if *nameFlag == "" {
		fmt.Printf("Please specify a human-readable name for the node.\n")
		os.Exit(1)
	}

	// Require a listen address to be set.
	if *listenAddrFlag == "" {
		fmt.Printf("Please specify on which ip:port address for node to listen.\n")
		os.Exit(1)
	}

	isClient := *isClientFlag
	isMix := *isMixFlag
	pkiAddr := *pkiAddrFlag
	name := *nameFlag
	listenAddr := *listenAddrFlag

	fmt.Printf("Params:  isClient='%v'  &&  isMix='%v'  &&  pkiAddr='%v'  &&  listenAddr='%v'\n\n", isClient, isMix, pkiAddr, listenAddr)

	// Generate a public-private key pair.
	// We use NaCl which uses Curve25519.
	pKey, sKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate public-private key pair: %v\n", err)
		os.Exit(1)
	}

	// Construct common node characteristics.
	node := &mixnet.Node{
		Name: name,
		PKey: pKey,
		SKey: sKey,
	}

	if isMix {

		// Start listening on TCP socket.
		l, err := net.Listen("tcp", listenAddr)
		if err != nil {
			fmt.Printf("Failed to listen on listenAddr: %v\n", err)
			os.Exit(1)
		}
		defer l.Close()

		mix := &mixnet.Mix{
			Node:     node,
			Listener: l,
		}

		// Run endless loop of mix node.
		err = mix.Run()

	} else if isClient {

		client := &mixnet.Client{
			node,
		}

		err = client.Run()
	}

	if err != nil {
		fmt.Printf("Failed to run node: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nAll shut down, exiting.\n")
}
