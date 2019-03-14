package main

import (
	"flag"
	"fmt"
	"os"

	"crypto/rand"

	"github.com/numbleroot/zeno/mixnet"
	"golang.org/x/crypto/nacl/box"
)

func main() {

	// Allow for and require various arguments.
	isClientFlag := flag.Bool("client", false, "Append this flag on a node representing a client of the mix-net.")
	isMixFlag := flag.Bool("mix", false, "Append this flag on a node taking up mix responsibilities.")
	pkiAddrFlag := flag.String("pki", "127.0.0.1:10001", "Provide IP:port address string of PKI for mix-net.")
	listenAddrFlag := flag.String("listenAddr", "", "Specify on which IP:port for this node to listen for messages.")
	flag.Parse()

	// Enforce either client or mix designation.
	if *isClientFlag == *isMixFlag {
		fmt.Printf("Please identify node as either '-client' or '-mix'.\n")
		os.Exit(1)
	}

	// Require a listen address to be set.
	if *listenAddrFlag == "" {
		fmt.Printf("Please specify on which IP:port for node to listen.\n")
		os.Exit(1)
	}

	isClient := *isClientFlag
	isMix := *isMixFlag
	pkiAddr := *pkiAddrFlag
	listenAddr := *listenAddrFlag

	fmt.Printf("Params:  isClient='%v'  &&  isMix='%v'  &&  pkiAddr='%v'  &&  listenAddr='%v'\n", isClient, isMix, pkiAddr, listenAddr)

	// Generate a public-private key pair.
	// We are using NaCl which uses Curve25519.
	pKey, sKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate public-private key pair: %v\n", err)
		os.Exit(1)
	}

	mix := &mixnet.Mix{
		&mixnet.Node{
			Name: "lol",
			PKey: pKey,
			SKey: sKey,
		},
	}

	// Hand-over to endless loop method of respective service.
	mix.Run()
}
