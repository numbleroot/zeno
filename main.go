package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"golang.org/x/crypto/nacl/box"
)

func main() {

	// Allow for and require various arguments.
	isClientFlag := flag.Bool("client", false, "Append this flag on a node representing a client of the mix-net.")
	isMixFlag := flag.Bool("mix", false, "Append this flag on a node intended for mix responsibilities (might still become regular client).")
	pkiAddrFlag := flag.String("pki", "127.0.0.1:10001", "Provide ip:port address string of PKI for mix-net.")
	pkiCertPathFlag := flag.String("pkiCertPath", filepath.Join(os.Getenv("GOPATH"), "src/github.com/numbleroot/zeno-pki/cert.pem"), "Specify file system path to PKI server TLS certificate.")
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
	pkiCertPath := *pkiCertPathFlag
	msgLisAddr := *msgLisAddrFlag
	pkiLisAddr := *pkiLisAddrFlag

	// Generate a public-private key pair used
	// ONLY for receiving messages. Based on
	// Curve25519 via NaCl library.
	recvPubKey, recvSecKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate public-private key pair for receiving messages: %v\n", err)
		os.Exit(1)
	}

	// Generate ephemeral TLS certificate and config
	// for public listener.
	pubTLSConfAsServer, pubCertPEM, err := GenPubTLSCertAndConf("localhost", strings.Split(msgLisAddr, ":")[0])
	if err != nil {
		fmt.Printf("Failed generating ephemeral TLS certificate and config: %v\n", err)
		os.Exit(1)
	}

	// Obtain strong and suitable TLS configuration
	// to use when contacting the PKI server.
	pkiTLSConfAsClient, err := GenPKITLSConf(pkiCertPath)
	if err != nil {
		fmt.Printf("Failed putting together PKI server TLS configuration: %v\n", err)
		os.Exit(1)
	}

	node := &Node{
		RecvPubKey:         recvPubKey,
		RecvSecKey:         recvSecKey,
		PubLisAddr:         msgLisAddr,
		PubTLSConfAsServer: pubTLSConfAsServer,
		PubCertPEM:         pubCertPEM,
		PKIAddr:            pkiAddr,
		PKILisAddr:         pkiLisAddr,
		PKITLSConfAsClient: pkiTLSConfAsClient,
		PKITLSConfAsServer: pubTLSConfAsServer,
		SigRotateEpoch:     make(chan struct{}),
		SigMixesElected:    make(chan struct{}),
		SigClientsAdded:    make(chan struct{}),
	}

	// Open socket for incoming mix-net messages.
	node.PubListener, err = quic.ListenAddr(node.PubLisAddr, node.PubTLSConfAsServer, nil)
	if err != nil {
		fmt.Printf("Failed to listen for mix-net messages on socket %s: %v\n", node.PubLisAddr, err)
		os.Exit(1)
	}
	defer node.PubListener.Close()

	// Open up socket for eventual cascades matrix
	// election data from PKI.
	node.PKIListener, err = quic.ListenAddr(node.PKILisAddr, node.PKITLSConfAsServer, nil)
	if err != nil {
		fmt.Printf("Failed to listen for PKI information on socket %s: %v\n", node.PKILisAddr, err)
		os.Exit(1)
	}
	defer node.PKIListener.Close()

	// Wait for and act upon messages from PKI.
	go node.AcceptMsgsFromPKI()

	// Prepare the upcoming epoch by electing
	// cascades and receiving all clients.
	elected, err := node.PrepareNextEpoch(isMix, isClient)
	if err != nil {
		fmt.Printf("Preparing upcoming epoch failed: %v", err)
		os.Exit(1)
	}

	// TODO: Listeners and connections need to be
	//       shut down and closed way more explicitely.

	for {

		// Swap elected mixes and registered clients
		// for upcoming epoch to current.
		node.CurCascadesMatrix = node.NextCascadesMatrix
		node.CurClients = node.NextClients
		node.CurClientsByAddress = node.NextClientsByAddress

		if elected {

			mix := &Mix{
				Node: node,
			}

			// This node is a mix and was elected
			// to be part of the cascades matrix.
			// Run rounds protocol in background.
			go mix.RunRounds()

			// Wait for signal to prepare next epoch.
			<-mix.SigRotateEpoch

			// Prepare the upcoming epoch by electing
			// cascades and receiving all clients.
			elected, err = mix.PrepareNextEpoch(isMix, isClient)
			if err != nil {
				fmt.Printf("Preparing upcoming epoch failed: %v", err)
				os.Exit(1)
			}

		} else {

			client := &Client{
				Node:   node,
				SendWG: &sync.WaitGroup{},
			}

			// This node is a client. Run rounds
			// protocol in background.
			go client.RunRounds()

			// Wait for signal to prepare next epoch.
			<-client.SigRotateEpoch

			// Prepare the upcoming epoch by electing
			// cascades and receiving all clients.
			elected, err = client.PrepareNextEpoch(isMix, isClient)
			if err != nil {
				fmt.Printf("Preparing upcoming epoch failed: %v", err)
				os.Exit(1)
			}
		}
	}
}
