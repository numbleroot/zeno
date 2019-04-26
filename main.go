package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lucas-clemente/quic-go"
)

// Enable TLS 1.3.
func init() {
	os.Setenv("GODEBUG", fmt.Sprintf("%s,tls13=1", os.Getenv("GODEBUG")))
}

func main() {

	// Allow for and require various arguments.
	isClientFlag := flag.Bool("client", false, "Append this flag on a node representing a client of the mix-net.")
	isMixFlag := flag.Bool("mix", false, "Append this flag on a node intended for mix responsibilities (might still become regular client).")
	msgPublicAddrFlag := flag.String("msgPublicAddr", "127.0.0.1:33000", "Specify on which ip:port address this node is going to be publicly addressable.")
	msgLisAddrFlag := flag.String("msgLisAddr", "0.0.0.0:33000", "Specify on which ip:port address for this node to listen for messages.")
	pkiLisAddrFlag := flag.String("pkiLisAddr", "0.0.0.0:44000", "Specify on which ip:port address for this node to listen for PKI information.")
	pkiAddrFlag := flag.String("pki", "1.1.1.1:33000", "Provide ip:port address string of PKI for mix-net.")
	pkiCertPathFlag := flag.String("pkiCertPath", filepath.Join(os.Getenv("GOPATH"), "src/github.com/numbleroot/zeno-pki/cert.pem"), "Specify file system path to PKI server TLS certificate.")

	flag.Parse()

	// Enforce either client or mix designation.
	if *isClientFlag == *isMixFlag {
		fmt.Printf("Please identify node as either '-client' or '-mix'.\n")
		os.Exit(1)
	}

	isClient := *isClientFlag
	isMix := *isMixFlag
	msgPublicAddr := *msgPublicAddrFlag
	msgLisAddr := *msgLisAddrFlag
	pkiLisAddr := *pkiLisAddrFlag
	pkiAddr := *pkiAddrFlag
	pkiCertPath := *pkiCertPathFlag

	// Generate ephemeral TLS certificate and config
	// for PKI listener.
	pkiTLSConfAsServer, pkiCertPEM, err := GenPubTLSCertAndConf("", strings.Split(msgPublicAddr, ":")[0])
	if err != nil {
		fmt.Printf("Failed generating ephemeral TLS certificate and config for PKI listener: %v\n", err)
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
		PubLisAddr:         msgLisAddr,
		PKIAddr:            pkiAddr,
		PKILisAddr:         pkiLisAddr,
		PKITLSConfAsClient: pkiTLSConfAsClient,
		PKITLSConfAsServer: pkiTLSConfAsServer,
		PKICertPEM:         pkiCertPEM,
		SigRotateEpoch:     make(chan struct{}),
		SigCloseEpoch:      make(chan struct{}),
		SigMixesElected:    make(chan struct{}),
		SigClientsAdded:    make(chan struct{}),
	}

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

	mix := &Mix{
		Node: node,
	}

	client := &Client{
		Node:       node,
		muUpdState: &sync.RWMutex{},
	}

	for {

		if elected {

			// Swap state prepared for upcoming epoch
			// into places for current epoch.
			node.CurRecvPubKey = node.NextRecvPubKey
			node.CurRecvSecKey = node.NextRecvSecKey
			node.CurPubTLSConfAsServer = node.NextPubTLSConfAsServer
			node.CurPubCertPEM = node.NextPubCertPEM
			node.CurCascadesMatrix = node.NextCascadesMatrix
			node.CurClients = node.NextClients
			node.CurClientsByAddress = node.NextClientsByAddress

			// Open socket for incoming mix-net messages.
			node.PubListener, err = quic.ListenAddr(node.PubLisAddr, node.CurPubTLSConfAsServer, nil)
			if err != nil {
				fmt.Printf("Failed to listen for mix-net messages on socket %s: %v\n", node.PubLisAddr, err)
				os.Exit(1)
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

			// Drain old epoch state.
			fmt.Printf("\nSending internal signal to drain epoch state\n")
			node.SigCloseEpoch <- struct{}{}
			node.SigCloseEpoch <- struct{}{}

		} else {

			client.muUpdState.Lock()

			// Swap state prepared for upcoming epoch
			// into places for current epoch.
			node.CurRecvPubKey = node.NextRecvPubKey
			node.CurRecvSecKey = node.NextRecvSecKey
			node.CurPubTLSConfAsServer = node.NextPubTLSConfAsServer
			node.CurPubCertPEM = node.NextPubCertPEM
			node.CurCascadesMatrix = node.NextCascadesMatrix
			node.CurClients = node.NextClients
			node.CurClientsByAddress = node.NextClientsByAddress

			// Open socket for incoming mix-net messages.
			node.PubListener, err = quic.ListenAddr(node.PubLisAddr, node.CurPubTLSConfAsServer, nil)
			if err != nil {
				fmt.Printf("Failed to listen for mix-net messages on socket %s: %v\n", node.PubLisAddr, err)
				client.muUpdState.Unlock()
				os.Exit(1)
			}

			client.muUpdState.Unlock()

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

			// Drain old epoch state.
			fmt.Printf("\nSending internal signal to drain epoch state\n")
			node.SigCloseEpoch <- struct{}{}
		}

		// Close public listener.
		err = node.PubListener.Close()
		if err != nil {
			fmt.Printf("Error while closing public listener: %v\n", err)
		}

		fmt.Printf("\nShall the regular rounds begin!\n")
	}
}
