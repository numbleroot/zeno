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
	numMsgToRecvFlag := flag.Int("numMsgToRecv", -1, "Specify how many messages a '-client' is supposed to receive before exiting, -1 disables this limit.")
	isEvalFlag := flag.Bool("eval", false, "Append this flag to write evaluation output to files '~/zeno_send.log' and '~/zeno_receive.log'")

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
	numMsgToRecv := *numMsgToRecvFlag
	isEval := *isEvalFlag

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
		IsEval:             isEval,
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

	mix := &Mix{
		Node: node,
	}

	client := &Client{
		Node:         node,
		muUpdState:   &sync.RWMutex{},
		NumMsgToRecv: numMsgToRecv,
	}

	if client.IsEval {

		// In case we are evaluating this node,
		// create channels for the file writing
		// goroutines to receive measurements on.
		client.EvalSendChan = make(chan string, 50)
		client.EvalRecvChan = make(chan string, 50)

		go func(logs chan string) {

			// Open an append-only, synchronized file.
			evalFile, err := os.OpenFile("zeno_send.log", (os.O_APPEND | os.O_CREATE | os.O_TRUNC | os.O_WRONLY), 0644)
			if err != nil {
				fmt.Printf("Unable to create send measurements file '~/zeno_send.log': %v\n", err)
				os.Exit(1)
			}

			// Write every measurement into file.
			for log := range logs {
				fmt.Fprint(evalFile, log)
				_ = evalFile.Sync()
			}

		}(client.EvalSendChan)

		go func(logs chan string) {

			// Open an append-only, synchronized file.
			evalFile, err := os.OpenFile("zeno_recv.log", (os.O_APPEND | os.O_CREATE | os.O_TRUNC | os.O_WRONLY), 0644)
			if err != nil {
				fmt.Printf("Unable to create recv measurements file '~/zeno_recv.log': %v\n", err)
				os.Exit(1)
			}

			// Write every measurement into file.
			for log := range logs {
				fmt.Fprint(evalFile, log)
				_ = evalFile.Sync()
			}

		}(client.EvalRecvChan)
	}

	// Prepare the upcoming epoch by electing
	// cascades and receiving all clients.
	elected, err := node.PrepareNextEpoch(isMix, isClient)
	if err != nil {
		fmt.Printf("Preparing upcoming epoch failed: %v", err)
		os.Exit(1)
	}

	for {

		if elected {

			// In case this node used to be a client,
			// reset marker so that sending function returns.
			client.muUpdState.Lock()
			client.IsClient = false
			client.muUpdState.Unlock()

			// Swap state prepared for upcoming epoch
			// into places for current epoch, and reset
			// mix state from prior round.
			mix.CurRecvPubKey = mix.NextRecvPubKey
			mix.CurRecvSecKey = mix.NextRecvSecKey
			mix.CurPubTLSConfAsServer = mix.NextPubTLSConfAsServer
			mix.CurPubCertPEM = mix.NextPubCertPEM
			mix.CurCascadesMatrix = mix.NextCascadesMatrix
			mix.CurClients = mix.NextClients
			mix.CurClientsByAddress = mix.NextClientsByAddress
			mix.OwnChain = -1
			mix.OwnIndex = -1
			mix.IsEntry = false
			mix.IsExit = false
			mix.Successor = nil

			// Open socket for incoming mix-net messages.
			mix.PubListener, err = quic.ListenAddr(mix.PubLisAddr, mix.CurPubTLSConfAsServer, nil)
			if err != nil {
				fmt.Printf("Failed to listen for mix-net messages on socket %s: %v\n", mix.PubLisAddr, err)
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
			mix.SigCloseEpoch <- struct{}{}
			mix.SigCloseEpoch <- struct{}{}

		} else {

			client.muUpdState.Lock()

			// Mark node as client (again).
			client.IsClient = true

			// Swap state prepared for upcoming epoch
			// into places for current epoch.
			client.CurRecvPubKey = client.NextRecvPubKey
			client.CurRecvSecKey = client.NextRecvSecKey
			client.CurPubTLSConfAsServer = client.NextPubTLSConfAsServer
			client.CurPubCertPEM = client.NextPubCertPEM
			client.CurCascadesMatrix = client.NextCascadesMatrix
			client.CurClients = client.NextClients
			client.CurClientsByAddress = client.NextClientsByAddress

			// Open socket for incoming mix-net messages.
			client.PubListener, err = quic.ListenAddr(client.PubLisAddr, client.CurPubTLSConfAsServer, nil)
			if err != nil {
				fmt.Printf("Failed to listen for mix-net messages on socket %s: %v\n", client.PubLisAddr, err)
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
			client.SigCloseEpoch <- struct{}{}
		}

		// Close public listener.
		err = node.PubListener.Close()
		if err != nil {
			fmt.Printf("Error while closing public listener: %v\n", err)
		}

		fmt.Printf("\nShall the regular rounds begin!\n")
	}
}
