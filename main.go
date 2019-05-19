package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
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
	isEvalFlag := flag.Bool("eval", false, "Append this flag to write evaluation output to files '/tmp/zeno_client_send.evaluation' and '/tmp/zeno_client_recv.evaluation'")
	numMsgToRecvFlag := flag.Int("numMsgToRecv", -1, "Specify how many messages a '-client' is supposed to receive before exiting, -1 disables this limit.")
	metricsPipeFlag := flag.String("metricsPipe", "/tmp/collect", "Specify the named pipe to use for IPC with the collector sidecar.")

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
	isEval := *isEvalFlag
	numMsgToRecv := *numMsgToRecvFlag
	metricsPipe := *metricsPipeFlag

	// Generate ephemeral TLS certificate and config
	// for PKI listener.
	pkiTLSConfAsServer, pkiCertPEM, err := GenPubTLSCertAndConf("", []string{
		strings.Split(msgPublicAddr, ":")[0],
		strings.Split(pkiLisAddr, ":")[0],
	})
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

	if node.IsEval {

		// Open named pipe for sending metrics to collector.
		pipe, err := os.OpenFile(metricsPipe, os.O_WRONLY, 0600)
		if err != nil {
			fmt.Printf("Unable to open named pipe for sending metrics to collector: %v\n", err)
			os.Exit(1)
		}
		node.MetricsPipe = pipe
	}

	// Open up socket for eventual cascades matrix
	// election data from PKI.
	tried := 0
	node.PKIListener, err = tls.Listen("tcp", node.PKILisAddr, node.PKITLSConfAsServer)
	if err != nil {
		fmt.Printf("Failed to listen on PKI socket %s (will try again): %v\n", node.PKILisAddr, err)
		time.Sleep(2 * time.Second)
	}

	for err != nil && tried < 10 {

		node.PKIListener, err = tls.Listen("tcp", node.PKILisAddr, node.PKITLSConfAsServer)
		if err != nil {
			fmt.Printf("Failed to listen on PKI socket %s (will try again): %v\n", node.PKILisAddr, err)
			time.Sleep(2 * time.Second)
		}
	}

	if tried >= 10 {
		fmt.Printf("Failed to listen on PKI socket %s permanently: %v\n", node.PKILisAddr, err)
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
			mix.PubListener, err = tls.Listen("tcp", mix.PubLisAddr, mix.CurPubTLSConfAsServer)
			if err != nil {
				fmt.Printf("Failed to listen on mix-net socket %s: %v\n", mix.PubLisAddr, err)
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
			client.PubListener, err = tls.Listen("tcp", client.PubLisAddr, client.CurPubTLSConfAsServer)
			if err != nil {
				fmt.Printf("Failed to listen on mix-net socket %s: %v\n", client.PubLisAddr, err)
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
