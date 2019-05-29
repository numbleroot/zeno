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
	isMixFlag := flag.Bool("mix", false, "Append this flag on a node intended for mix responsibilities (might still become regular client).")
	isClientFlag := flag.Bool("client", false, "Append this flag on a node representing a client of the mix-net.")
	nameFlag := flag.String("name", "", "Supply the name of this node.")
	partnerFlag := flag.String("partner", "", "Supply the name of this node's conversation partner.")
	msgPublicAddrFlag := flag.String("msgPublicAddr", "127.0.0.1:33000", "Specify on which ip:port address this node is going to be publicly addressable.")
	msgLisAddrFlag := flag.String("msgLisAddr", "0.0.0.0:33000", "Specify on which ip:port address for this node to listen for messages.")
	pkiLisAddrFlag := flag.String("pkiLisAddr", "0.0.0.0:44000", "Specify on which ip:port address for this node to listen for PKI information.")
	pkiAddrFlag := flag.String("pki", "1.1.1.1:33000", "Provide ip:port address string of PKI for mix-net.")
	pkiCertPathFlag := flag.String("pkiCertPath", filepath.Join(os.Getenv("GOPATH"), "src/github.com/numbleroot/zeno-pki/cert.pem"), "Specify file system path to PKI server TLS certificate.")
	isEvalFlag := flag.Bool("eval", false, "Append this flag to write evaluation metrics out to a collector process.")
	numMsgToRecvFlag := flag.Int("numMsgToRecv", -1, "Specify how many messages a '-client' is supposed to receive before exiting, -1 disables this limit.")
	killMixesInRoundFlag := flag.Int("killMixesInRound", -1, "If set to a positive number, the second-in-cascade mixes from all but the first cascade will crash at the beginning of this round.")
	metricsPipeFlag := flag.String("metricsPipe", "/tmp/collect", "Specify the named pipe to use for IPC with the collector sidecar.")

	flag.Parse()

	if *isClientFlag == *isMixFlag {
		fmt.Printf("Please identify node as either '-client' or '-mix'.\n")
		os.Exit(1)
	}

	if *nameFlag == "" {
		fmt.Printf("Zeno nodes need to be given a name ('-name').\n")
		os.Exit(1)
	}

	if *partnerFlag == "" {
		fmt.Printf("Zeno nodes need to be assigned a conversation partner to potentially exchange messages with ('-partner').\n")
		os.Exit(1)
	}

	isMix := *isMixFlag
	isClient := *isClientFlag
	name := *nameFlag
	partner := *partnerFlag
	msgPublicAddr := *msgPublicAddrFlag
	msgLisAddr := *msgLisAddrFlag
	pkiLisAddr := *pkiLisAddrFlag
	pkiAddr := *pkiAddrFlag
	pkiCertPath := *pkiCertPathFlag
	isEval := *isEvalFlag
	numMsgToRecv := *numMsgToRecvFlag
	killMixesInRound := *killMixesInRoundFlag
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
		Name:               name,
		Partner:            &Endpoint{Name: partner},
		PubLisAddr:         msgLisAddr,
		SigRotateEpoch:     make(chan struct{}),
		SigCloseEpoch:      make(chan struct{}),
		SigMixesElected:    make(chan struct{}),
		SigClientsAdded:    make(chan struct{}),
		PKIAddr:            pkiAddr,
		PKILisAddr:         pkiLisAddr,
		PKITLSConfAsClient: pkiTLSConfAsClient,
		PKITLSConfAsServer: pkiTLSConfAsServer,
		PKICertPEM:         pkiCertPEM,
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
		Node:             node,
		KillMixesInRound: killMixesInRound,
	}

	client := &Client{
		Node:         node,
		NumMsgToRecv: numMsgToRecv,
		muUpdState:   &sync.RWMutex{},
		muNewMsg:     &sync.Mutex{},
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
			mix.RoundCounter = 1
			mix.CurRecvPubKey = mix.NextRecvPubKey
			mix.CurRecvSecKey = mix.NextRecvSecKey
			mix.CurPubTLSConfAsServer = mix.NextPubTLSConfAsServer
			mix.CurPubCertPEM = mix.NextPubCertPEM
			mix.CurCascadesMatrix = mix.NextCascadesMatrix
			mix.CurClients = mix.NextClients
			mix.OwnChain = -1
			mix.OwnIndex = -1
			mix.IsEntry = false
			mix.IsExit = false
			mix.Successor = nil

			// Open socket for incoming mix-net messages.
			tried := 1
			mix.PubListener, err = tls.Listen("tcp", mix.PubLisAddr, mix.CurPubTLSConfAsServer)
			for err != nil && tried <= 10 {

				fmt.Printf("Failed %d times to listen on mix-net socket %s (will try again): %v\n", tried, mix.PubLisAddr, err)

				tried++
				time.Sleep(200 * time.Millisecond)

				mix.PubListener, err = tls.Listen("tcp", mix.PubLisAddr, mix.CurPubTLSConfAsServer)
			}
			if err != nil {
				fmt.Printf("Failed permanently to listen on mix-net socket %s (%d times): %v\n", mix.PubLisAddr, tried, err)
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
			client.muNewMsg.Lock()

			// Mark node as client (again).
			client.IsClient = true

			// Swap state prepared for upcoming epoch
			// into places for current epoch.
			client.RoundCounter = 1
			client.CurRecvPubKey = client.NextRecvPubKey
			client.CurRecvSecKey = client.NextRecvSecKey
			client.CurPubTLSConfAsServer = client.NextPubTLSConfAsServer
			client.CurPubCertPEM = client.NextPubCertPEM
			client.CurCascadesMatrix = client.NextCascadesMatrix
			client.CurClients = client.NextClients

			// Open socket for incoming mix-net messages.
			tried := 1
			client.PubListener, err = tls.Listen("tcp", client.PubLisAddr, client.CurPubTLSConfAsServer)
			for err != nil && tried <= 10 {

				fmt.Printf("Failed %d times to listen on mix-net socket %s (will try again): %v\n", tried, client.PubLisAddr, err)

				tried++
				time.Sleep(200 * time.Millisecond)

				client.PubListener, err = tls.Listen("tcp", client.PubLisAddr, client.CurPubTLSConfAsServer)
			}
			if err != nil {
				fmt.Printf("Failed permanently to listen on mix-net socket %s (%d times): %v\n", client.PubLisAddr, tried, err)
				client.muUpdState.Unlock()
				client.muNewMsg.Unlock()
				os.Exit(1)
			}

			client.RecvdMsgs = make(map[string]bool)
			client.DoneCounter = 300

			client.muUpdState.Unlock()
			client.muNewMsg.Unlock()

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

			// Close all possibly active exit mix connections.
			for i := 0; i < len(client.CurCascadesMatrix); i++ {
				client.SigCloseEpoch <- struct{}{}
			}
		}

		// Close public listener.
		err = node.PubListener.Close()
		if err != nil {
			fmt.Printf("Error while closing public listener: %v\n", err)
		}

		fmt.Printf("\nShall the regular rounds begin!\n")
	}
}
