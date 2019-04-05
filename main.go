package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lucas-clemente/quic-go"

	"github.com/numbleroot/zeno/mixnet"
	"golang.org/x/crypto/nacl/box"
)

func main() {

	// Allow for and require various arguments.
	isClientFlag := flag.Bool("client", false, "Append this flag on a node representing a client of the mix-net.")
	isMixFlag := flag.Bool("mix", false, "Append this flag on a node taking up mix responsibilities.")
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

	// Read PKI server TLS certificate from
	// specified file system location.
	pkiCert, err := ioutil.ReadFile(pkiCertPath)
	if err != nil {
		fmt.Printf("Failed to load PKI server TLS certificate from path '%s': %v\n", pkiCertPath, err)
		os.Exit(1)
	}

	// Create new empty cert pool.
	pkiCertRoot := x509.NewCertPool()

	// Attempt to add the loaded PKI server certificate.
	ok := pkiCertRoot.AppendCertsFromPEM(pkiCert)
	if !ok {
		fmt.Printf("Failed to add PKI server TLS certificate to pool: %v\n", err)
		os.Exit(1)
	}

	// Construct common node characteristics.
	node := &mixnet.Node{
		RecvPubKey: recvPubKey,
		RecvSecKey: recvSecKey,
		PKIAddr:    pkiAddr,
		PKILisAddr: pkiLisAddr,
		PKITLSConf: &tls.Config{
			RootCAs:            pkiCertRoot,
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS13,
			CurvePreferences:   []tls.CurveID{tls.X25519},
		},
		PubLisAddr:            msgLisAddr,
		ChainMatrixConfigured: make(chan struct{}),
	}

	// Open up socket for eventual chain matrix
	// election data from PKI.
	// TODO: Should this be over TLS not TCP?
	node.PKIListener, err = net.Listen("tcp", node.PKILisAddr)
	if err != nil {
		fmt.Printf("Failed to listen for PKI information on socket %s: %v\n", node.PKILisAddr, err)
		os.Exit(1)
	}
	defer node.PKIListener.Close()

	// Start listening for incoming mix-net messages.
	// TODO: Should this be over TLS not TCP?
	// node.PubListener, err = net.Listen("tcp", node.PubLisAddr)
	node.PubListener, err = quic.ListenAddr(node.PubLisAddr, &tls.Config{
		InsecureSkipVerify: true,
	}, nil)
	if err != nil {
		fmt.Printf("Failed to listen for mix-net messages on socket %s: %v\n", node.PubLisAddr, err)
		os.Exit(1)
	}
	defer node.PubListener.Close()

	// Handle messages from PKI.
	go node.HandlePKIMsgs()

	if isMix {

		// Nodes that offer to take up a mix role
		// register their intent with the PKI.
		err = node.RegisterMixIntent()
		if err != nil {
			fmt.Printf("Failed to register intent for mixing at PKI server: %v\n", err)
			os.Exit(1)
		}

	} else if isClient {

		// Nodes that are regular clients in the
		// system register with their address and
		// receive public key at the PKI.
		err = node.RegisterClient()
		if err != nil {
			fmt.Printf("Failed to register as client at PKI server: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Waiting for chain matrix to configure...\n")

	// Wait until chain matrix has been built.
	<-node.ChainMatrixConfigured

	fmt.Printf("Chain matrix configured.\n\n")

	elected := false

	if isMix {

		// TODO: Figure out whether the mix intent of this
		//       node resulted in it getting elected.
		elected = true

		if !elected {

			// This node intended to become a mix yet did
			// not get elected. Register as regular client.
			err = node.RegisterClient()
			if err != nil {
				fmt.Printf("Failed to late-register as client at PKI server: %v\n", err)
				os.Exit(1)
			}
		}
	}

	// Query PKI for all known clients and stash
	// list of Endpoints for later use.
	err = node.GetAllClients()
	if err != nil {
		fmt.Printf("Failed retrieving all known clients from PKI: %v\n", err)
		os.Exit(1)
	}

	if elected {

		// This node is a mix and was elected
		// to be part of the chain matrix.

		mix := &mixnet.Mix{
			Node: node,
		}

		// Determine this mix node's place in chain matrix.
		mix.SetOwnPlace()

		// Connect to each mix node's successor mix.
		err := mix.ReconnectToSuccessor()
		if err != nil {
			fmt.Printf("Failed to connect to mix node's successor mix: %v\n", err)
			os.Exit(1)
		}

		// Initialize state on mix for upcoming round.
		err = mix.InitNewRound()
		if err != nil {
			fmt.Printf("Failed generating cover traffic messages for pool: %v\n", err)
			os.Exit(1)
		}

		// Run mix node part of mix-net round
		// protocol in background.
		go mix.RotateRoundState()

		for {

			// Wait for incoming connections on public socket.
			session, err := mix.PubListener.Accept()
			if err != nil {
				fmt.Printf("Public connection error: %v\n", err)
				continue
			}

			connWrite, err := session.AcceptStream()
			if err != nil {
				fmt.Printf("Failed accepting incoming stream: %v\n", err)
				continue
			}

			sender := strings.Split(session.RemoteAddr().String(), ":")[0]
			fmt.Printf("Sender: '%s'\n", sender)

			if mix.IsEntry {

				// Create buffered I/O reader from connection.
				connRead := bufio.NewReader(connWrite)

				// At entry mixes we only receive single
				// conversation messages from clients.
				// We handle them directly.
				go mix.AddConvoMsg(connRead, connWrite, sender)

			} else {

				// At non-entry mixes we only expect to receive
				// Cap'n Proto batch messages.
				go mix.HandleBatchMsgs(connWrite, sender)
			}
		}

	} else {

		// This node is a client.

		client := &mixnet.Client{
			Node:   node,
			SendWG: &sync.WaitGroup{},
		}

		// Handle messaging loop.
		go client.SendMsg()

		for {

			// Wait for incoming connections on public socket.
			session, err := client.PubListener.Accept()
			if err != nil {
				fmt.Printf("Public connection error: %v\n", err)
				continue
			}

			connWrite, err := session.AcceptStream()
			if err != nil {
				fmt.Printf("Failed accepting incoming stream: %v\n", err)
				continue
			}
			decoder := gob.NewDecoder(connWrite)

			// Wait for a message.
			var msg []byte
			err = decoder.Decode(&msg)
			if err != nil {
				fmt.Printf("Failed decoding incoming message as slice of bytes: %v\n", err)
				continue
			}

			// Display message.
			fmt.Printf("RECEIVED: '%s'\n", msg)
		}
	}
}
