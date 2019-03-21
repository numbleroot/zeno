package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

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

	fmt.Printf("Params:  isClient='%v'  &&  isMix='%v'  &&  pkiAddr='%v'  &&  msgLisAddr='%v'  &&  pkiLisAddr='%v'\n\n", isClient, isMix, pkiAddr, msgLisAddr, pkiLisAddr)

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
		PKITLSConf: &tls.Config{
			RootCAs:            pkiCertRoot,
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS13,
			CurvePreferences:   []tls.CurveID{tls.X25519},
		},
		ChainMatrixConfigured: make(chan struct{}),
	}

	// Open up socket for eventual chain matrix
	// election data from PKI.
	node.PKIListener, err = net.Listen("tcp", pkiLisAddr)
	if err != nil {
		fmt.Printf("Failed to listen for PKI information on socket %s: %v\n", pkiLisAddr, err)
		os.Exit(1)
	}
	defer node.PKIListener.Close()

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

		// Wait until chainMatrix has been built.
		<-node.ChainMatrixConfigured

		// Determine whether this node is an entry
		// or a common mix node.

		mix := &mixnet.Mix{
			Node: node,
		}

		// Start listening for incoming mix-net messages.
		mix.PubListener, err = net.Listen("tcp", msgLisAddr)
		if err != nil {
			fmt.Printf("Failed to listen for mix-net messages on socket %s: %v\n", msgLisAddr, err)
			os.Exit(1)
		}
		defer mix.PubListener.Close()

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

		// Nodes that are regular clients in the
		// system register with their address and
		// receive public key at the PKI.
		err = node.RegisterClient()
		if err != nil {
			fmt.Printf("Failed to register as client at PKI server: %v\n", err)
			os.Exit(1)
		}

		// Wait until chainMatrix has been built.
		<-node.ChainMatrixConfigured

		client := &mixnet.Client{
			Node: node,
		}

		err := client.Run()
		if err != nil {
			fmt.Printf("Error while running client: %v\n", err)
		}
	}

	fmt.Printf("\nAll shut down, exiting.\n")
}
