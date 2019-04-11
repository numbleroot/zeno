package main

import (
	"bufio"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/lucas-clemente/quic-go"
)

// Enable TLS 1.3.
func init() {
	os.Setenv("GODEBUG", fmt.Sprintf("%s,tls13=1", os.Getenv("GODEBUG")))
}

// RegisterAtPKI accepts a category to register a
// node of this system under at the PKI, 'mixes'
// or 'clients'. It transmit relevant node and
// connection information via TLS to the PKI server.
func (node *Node) RegisterAtPKI(category string) error {

	// Connect to PKI TLS endpoint.
	session, err := quic.DialAddr(node.PKIAddr, node.PKITLSConfAsClient, nil)
	if err != nil {
		return err
	}

	// Upgrade session to blocking stream.
	connWrite, err := session.OpenStreamSync()
	if err != nil {
		return err
	}

	// Create buffered I/O reader from connection.
	connRead := bufio.NewReader(connWrite)

	// Register this node's intent on participating
	// as a mix node with the PKI.
	fmt.Fprintf(connWrite, "post %s %s %s %x %x\n", category, node.PubLisAddr, node.PKILisAddr, *node.RecvPubKey, node.PubCertPEM)

	// Expect an acknowledgement.
	resp, err := connRead.ReadString('\n')
	if err != nil {
		return err
	}

	// Verify cleaned response.
	resp = strings.ToLower(strings.Trim(resp, "\n "))
	if resp != "0" {
		return fmt.Errorf("PKI returned failure response to mix intent registration: %s", resp)
	}

	return nil
}

// GetAllClients retrieves the set of client
// mappings registered at the PKI.
func (node *Node) GetAllClients() error {

	// Connect to PKI TLS endpoint.
	session, err := quic.DialAddr(node.PKIAddr, node.PKITLSConfAsClient, nil)
	if err != nil {
		return err
	}

	// Upgrade session to blocking stream.
	connWrite, err := session.OpenStreamSync()
	if err != nil {
		return err
	}

	// Create buffered I/O reader from connection.
	connRead := bufio.NewReader(connWrite)

	// Query for a string containing all clients.
	fmt.Fprintf(connWrite, "getall clients\n")

	// Expect a rather long response string.
	clientsRaw, err := connRead.ReadString('\n')
	if err != nil {
		return err
	}

	// Parse string into slice of Endpoint.
	clients := strings.Split(strings.ToLower(strings.Trim(clientsRaw, "\n ")), ";")

	// Prepare internal state tracking objects.
	node.KnownClients = make(map[string]*Endpoint)
	node.ChooseClients = make([]string, 0, len(clients))

	for i := range clients {

		client := strings.Split(clients[i], ",")

		if node.PubLisAddr != client[0] {

			// Parse contained public key in hex
			// representation to byte slice.
			pubKey := new([32]byte)
			pubKeyRaw, err := hex.DecodeString(client[1])
			if err != nil {
				return err
			}
			copy(pubKey[:], pubKeyRaw)

			// Parse contained TLS certificate in
			// hex representation to byte slice.
			pubCertPEM, err := hex.DecodeString(client[2])
			if err != nil {
				return err
			}

			// Create new empty cert pool.
			certPool := x509.NewCertPool()

			// Attempt to add received certificate to pool.
			ok := certPool.AppendCertsFromPEM(pubCertPEM)
			if !ok {
				return fmt.Errorf("failed to add received client's certificate to empty pool")
			}

			// Append as new Endpoint to map.
			node.KnownClients[client[0]] = &Endpoint{
				Addr:        client[0],
				PubKey:      pubKey,
				PubCertPool: certPool,
			}

			// Also append only the adress to
			// clients slice for cover traffic.
			node.ChooseClients = append(node.ChooseClients, client[0])
		}
	}

	return nil
}

// ConfigureChainMatrix parses the received
// set of cascade candidates and executes
// the deterministic cascades election that
// are captured in chain matrix afterwards.
func (node *Node) ConfigureChainMatrix(connRead *bufio.Reader, connWrite quic.Stream) error {

	// Receive candidates string from PKI.
	candsMsg, err := connRead.ReadString('\n')
	if err != nil {
		return err
	}

	fmt.Printf("Candidates broadcast received!\n")

	// Parse list of addresses and public keys
	// received from PKI into candidates slice.
	candsLines := strings.Split(strings.ToLower(strings.Trim(candsMsg, "\n ")), ";")
	cands := make([]*Endpoint, len(candsLines))

	for i := range candsLines {

		candsParts := strings.Split(candsLines[i], ",")

		// Parse contained public key in hex
		// representation to byte slice.
		pubKey := new([32]byte)
		pubKeyRaw, err := hex.DecodeString(candsParts[1])
		if err != nil {
			return err
		}
		copy(pubKey[:], pubKeyRaw)

		// Parse contained TLS certificate in
		// hex representation to byte slice.
		pubCertPEM, err := hex.DecodeString(candsParts[2])
		if err != nil {
			return err
		}

		// Create new empty cert pool.
		certPool := x509.NewCertPool()

		// Attempt to add received certificate to pool.
		ok := certPool.AppendCertsFromPEM(pubCertPEM)
		if !ok {
			return fmt.Errorf("failed to add received mix' certificate to empty pool")
		}

		cands[i] = &Endpoint{
			Addr:        candsParts[0],
			PubKey:      pubKey,
			PubCertPool: certPool,
		}
	}

	// Sort candidates deterministically.
	sort.Slice(cands, func(i, j int) bool {
		return string(cands[i].Addr) < string(cands[j].Addr)
	})

	// We will mock the execution of a VDF here.
	// In the future, this should obviously be replaced
	// by an appropriate choice of an actual VDF, until
	// then we simulate the execution environment by
	// accepting a shared random string that will seed
	// a PRNG from which each node determines the cascade
	// mixes deterministically and offline.

	if len(cands) != (NumCascades * LenCascade) {
		return fmt.Errorf("received candidates set of unexpected length, saw: %d, expected: %d", len(cands), (NumCascades * LenCascade))
	}

	node.ChainMatrix = make([][]*Endpoint, NumCascades)

	for c := 0; c < NumCascades; c++ {

		chain := make([]*Endpoint, LenCascade)

		// Extract next-up candidate from list.
		for m := 0; m < LenCascade; m++ {
			chain[m] = cands[((c * LenCascade) + m)]
		}

		// Integrate new chain into matrix.
		node.ChainMatrix[c] = chain
	}

	// Signal channel node.ChainMatrixConfigured.
	node.ChainMatrixConfigured <- struct{}{}

	return nil
}

// HandlePKIMsgs runs in a loop waiting for
// incoming messages from the PKI. Usually,
// they will contain cascade candidates.
func (node *Node) HandlePKIMsgs() {

	for {

		// Wait for incoming connections from PKI.
		session, err := node.PKIListener.Accept()
		if err != nil {
			fmt.Printf("Error accepting connection from PKI: %v\n", err)
			continue
		}

		// Upgrade session to synchronous stream.
		connWrite, err := session.AcceptStream()
		if err != nil {
			fmt.Printf("Failed accepting incoming stream from PKI: %v\n", err)
			continue
		}

		// Create buffered I/O reader from connection.
		connRead := bufio.NewReader(connWrite)

		go node.ConfigureChainMatrix(connRead, connWrite)
	}
}
