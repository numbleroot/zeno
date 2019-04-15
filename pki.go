package main

import (
	"bufio"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"

	"github.com/lucas-clemente/quic-go"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
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
	node.Clients = make([]*Endpoint, len(clients))
	node.ClientsByAddress = make(map[string]int)

	for i := range clients {

		clientParts := strings.Split(clients[i], ",")

		// Parse contained public key in hex
		// representation to byte slice.
		pubKey := new([32]byte)
		pubKeyRaw, err := hex.DecodeString(clientParts[1])
		if err != nil {
			return err
		}
		copy(pubKey[:], pubKeyRaw)

		// Parse contained TLS certificate in
		// hex representation to byte slice.
		pubCertPEM, err := hex.DecodeString(clientParts[2])
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

		client := &Endpoint{
			Addr:        clientParts[0],
			PubKey:      pubKey,
			PubCertPool: certPool,
		}

		// Add as new Endpoint to slice of clients.
		node.Clients[i] = client
	}

	// Sort clients deterministically.
	sort.Slice(node.Clients, func(i, j int) bool {
		return node.Clients[i].Addr < node.Clients[j].Addr
	})

	// Add index into slice for each client under
	// its address to map.
	for i := range node.Clients {
		node.ClientsByAddress[node.Clients[i].Addr] = i
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

	// Enforce the minimum number of mix
	// candidates to be present.
	if len(cands) < (NumCascades * LenCascade) {
		return fmt.Errorf("received candidates set of unexpected length, saw: %d, expected: %d", len(cands), (NumCascades * LenCascade))
	}

	// Sort candidates deterministically.
	sort.Slice(cands, func(i, j int) bool {
		return cands[i].Addr < cands[j].Addr
	})

	// We will mock the execution of a VDF here.
	// In the future, this should obviously be replaced
	// by an appropriate choice of an actual VDF, until
	// then we simulate the execution environment by
	// accepting a shared random string that will seed
	// a PRNG from which each node determines the cascade
	// mixes deterministically and offline.

	// Cycle through candidates and incorporate
	// all public keys into the state for the
	// SHAKE256 hash.
	hash := sha3.NewShake256()
	for i := range cands {

		_, err := hash.Write(cands[i].PubKey[:])
		if err != nil {
			return fmt.Errorf("failed adding candidate's public key to SHAKE hash: %v", err)
		}
	}

	// Create resulting hash of 64 bytes.
	candsPass := make([]byte, 64)
	hash.Read(candsPass)

	// Use hash as password to password generation
	// function scrypt with empty salt. Read 8 bytes
	// output secret.
	scryptPass, err := scrypt.Key(candsPass, nil, 131072, 8, 2, 8)
	if err != nil {
		return fmt.Errorf("scrypt operation for PRNG seed failed: %v", err)
	}

	// Interpret 8 byte scrypt secret as unsigned
	// 64 bit integer which we will use as the
	// seed to math.Rand.
	seed := binary.LittleEndian.Uint64(scryptPass)

	// Seed math.Rand with created seed.
	prng := rand.New(rand.NewSource(int64(seed)))

	// Prepare appropriately sized chain matrix.
	node.ChainMatrix = make([][]*Endpoint, NumCascades)

	// Prepare auxiliary map to track drawn values.
	drawnValues := make(map[int]bool)

	for c := 0; c < NumCascades; c++ {

		chain := make([]*Endpoint, LenCascade)

		for m := 0; m < LenCascade; m++ {

			// Draw pseudo-random number representing
			// index in candidates set to fill position.
			idx := prng.Intn(len(cands))

			// As long as we draw numbers that we have
			// used before, continue drawing.
			_, drawn := drawnValues[idx]
			for drawn {
				idx = prng.Intn(len(cands))
				_, drawn = drawnValues[idx]
			}

			// Add fresh mix to current chain.
			chain[m] = cands[idx]

			// Mark index as drawn.
			drawnValues[idx] = true
		}

		// Integrate new chain into matrix.
		node.ChainMatrix[c] = chain
	}

	fmt.Printf("Final matrix:\n")
	for i := range node.ChainMatrix {

		fmt.Printf("\tCASC %d: ", i)
		for j := range node.ChainMatrix[i] {

			if j == (len(node.ChainMatrix[i]) - 1) {
				fmt.Printf("%s", node.ChainMatrix[i][j].Addr)
			} else {
				fmt.Printf("%s => ", node.ChainMatrix[i][j].Addr)
			}
		}
		fmt.Printf("\n")
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
