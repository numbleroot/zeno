package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"

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

	var resp string

	for resp != "0" {

		// Connect to PKI TLS endpoint.
		session, err := quic.DialAddr(node.PKIAddr, node.PKITLSConfAsClient, nil)
		if err != nil {
			return err
		}

		fmt.Printf("\nConnected to PKI at %s.\n", node.PKIAddr)

		// Upgrade session to blocking stream.
		connWrite, err := session.OpenStreamSync()
		if err != nil {
			return err
		}

		// Create buffered I/O reader from connection.
		connRead := bufio.NewReader(connWrite)

		// Register this node's intent on participating
		// in a particular role with the PKI.
		fmt.Fprintf(connWrite, "%s %s %s %x %x\n", category, node.PubLisAddr, node.PKILisAddr, *node.RecvPubKey, node.PubCertPEM)

		// Expect an acknowledgement.
		resp, err = connRead.ReadString('\n')
		if err != nil {
			return err
		}

		// Verify cleaned response.
		resp = strings.ToLower(strings.Trim(resp, "\n "))
		if resp == "2" {

			// Wrong phase in epoch protocol.
			// Wait a bit and try again.
			fmt.Printf("Registration for %s at PKI was inconvenient. Waiting %v and trying again...\n", category, (1 * time.Second))
			time.Sleep(1 * time.Second)

		} else if resp != "0" {
			return fmt.Errorf("PKI returned failure response to mix intent registration: %s", resp)
		}
	}

	return nil
}

// ElectMixes accepts the slice of strings
// carrying mix candidates and performs all
// the necessary steps to end up with the
// shared cascades matrix at the end.
func (node *Node) ElectMixes(data []string) error {

	mockVDFTicker := time.NewTicker(1 * EpochBrick)

	// Parse list of addresses and public keys
	// received from PKI into candidates slice.
	cands := make([]*Endpoint, len(data))

	for i := range data {

		candsParts := strings.Split(data[i], ",")

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
	// then we simulate the execution environment.

	// Cycle through candidates and incorporate all
	// public keys into the state for the SHAKE256 hash.
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

	// Prepare appropriately sized cascades matrix.
	node.NextCascadesMatrix = make([][]*Endpoint, NumCascades)

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
		node.NextCascadesMatrix[c] = chain
	}

	fmt.Printf("Upcoming cascades matrix:\n")
	for i := range node.NextCascadesMatrix {

		fmt.Printf("\tCASC %d: ", i)
		for j := range node.NextCascadesMatrix[i] {

			if j == (len(node.NextCascadesMatrix[i]) - 1) {
				fmt.Printf("%s", node.NextCascadesMatrix[i][j].Addr)
			} else {
				fmt.Printf("%s => ", node.NextCascadesMatrix[i][j].Addr)
			}
		}
		fmt.Printf("\n")
	}

	// Wait for ticker signal for proper
	// mocking of a VDF execution.
	<-mockVDFTicker.C

	return nil
}

// ParseClients parses the received set
// of clients and incorporates them in
// the correct places in local structures.
func (node *Node) ParseClients(data []string) error {

	// Prepare state structure.
	clients := make([]*Endpoint, len(data))

	for i := range data {

		clientParts := strings.Split(data[i], ",")

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

		// Add as new Endpoint to slice of clients.
		clients[i] = &Endpoint{
			Addr:        clientParts[0],
			PubKey:      pubKey,
			PubCertPool: certPool,
		}
	}

	// Sort clients deterministically.
	sort.Slice(clients, func(i, j int) bool {
		return clients[i].Addr < clients[j].Addr
	})

	// Set internal clients structure to created one.
	node.NextClients = clients
	node.NextClientsByAddress = make(map[string]int)

	// Add index into slice for each client under
	// its address to map.
	for i := range node.NextClients {
		node.NextClientsByAddress[node.NextClients[i].Addr] = i
	}

	return nil
}

// HandleMsgFromPKI parses the received message
// from the PKI and takes appropriate steps
// after having parsed it.
func (node *Node) HandleMsgFromPKI(connRead *bufio.Reader, connWrite quic.Stream) {

	// Receive data as string from PKI.
	dataRaw, err := connRead.ReadString('\n')
	if err != nil {
		fmt.Printf("Error receiving data from PKI: %v\n", err)
		return
	}

	// Split raw data at semicola. First line
	// determines which type of data this
	// broadcast carries.
	data := strings.Split(strings.ToLower(strings.Trim(dataRaw, "\n ")), ";")

	switch data[0] {
	case "mixes":

		fmt.Printf("PKI mix candidates broadcast received!\n")

		// Determine mix nodes based on received data.
		err = node.ElectMixes(data[1:])
		if err != nil {
			fmt.Printf("Cascades election failed: %v\n", err)
			return
		}

		// Signal completion to main routine.
		node.SigMixesElected <- struct{}{}

	case "clients":

		fmt.Printf("PKI clients broadcast received!\n")

		// Parse set of clients and store internally.
		err = node.ParseClients(data[1:])
		if err != nil {
			fmt.Printf("Parsing received set of clients failed: %v\n", err)
			return
		}

		// Signal completion to main routine.
		node.SigClientsAdded <- struct{}{}

	case "epoch":

		fmt.Printf("PKI epoch rotation signal received!\n")

		// Signal epoch rotation to main routine.
		node.SigRotateEpoch <- struct{}{}
	}
}

// AcceptMsgsFromPKI runs in a loop waiting for
// and acting upon messages from the PKI.
func (node *Node) AcceptMsgsFromPKI() {

	fmt.Printf("Waiting for PKI messages...\n")

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

		go node.HandleMsgFromPKI(connRead, connWrite)
	}
}

// PrepareNextEpoch takes care of registering
// a node under the intended role with the PKI,
// waits for signals of the PKI on sent data
// such as mix candidates and clients, and acts
// upon those data sets.
func (node *Node) PrepareNextEpoch(isMix bool, isClient bool) (bool, error) {

	if isMix {

		// Nodes that offer to take up a mix role
		// register their intent with the PKI.
		err := node.RegisterAtPKI("mixes")
		if err != nil {
			return false, fmt.Errorf("failed to register mix intent: %v", err)
		}

	} else if isClient {

		// Nodes that are regular clients in the
		// system register with their address and
		// receive public key at the PKI.
		err := node.RegisterAtPKI("clients")
		if err != nil {
			return false, fmt.Errorf("failed to register as client: %v", err)
		}
	}

	fmt.Printf("\nRegistered at PKI, waiting for mix election to finish\n")

	// Wait for signal that the cascades matrix
	// has been computed.
	<-node.SigMixesElected

	elected := false

	if isMix {

		// Figure out whether the mix intent of this
		// node resulted in it getting elected.
		for chain := range node.NextCascadesMatrix {

			for m := range node.NextCascadesMatrix[chain] {

				if bytes.Equal(node.NextCascadesMatrix[chain][m].PubKey[:], node.RecvPubKey[:]) {
					elected = true
					break
				}
			}

			if elected {
				break
			}
		}

		if !elected {

			fmt.Printf("Node %s wanted to be a mix, but was not elected.\n", node.PubLisAddr)

			// This node intended to become a mix yet did
			// not get elected. Register as regular client.
			err := node.RegisterAtPKI("clients")
			if err != nil {
				return elected, fmt.Errorf("failed to late-register as client: %v", err)
			}

		} else {
			fmt.Printf("Node %s has been elected to be a mix.\n", node.PubLisAddr)
		}
	}

	fmt.Printf("\nMixes determined, waiting for clients to be broadcast\n")

	// Wait for signal that set of clients for
	// upcoming epoch has been received and parsed.
	<-node.SigClientsAdded

	fmt.Printf("\nShall the regular rounds begin!\n")

	return elected, nil
}
