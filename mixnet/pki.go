package mixnet

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// Enable TLS 1.3.
func init() {
	os.Setenv("GODEBUG", fmt.Sprintf("%s,tls13=1", os.Getenv("GODEBUG")))
}

// RegisterMixIntent contacts the PKI server
// and registers this node's intent on participating
// as mix node with it.
func (node *Node) RegisterMixIntent() error {

	// Connect to PKI TLS endpoint.
	connWrite, err := tls.Dial("tcp", node.PKIAddr, node.PKITLSConf)
	if err != nil {
		return err
	}

	// Create buffered I/O reader from connection.
	connRead := bufio.NewReader(connWrite)

	// Register this node's intent on participating
	// as a mix node with the PKI.
	fmt.Fprintf(connWrite, "post mixes %s %x %s\n", node.PubLisAddr, *node.RecvPubKey, node.PKILisAddr)

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

	// Close connection.
	fmt.Fprintf(connWrite, "quit\n")
	connWrite.Close()

	return nil
}

// RegisterClient announces this node's address
// and receive public key as a client to the PKI.
func (node *Node) RegisterClient() error {

	// Connect to PKI TLS endpoint.
	connWrite, err := tls.Dial("tcp", node.PKIAddr, node.PKITLSConf)
	if err != nil {
		return err
	}

	// Create buffered I/O reader from connection.
	connRead := bufio.NewReader(connWrite)

	// Register this node as a client in the system.
	fmt.Fprintf(connWrite, "post clients %s %x %s\n", node.PubLisAddr, *node.RecvPubKey, node.PKILisAddr)

	// Expect an acknowledgement.
	resp, err := connRead.ReadString('\n')
	if err != nil {
		return err
	}

	// Verify cleaned response.
	resp = strings.ToLower(strings.Trim(resp, "\n "))
	if resp != "0" {
		return fmt.Errorf("PKI returned failure response to client registration: %s", resp)
	}

	// Close connection.
	connWrite.Close()

	return nil
}

// ConfigureChainMatrix parses the received
// set of cascade candidates and executes
// the deterministic cascades election that
// are captured in chain matrix afterwards.
func (node *Node) ConfigureChainMatrix(connRead *bufio.Reader, connWrite net.Conn) error {

	// Receive candidates string from PKI.
	candsMsg, err := connRead.ReadString('\n')
	if err != nil {
		return err
	}

	fmt.Printf("Candidates broadcast received!\n")

	// TODO: Parse list of addresses and public keys
	//       received from PKI into candidates slice.

	candsLines := strings.Split(strings.ToLower(strings.Trim(candsMsg, "\n ")), ";")
	cands := make([]*Endpoint, 0, len(candsLines))

	for line := range candsLines {

		candsParts := strings.Split(candsLines[line], ",")

		key := new([32]byte)
		keyRaw, err := hex.DecodeString(candsParts[1])
		if err != nil {
			return err
		}

		copy(key[:], keyRaw)

		cands = append(cands, &Endpoint{
			Addr:   candsParts[0],
			PubKey: key,
		})
	}

	// TODO: Sort candidates deterministically.
	sort.Slice(cands, func(i, j int) bool {
		return cands[i].Addr < cands[j].Addr
	})

	// TODO: Run VDF over candidates. Output is a
	//       sequence of mixes of size c = s x l.

	// TODO: Walk through sequence and fill ChainMatrix
	//       accordingly. If we see our address and
	//       public key, set flag whether we are an
	//       entry mix or a common one.
	node.ChainMatrix = [][]*Endpoint{
		cands,
	}

	// Signal channel node.ChainMatrixConfigured.
	node.ChainMatrixConfigured <- struct{}{}

	connWrite.Close()

	return nil
}

// HandlePKIMsgs runs in a loop waiting for
// incoming messages from the PKI. Usually,
// they will contain cascade candidates.
func (node *Node) HandlePKIMsgs() {

	for {

		// Wait for incoming connections from PKI.
		connWrite, err := node.PKIListener.Accept()
		if err != nil {
			fmt.Printf("Error accepting connection from PKI: %v\n", err)
			continue
		}

		// Create buffered I/O reader from connection.
		connRead := bufio.NewReader(connWrite)

		go node.ConfigureChainMatrix(connRead, connWrite)
	}
}
