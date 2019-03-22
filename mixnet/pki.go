package mixnet

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"os"
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
	// as a mix node by posting its receive public key
	// and a TLS certificate for the PKI to connect with.
	fmt.Fprintf(connWrite, "post mixes %x\n", *node.RecvPubKey)

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
	fmt.Fprintf(connWrite, "post clients %x\n", *node.RecvPubKey)

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
	fmt.Fprintf(connWrite, "quit\n")
	connWrite.Close()

	return nil
}

func (node *Node) ConfigureChainMatrix(connRead *bufio.Reader, connWrite net.Conn) error {

	fmt.Printf("Candidates broadcast received!\n")

	fmt.Fprintf(connWrite, "0\n")

	// TODO: Parse list of addresses and public keys
	//       received from PKI into candidates slice.

	// TODO: Sort candidates deterministically.

	// TODO: Run VDF over candidates. Output is a
	//       sequence of mixes of size c = s x l.

	// TODO: Walk through sequence and fill ChainMatrix
	//       accordingly. If we see our address and
	//       public key, set flag whether we are an
	//       entry mix or a common one.

	// TODO: Signal channel node.ChainMatrixConfigured.
	node.ChainMatrixConfigured <- struct{}{}

	return nil
}

func (node *Node) HandlePKIMsgs() {

	for {

		// Wait for incoming connections from PKI.
		connWrite, err := node.PKIListener.Accept()
		if err != nil {
			fmt.Printf("PKI connection error: %v\n", err)
			continue
		}

		// Create buffered I/O reader from connection.
		connRead := bufio.NewReader(connWrite)

		go node.ConfigureChainMatrix(connRead, connWrite)
	}
}
