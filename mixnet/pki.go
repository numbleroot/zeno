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
	fmt.Fprintf(connWrite, "post mixes %x\n", node.RecvPubKey)

	// Expect an acknowledgement.
	line, err := connRead.ReadString('\n')
	if err != nil {
		return err
	}

	// Verify cleaned response.
	line = strings.ToLower(strings.Trim(line, "\n "))
	if line != "0" {
		return fmt.Errorf("PKI returned failure response to mix intent registration: %s", line)
	}

	return nil
}

func (node *Node) ConfigureChainMatrix(connRead *bufio.Reader, connWrite net.Conn) {

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
