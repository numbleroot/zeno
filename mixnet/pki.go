package mixnet

import (
	"bufio"
	"fmt"
	"net"
)

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
