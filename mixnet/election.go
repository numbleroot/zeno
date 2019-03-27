package mixnet

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
)

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

		cands[i] = &Endpoint{
			Addr:   candsParts[0],
			PubKey: pubKey,
		}
	}

	// Sort candidates deterministically.
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

// SetOwnPlace sets important indices into
// chain matrix for a just elected mix.
func (mix *Mix) SetOwnPlace() {

	breakHere := false

	for chain := range mix.ChainMatrix {

		for m := range mix.ChainMatrix[chain] {

			if bytes.Equal(mix.ChainMatrix[chain][m].PubKey[:], mix.RecvPubKey[:]) {

				// If we found this mix' place in the
				// chain matrix, set values and signal
				// to break from loops.
				mix.OwnChain = chain
				mix.OwnIndex = m

				if m == 0 {
					mix.IsEntry = true
				} else if m == (len(mix.ChainMatrix[chain]) - 1) {
					mix.IsExit = true
				}

				breakHere = true
				break
			}
		}

		if breakHere {
			break
		}
	}
}
