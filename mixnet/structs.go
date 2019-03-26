package mixnet

import (
	"crypto/tls"
	"net"
	"sync"

	"github.com/numbleroot/zeno/rpc"
)

// Endpoint describes a network-reachable
// entity on address associated with a
// public key.
type Endpoint struct {
	Addr   string
	PubKey *[32]byte
}

// OnionKeyPair collects the keys we need
// for an onion-encrypted message: the PubKey
// to prepend to the ciphertext symmetrically
// encrypted with SymKey.
type OnionKeyPair struct {
	PubKey *[32]byte
	SymKey *[32]byte
}

// RoundClient bundles all objects
// required for a client to participate
// in a zeno round.
type RoundClient struct {
	Nonce   *[24]byte
	MsgKeys [][]*OnionKeyPair
}

type RoundMix struct {
}

// Node collects the basic information
// any node in our system works with.
type Node struct {
	RecvPubKey            *[32]byte
	RecvSecKey            *[32]byte
	PKIAddr               string
	PKILisAddr            string
	PKITLSConf            *tls.Config
	PKIListener           net.Listener
	PubLisAddr            string
	PubListener           net.Listener
	ChainMatrixConfigured chan struct{}
	ChainMatrix           [][]*Endpoint
}

// Client represents a client node in
// our system architecture.
type Client struct {
	*Node
	SendWG     *sync.WaitGroup
	EntryConns []*rpc.Mix
	CurRound   *RoundClient
	PrevRound  *RoundClient
}

// Mix represents a mix node in our
// system architecture.
type Mix struct {
	*Node
	IsEntry bool
}
