package mixnet

import (
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/numbleroot/zeno/rpc"
)

// Endpoint describes a network-reachable
// entity on address associated with a
// public key.
type Endpoint struct {
	Addr   []byte
	PubKey *[32]byte
}

// OnionKeyState collects the keys we need
// for an onion-encrypted message: the PubKey
// to prepend to the ciphertext symmetrically
// encrypted with SymKey.
type OnionKeyState struct {
	Nonce  *[24]byte
	PubKey *[32]byte
	SymKey *[32]byte
}

// ConvoMsg represents the struct to be sent
// from client to entry mix containing the
// public key used to encrypt the first onion
// layer, the message itself, and within the
// message also the nonce used to encrypt.
type ConvoMsg struct {
	PubKey  *[32]byte
	Content []byte
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
	PubListener           quic.Listener
	ChainMatrixConfigured chan struct{}
	ChainMatrix           [][]*Endpoint
	KnownClients          []*Endpoint
}

// Client represents a client node in
// our system architecture.
type Client struct {
	*Node
	SendWG     *sync.WaitGroup
	EntryConns []*rpc.Mix
	CurRound   [][]*OnionKeyState
	PrevRound  [][]*OnionKeyState
}

// Mix represents a mix node in our
// system architecture.
type Mix struct {
	*Node
	OwnChain    int
	OwnIndex    int
	IsEntry     bool
	IsExit      bool
	Successor   *rpc.Mix
	RoundTicker *time.Ticker
	muAddMsgs   *sync.Mutex
	ClientsSeen map[string]bool
	FirstPool   []*rpc.ConvoMsg
	SecPool     []*rpc.ConvoMsg
	ThirdPool   []*rpc.ConvoMsg
	NextPool    []*rpc.ConvoMsg
	OutPool     []*rpc.ConvoMsg
}
