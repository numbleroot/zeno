package main

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/numbleroot/zeno/rpc"
)

// PKIRegistration bundles all information
// required for a node to register under
// various categories with the PKI.
type PKIRegistration struct {
	Category       uint8
	PubAddr        string
	PubKey         *[32]byte
	PubCertPEM     []byte
	ContactAddr    string
	ContactCertPEM []byte
}

// Endpoint describes a network-reachable
// entity on address associated with a
// public key.
type Endpoint struct {
	Addr        string
	PubKey      *[32]byte
	PubCertPool *x509.CertPool
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

// TODO: Make all Pub* elements also
//       available in CurPub* and NextPub*
//       variants and switch accordingly
//       after PrepareUpcomingEpoch().
// Node collects the basic information
// any node in our system works with.
type Node struct {
	RecvPubKey           *[32]byte
	RecvSecKey           *[32]byte
	PubLisAddr           string
	PubTLSConfAsServer   *tls.Config
	PubCertPEM           []byte
	PubListener          quic.Listener
	PKIAddr              string
	PKILisAddr           string
	PKITLSConfAsClient   *tls.Config
	PKITLSConfAsServer   *tls.Config
	PKICertPEM           []byte
	PKIListener          quic.Listener
	SigRotateEpoch       chan struct{}
	SigCloseEpoch        chan struct{}
	SigMixesElected      chan struct{}
	SigClientsAdded      chan struct{}
	CurCascadesMatrix    [][]*Endpoint
	NextCascadesMatrix   [][]*Endpoint
	CurClients           []*Endpoint
	CurClientsByAddress  map[string]int
	NextClients          []*Endpoint
	NextClientsByAddress map[string]int
}

// Client represents a client node in
// our system architecture.
type Client struct {
	*Node
	SendWG    *sync.WaitGroup
	CurRound  [][]*OnionKeyState
	PrevRound [][]*OnionKeyState
}

// Mix represents a mix node in our
// system architecture.
type Mix struct {
	*Node
	OwnChain    int
	OwnIndex    int
	IsEntry     bool
	IsExit      bool
	Successor   quic.Stream
	RoundTicker *time.Ticker
	muAddMsgs   *sync.Mutex
	ClientsSeen map[string]bool
	FirstPool   []*rpc.ConvoMsg
	SecPool     []*rpc.ConvoMsg
	ThirdPool   []*rpc.ConvoMsg
	NextPool    []*rpc.ConvoMsg
	OutPool     []*rpc.ConvoMsg
}
