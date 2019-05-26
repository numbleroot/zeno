package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"sync"
	"time"

	"github.com/numbleroot/zeno/rpc"
)

// PKIRegistration bundles all information
// required for a node to register under
// various categories with the PKI.
type PKIRegistration struct {
	Category       uint8
	Name           string
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
	Name        string
	Addr        string
	PubKey      *[32]byte
	PubCertPool *x509.CertPool
}

// FlatEndpoint is identical to Endpoint
// except that it stores values instead
// of references.
type FlatEndpoint struct {
	Name        string
	Addr        string
	PubKey      [32]byte
	PubCertPool x509.CertPool
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
	Name                   string
	Partner                *Endpoint
	PubLisAddr             string
	PubListener            net.Listener
	RoundCounter           int
	SigRotateEpoch         chan struct{}
	SigCloseEpoch          chan struct{}
	SigMixesElected        chan struct{}
	SigClientsAdded        chan struct{}
	CurRecvPubKey          *[32]byte
	CurRecvSecKey          *[32]byte
	CurPubTLSConfAsServer  *tls.Config
	CurPubCertPEM          []byte
	NextRecvPubKey         *[32]byte
	NextRecvSecKey         *[32]byte
	NextPubTLSConfAsServer *tls.Config
	NextPubCertPEM         []byte
	PKIAddr                string
	PKILisAddr             string
	PKITLSConfAsClient     *tls.Config
	PKITLSConfAsServer     *tls.Config
	PKICertPEM             []byte
	PKIListener            net.Listener
	CurCascadesMatrix      [][]*Endpoint
	NextCascadesMatrix     [][]*Endpoint
	CurClients             []*Endpoint
	CurClientsByAddress    map[string]chan []byte
	NextClients            []*Endpoint
	IsEval                 bool
	MetricsPipe            *os.File
}

// Client represents a client node in
// our system architecture.
type Client struct {
	*Node
	muUpdState   *sync.RWMutex
	IsClient     bool
	NumMsgToRecv int
}

// Mix represents a mix node in our
// system architecture.
type Mix struct {
	*Node
	OwnChain         int
	OwnIndex         int
	IsEntry          bool
	IsExit           bool
	Successor        *tls.Conn
	RoundTicker      *time.Ticker
	muAddMsgs        *sync.Mutex
	ClientsSeen      map[string]bool
	FirstPool        []*rpc.ConvoMsg
	SecPool          []*rpc.ConvoMsg
	ThirdPool        []*rpc.ConvoMsg
	NextPool         []*rpc.ConvoMsg
	OutPool          []*rpc.ConvoMsg
	KillMixesInRound int
}

// ClientSendResult is used by the sending
// goroutines in clients when returning the
// response and time measurement back to caller.
type ClientSendResult struct {
	Status uint8
	Time   int64
}
