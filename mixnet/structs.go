package mixnet

import "net"

type Endpoint struct {
	Addr   string
	PubKey *[32]byte
}

// Node collects the basic information
// any node in our system works with.
type Node struct {
	RecvPubKey       *[32]byte
	RecvSecKey       *[32]byte
	PKIListener      net.Listener
	ChainMatrixBuilt chan struct{}
	ChainMatrix      [][]Endpoint
}

// Client packages information required
// for running a client.
type Client struct {
	*Node
}

type EntryMix struct {
	*Node
	PubListener net.Listener
}

type CommonMix struct {
	*Node
	PubListener net.Listener
}
