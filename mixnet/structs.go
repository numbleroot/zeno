package mixnet

import (
	"crypto/tls"
	"net"
	"sync"

	"github.com/numbleroot/zeno/rpc"
)

type Endpoint struct {
	Addr   string
	PubKey *[32]byte
}

// Node collects the basic information
// any node in our system works with.
type Node struct {
	ShutDown              chan struct{}
	RecvPubKey            *[32]byte
	RecvSecKey            *[32]byte
	PKIAddr               string
	PKITLSConf            *tls.Config
	PKIListener           net.Listener
	ChainMatrixConfigured chan struct{}
	ChainMatrix           [][]Endpoint
}

// Client packages information required
// for running a client.
type Client struct {
	*Node
	SendWG     *sync.WaitGroup
	EntryConns []*rpc.Mix
}

type Mix struct {
	*Node
	PubListener net.Listener
	IsEntry     bool
}
