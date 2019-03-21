package mixnet

import (
	"fmt"
	"net"

	"github.com/numbleroot/zeno/rpc"
	"golang.org/x/net/context"
	capnprpc "zombiezen.com/go/capnproto2/rpc"
)

// Run provides the main execution
// logic of a client.
func (cl *Client) Run() error {

	ctx := context.Background()

	c, err := net.Dial("tcp", "127.0.0.1:11000")
	if err != nil {
		return err
	}

	conn := capnprpc.NewConn(capnprpc.StreamTransport(c))
	defer conn.Close()

	entry := rpc.Mix{
		Client: conn.Bootstrap(ctx),
	}

	status, err := entry.AddConvoMsg(ctx, func(p rpc.Mix_addConvoMsg_Params) error {

		msg, err := p.NewMsg()
		if err != nil {
			return err
		}

		msg.SetContent([]byte("test payload!"))

		return nil

	}).Struct()
	if err != nil {
		return err
	}

	fmt.Printf("\nReceived status reply: '%#v'\n", status)

	return nil
}
