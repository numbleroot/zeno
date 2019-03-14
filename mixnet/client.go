package mixnet

import (
	"fmt"
	"net"

	"github.com/numbleroot/zeno/messages"
	"golang.org/x/net/context"
	"zombiezen.com/go/capnproto2/rpc"
)

type Client struct {
	*Node
}

func (cl *Client) Run() error {

	fmt.Printf("Client.Name: '%s'\nClient.PKey: '%x'\nClient.SKey: '%x'\n", cl.Name, *cl.PKey, *cl.SKey)

	ctx := context.Background()

	c, err := net.Dial("tcp", "127.0.0.1:11000")
	if err != nil {
		return err
	}

	conn := rpc.NewConn(rpc.StreamTransport(c))
	defer conn.Close()

	sender := messages.Mix{
		Client: conn.Bootstrap(ctx),
	}

	call := sender.AcceptBatch(ctx, func(p messages.Mix_acceptBatch_Params) error {

		batch, err := p.NewBatch()
		if err != nil {
			return err
		}

		batch.SetComment("This is a first try!")

		return nil

	})

	ack, err := call.Struct()
	if err != nil {
		return err
	}

	fmt.Printf("\nReceived acknowledgement: '%#v'\n", ack)

	return nil
}
