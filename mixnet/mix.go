package mixnet

import (
	"fmt"
	"net"

	"github.com/numbleroot/zeno/messages"
	"zombiezen.com/go/capnproto2/rpc"
)

type Mix struct {
	*Node
	Listener net.Listener
}

func (mix *Mix) AcceptBatch(call messages.Mix_acceptBatch) error {

	data, err := call.Params.Batch()
	if err != nil {
		return err
	}

	fmt.Printf("\nReceived: '%#v'\n", data)

	call.Results.SetAck("Batch received!")

	return nil
}

func (mix *Mix) Run() error {

	fmt.Printf("Mix.Name: '%s'\nMix.PKey: '%x'\nMix.SKey: '%x'\n", mix.Name, *mix.PKey, *mix.SKey)

	c, err := mix.Listener.Accept()
	if err != nil {
		return err
	}

	main := messages.Mix_ServerToClient(mix)
	conn := rpc.NewConn(rpc.StreamTransport(c), rpc.MainInterface(main.Client))
	err = conn.Wait()

	return err
}
