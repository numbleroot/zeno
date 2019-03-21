package mixnet

import (
	"fmt"
	"net"

	"github.com/numbleroot/zeno/rpc"
	capnprpc "zombiezen.com/go/capnproto2/rpc"
)

func (mix *CommonMix) AddBatch(call rpc.CommonMix_addBatch) error {

	data, err := call.Params.Batch()
	if err != nil {
		return err
	}

	fmt.Printf("\nAddBatch req: '%#v'\n", data)

	call.Results.SetStatus(0)

	return nil
}

func (mix *CommonMix) HandleMsg(c net.Conn) {

	main := rpc.CommonMix_ServerToClient(mix)
	conn := capnprpc.NewConn(capnprpc.StreamTransport(c), capnprpc.MainInterface(main.Client))

	err := conn.Wait()
	if err != nil {
		fmt.Printf("Error waiting for public connection: %v\n", err)
	}
}
