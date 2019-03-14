package mixnet

import (
    "fmt"
)

type Mix struct {
    *Node
}

func (m *Mix) Run() error {

    fmt.Printf("Mix.Name: '%s'\nMix.PKey: '%s'\nMix.SKey: '%s'\n", m.Name, m.PKey, m.SKey)

    return nil
}
