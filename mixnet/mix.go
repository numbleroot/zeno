package mixnet

import (
    "fmt"
)

type Mix struct {
    *Node
}

func (m *Mix) Run() error {

    fmt.Printf("Mix.Name: '%s'\nMix.PKey: '%x'\nMix.SKey: '%x'\n", m.Name, *m.PKey, *m.SKey)

    return nil
}
