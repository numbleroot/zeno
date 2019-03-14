package mixnet

import (
    "fmt"
)

type Client struct {
    *Node
}

func (c *Client) Run() error {

    fmt.Printf("Client.Name: '%s'\nClient.PKey: '%x'\nClient.SKey: '%x'\n", c.Name, *c.PKey, *c.SKey)

    return nil
}
