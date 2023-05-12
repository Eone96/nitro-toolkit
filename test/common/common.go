package common

import (
	nitroToolkit "github.com/anyswap/nitro-toolkit"
)

type Payload struct {
	ID        int
	Cmd       string
	IAMToken  *nitroToolkit.IAMToken
	KmsConfig *nitroToolkit.KmsConfig
	Data      []byte
}

type Response struct {
	ID     int
	ErrMsg string
	Data   []byte
}
