package main

import (
	"context"

	"lambda/pkg/apiserver"
)

func main() {
	apiserver.Run(context.Background())
}
