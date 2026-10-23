//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "memfdrun: cenário só para Linux (laboratório)")
	os.Exit(1)
}
