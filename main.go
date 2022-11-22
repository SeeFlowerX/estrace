package main

import (
	"estrace/cli"

	_ "github.com/shuLhan/go-bindata" // add for bindata in Makefile
)

func main() {
	cli.Start()
}
