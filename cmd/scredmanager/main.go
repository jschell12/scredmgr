package main

import (
	"os"

	"github.com/jschell12/scredmanager/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
