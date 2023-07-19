package cli

import (
	"estrace/cli/cmd"
	"fmt"
)

func Start() {
	cmd.Execute()
	fmt.Println("this is test pr,ok")
}
