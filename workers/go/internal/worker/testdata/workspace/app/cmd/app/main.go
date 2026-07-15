package main

import (
	"fmt"

	"example.com/app/lib"
	"example.com/shared"
	_ "example.net/external/pkg"
	"example.net/vendored/pkg"
)

func main() {
	fmt.Println(lib.Message, shared.Name, pkg.Name)
}
