package main

import (
	"fmt"
)

func foo() {
	var a int = 10
	var b int = a
	if !(b == 10) {
		panic("assert")
	}
	fmt.Printf("%v\n", b)
}

func main() {
	foo()
}
