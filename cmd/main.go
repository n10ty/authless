package main

import (
	"fmt"
	"regexp"
)

func main() {
	r, _ := regexp.Compile("\\S+@\\S+\\.\\S+")

	fmt.Println(r.Match([]byte("a@d.d")))
}
