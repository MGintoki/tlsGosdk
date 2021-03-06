package main

import (
	"fmt"
	"github.com/labstack/echo"
	"github.com/pretty66/gosdk"
)

func main() {
	e := echo.New()
	gosdk.LoadMidRoute(e)
	err := e.Start(":8086")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("start echo")

}
