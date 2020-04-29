package middle

import (
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/pretty66/gosdk"
)

func init() {
	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	gosdk.LoadMidRoute(e)

}
