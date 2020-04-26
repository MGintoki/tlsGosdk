package middle

import (
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

func init() {
	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	LoadMidRoute(e)

}
