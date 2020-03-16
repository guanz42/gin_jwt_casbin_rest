package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

// User demo
type User struct {
	UserName  string
	FirstName string
	LastName  string
}

func main() {

	r := gin.Default()

	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:            "gz jwt",
		SigningAlgorithm: "HS256",
		Key:              []byte("hello world"),
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour,
		// 认证
		Authenticator: func(c *gin.Context) (i interface{}, err error) {
			var loginVal login
			if err := c.ShouldBind(&loginVal); err != nil {
				return "", jwt.ErrMissingLoginValues
			}

			username := loginVal.Username
			password := loginVal.Password

			if (username == "admin" && password == "admin") || (username == "test" && password == "test") {
				return &User{
					UserName:  username,
					LastName:  "Bo-Yi",
					FirstName: "Wu",
				}, nil
			}

			return nil, jwt.ErrFailedAuthentication
		},
		// 授权
		Authorizator: func(data interface{}, c *gin.Context) bool {
			if v, ok := data.(*User); ok && v.UserName == "admin" {
				return true
			}

			return false
		},
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*User); ok {
				return jwt.MapClaims{
					"id": v.UserName,
				}
			}
			return jwt.MapClaims{}
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(http.StatusOK, gin.H{
				"code":    code,
				"message": "message",
				"status":  "Unauthorized",
			})
		},
		LoginResponse:   nil,
		LogoutResponse:  nil,
		RefreshResponse: nil,
		//IdentityHandler:       nil,
		//IdentityKey:           "",
		TokenLookup: "header: Authorization",
		//TokenHeadName:         "",
		//TimeFunc:              nil,
		//HTTPStatusMessageFunc: nil,
		//PrivKeyFile:           "",
		//PubKeyFile:            "",
		//SendCookie:            false,
		//SecureCookie:          false,
		//CookieHTTPOnly:        false,
		//CookieDomain:          "",
		//SendAuthorization:     false,
		//DisabledAbort:         false,
		//CookieName:            "",
	})

	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	r.POST("/login", authMiddleware.LoginHandler)

	auth := r.Group("/v1")
	auth.Use(authMiddleware.MiddlewareFunc())
	{
		auth.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"hello": "world",
			})
		})
	}

	// Start server
	if err := r.Run(); err != nil {
		fmt.Println("start server error, ", err.Error())
	}
}
