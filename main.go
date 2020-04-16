package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/appleboy/gin-jwt/v2"
	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v2"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

const IdentityKey = "username"

func Authorization(e *casbin.Enforcer) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, exists := c.Get("username")
		if exists == false {
			fmt.Println("username not exists")
			c.Abort()
			return
		}

		fmt.Println("Authorization username: ", username)

		if username == "" {
			fmt.Println("headers invalid")
			c.JSON(200, gin.H{
				"code":    401,
				"message": "Unauthorized",
				"data":    "",
			})
			c.Abort()
			return
		}

		// 请求的path
		p := c.Request.URL.Path
		// 请求的方法
		m := c.Request.Method
		// 这里认证
		res, err := e.Enforce(username, p, m)

		if err != nil {
			fmt.Println("no permission")
			fmt.Println(err)
			c.JSON(200, gin.H{
				"code":    401,
				"message": "Unauthorized",
				"data":    "",
			})
			c.Abort()
			return
		}
		if !res {
			fmt.Println("permission check failed")
			c.JSON(200, gin.H{
				"code":    401,
				"message": "Unauthorized",
				"data":    "",
			})
			c.Abort()
			return
		}
		c.Next()
	}
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

			if (username == "administrator" && password == "administrator") || (username == "test" && password == "test") {
				return username, nil
			}

			return nil, jwt.ErrFailedAuthentication
		},
		// 授权
		Authorizator: nil,
		// 添加payload到jwt
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if _, ok := data.(string); ok {
				return jwt.MapClaims{
					IdentityKey: data,
				}
			}
			return jwt.MapClaims{}
		},
		// 未授权响应
		Unauthorized:    nil,
		LoginResponse:   nil,
		LogoutResponse:  nil,
		RefreshResponse: nil,
		IdentityHandler: nil,
		IdentityKey:     IdentityKey,
		TokenLookup:     "header: Authorization",
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

	a, _ := gormadapter.NewAdapter("mysql", "root:root@tcp(localhost)/")
	e, _ := casbin.NewEnforcer("authz_model.conf", a)
	e.EnableLog(true)

	_, _ = e.AddPolicy("role:admin", "*", "*")
	_, _ = e.AddRoleForUser("administrator", "role:admin")

	//从DB加载策略
	_ = e.LoadPolicy()

	r.POST("/login", authMiddleware.LoginHandler)

	auth := r.Group("/v1")
	auth.Use(authMiddleware.MiddlewareFunc(), Authorization(e))
	{
		auth.GET("/test", func(c *gin.Context) {
			username, _ := c.Get(IdentityKey)
			fmt.Printf("IdentityKey username: %v\n", username)
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
