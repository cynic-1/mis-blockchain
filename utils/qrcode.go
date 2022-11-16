package utils

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
)

func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		origin := c.Request.Header.Get("Origin") //请求头部
		if origin != "" {
			//接收客户端发送的origin （重要！）
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			//服务器支持的所有跨域请求的方法
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE,UPDATE")
			//允许跨域设置可以返回其他子段，可以自定义字段
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Length, X-CSRF-Token, Token,session")
			// 允许浏览器（客户端）可以解析的头部 （重要）
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers")
			//设置缓存时间
			c.Header("Access-Control-Max-Age", "172800")
			//允许客户端传递校验信息比如 cookie (重要)
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		//允许类型校验
		if method == "OPTIONS" {
			c.JSON(http.StatusOK, "ok!")
		}

		defer func() {
			if err := recover(); err != nil {
				log.Printf("Panic info is: %v", err)
			}
		}()

		c.Next()
	}
}

// 通过字典模拟 DB
var db = make(map[string]string)

func setupRouter() *gin.Engine {
	// 初始化 Gin 框架默认实例，该实例包含了路由、中间件以及配置信息
	r := gin.Default()

	r.Use(Cors()) //开启中间件 允许使用跨域请求

	// Ping 测试路由
	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "ping")
	})

	// 保存用户数据路由
	r.GET("/weixin/callback", func(c *gin.Context) {
		code := c.Query("code")
		state := c.Query("state")
		// user := c.Params.ByName("name")
		db[state] = code
		//if ok {
		c.JSON(http.StatusOK, gin.H{"code": code, "state": state})
		//} else {
		//	c.JSON(http.StatusOK, gin.H{"user": user, "status": "no value"})
		//}
	})

	// 需要 HTTP 基本授权认证的子路由群组设置
	//authorized := r.Group("/", gin.BasicAuth(gin.Accounts{
	//	"foo":  "bar", // 用户名:foo 密码:bar
	//	"manu": "123", // 用户名:manu 密码:123
	//}))

	// 获取用户信息路由
	r.GET("/user/:state", func(c *gin.Context) {
		state := c.Params.ByName("state")
		code, ok := db[state]
		if ok {
			c.JSON(http.StatusOK, gin.H{"state": state, "code": code})
		} else {
			c.JSON(http.StatusNotFound, gin.H{"state": state, "code": "no value"})
		}
	})

	return r
}

func StartQRCodeServer() {
	// 设置路由信息
	r := setupRouter()
	// 启动服务器并监听 8080 端口
	r.Run(":8080")
}
