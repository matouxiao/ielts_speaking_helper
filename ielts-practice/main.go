package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	_ "github.com/go-sql-driver/mysql"
)

type UserInput struct {
	ExamType  string `json:"exam_type" form:"exam_type"`
	Score     int    `json:"score" form:"score"`
	ExamMonth string `json:"exam_month" form:"exam_month"`
}

type User struct {
	Username string `json:"username" form:"username"`
	Password string `json:"password" form:"password"`
}

type ChatMessage struct {
	Message string `json:"message"`
}

type DeepSeekResponse struct {
	Response string `json:"response"`
}

var (
	db  *sql.DB
	rdb *redis.Client
	ctx = context.Background()
)

func init() {
	// MySQL 连接
	var err error
	dsn := "user:password@tcp(127.0.0.1:3306)/ielts_practice"
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Error connecting to MySQL: %v", err)
	}

	// Redis 连接
	rdb = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	_, err = rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Error connecting to Redis: %v", err)
	}
}

// 简单的内存数据库，实际项目中应该使用真实的数据库
var users = make(map[string]string)
var userStories = make(map[string]string) // 存储用户的当前故事

const DEEPSEEK_API_KEY = "your_deepseek_api_key" // 替换为实际的API密钥

func hashPassword(password string) string {
	hasher := md5.New()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

func generateStory(examType string, score int, month string) (string, error) {
	prompt := fmt.Sprintf("你是一个IELTS口语考官。请根据以下信息生成一个包含多个雅思口语题目的故事：\n考试类型：%s\n分数：%d\n考试月份：%s\n生成的故事应该符合考生的英语水平，并包含适合该月份的口语题目。", examType, score, month)

	// 调用DeepSeek API
	url := "https://api.deepseek.com/v1/chat/completions" // 替换为实际的API endpoint
	requestBody, _ := json.Marshal(map[string]interface{}{
		"model": "deepseek-chat",
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
	})

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+DEEPSEEK_API_KEY)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result DeepSeekResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	return result.Response, nil
}

func main() {
	r := gin.Default()

	// 设置 session 中间件
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	// 加载HTML模板
	r.LoadHTMLGlob("templates/*")

	// 设置静态文件路径
	r.Static("/static", "./static")

	// 登录页面
	r.GET("/", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("user") != nil {
			c.Redirect(http.StatusFound, "/home")
			return
		}
		c.Redirect(http.StatusFound, "/login")
	})

	r.GET("/login", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("user") != nil {
			c.Redirect(http.StatusFound, "/home")
			return
		}
		c.HTML(http.StatusOK, "login.html", nil)
	})

	// 注册页面
	r.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", nil)
	})

	// 处理注册
	r.POST("/register", func(c *gin.Context) {
		username := strings.TrimSpace(c.PostForm("username"))
		password := c.PostForm("password")
		confirmPassword := c.PostForm("confirm_password")

		if len(username) < 3 || len(username) > 20 {
			c.HTML(http.StatusBadRequest, "register.html", gin.H{
				"error": "用户名长度必须在3-20个字符之间",
			})
			return
		}

		if len(password) < 6 {
			c.HTML(http.StatusBadRequest, "register.html", gin.H{
				"error": "密码长度必须至少6位",
			})
			return
		}

		if password != confirmPassword {
			c.HTML(http.StatusBadRequest, "register.html", gin.H{
				"error": "两次输入的密码不一致",
			})
			return
		}

		if _, exists := users[username]; exists {
			c.HTML(http.StatusBadRequest, "register.html", gin.H{
				"error": "用户名已存在",
			})
			return
		}

		users[username] = hashPassword(password)
		c.Redirect(http.StatusFound, "/login")
	})

	// 处理登录
	r.POST("/login", func(c *gin.Context) {
		username := strings.TrimSpace(c.PostForm("username"))
		password := c.PostForm("password")

		if hashedPassword, exists := users[username]; exists && hashedPassword == hashPassword(password) {
			session := sessions.Default(c)
			session.Set("user", username)
			session.Save()
			c.Redirect(http.StatusFound, "/home")
			return
		}

		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"error": "用户名或密码错误",
		})
	})

	// 主页（需要登录）
	r.GET("/home", func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user")
		if user == nil {
			c.Redirect(http.StatusFound, "/login")
			return
		}
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title": "IELTS口语练习助手",
			"user":  user,
		})
	})

	// 退出登录
	r.GET("/logout", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Clear()
		session.Save()
		c.Redirect(http.StatusFound, "/login")
	})

	// 处理用户输入的路由（需要登录）
	r.POST("/generate", func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user")
		if user == nil {
			c.Redirect(http.StatusFound, "/login")
			return
		}

		var input UserInput
		if err := c.ShouldBind(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 验证分数范围
		validScore := true
		switch input.ExamType {
		case "gaokao":
			validScore = input.Score >= 0 && input.Score <= 150
		case "cet4", "cet6":
			validScore = input.Score >= 0 && input.Score <= 710
		default:
			validScore = false
		}

		if !validScore {
			c.HTML(http.StatusBadRequest, "index.html", gin.H{
				"title": "IELTS口语练习助手",
				"error": "请输入有效的分数范围",
			})
			return
		}

		// 生成故事
		story, err := generateStory(input.ExamType, input.Score, input.ExamMonth)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "index.html", gin.H{
				"title": "IELTS口语练习助手",
				"error": "生成故事时出现错误",
			})
			return
		}

		// 保存故事到用户会话
		userStories[user.(string)] = story

		c.HTML(http.StatusOK, "chat.html", gin.H{
			"user":  user,
			"story": story,
		})
	})

	// 处理聊天消息
	r.POST("/chat", func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user")
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "请先登录"})
			return
		}

		var chatMsg ChatMessage
		if err := c.ShouldBindJSON(&chatMsg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 获取用户当前的故事
		story := userStories[user.(string)]

		// 构建提示
		prompt := fmt.Sprintf("当前故事：%s\n用户反馈：%s\n请根据用户的反馈提供建议或修改故事。", story, chatMsg.Message)

		// 调用DeepSeek API处理用户消息
		url := "https://api.deepseek.com/v1/chat/completions"
		requestBody, _ := json.Marshal(map[string]interface{}{
			"model": "deepseek-chat",
			"messages": []map[string]string{
				{
					"role":    "user",
					"content": prompt,
				},
			},
		})

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "处理消息时出现错误"})
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+DEEPSEEK_API_KEY)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "处理消息时出现错误"})
			return
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "处理消息时出现错误"})
			return
		}

		var result DeepSeekResponse
		if err := json.Unmarshal(body, &result); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "处理消息时出现错误"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"response": result.Response})
	})

	// 重新生成故事
	r.POST("/regenerate", func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user")
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "请先登录"})
			return
		}

		// TODO: 保存用户的考试类型和分数信息，用于重新生成
		// 这里简单返回一个示例
		c.JSON(http.StatusOK, gin.H{
			"story": "这是一个重新生成的故事示例...",
		})
	})

	// 故事生成页面
	r.GET("/story-generator", func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user")
		if user == nil {
			c.Redirect(http.StatusFound, "/login")
			return
		}
		c.HTML(http.StatusOK, "story-generator.html", gin.H{
			"user": user,
		})
	})

	// 口语训练页面
	r.GET("/speaking-practice", func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user")
		if user == nil {
			c.Redirect(http.StatusFound, "/login")
			return
		}
		c.HTML(http.StatusOK, "speaking-practice.html", gin.H{
			"user": user,
		})
	})

	// 获取下一个口语题目
	r.GET("/next-question", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("user") == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "请先登录"})
			return
		}

		// TODO: 从题库中随机获取题目
		// 这里暂时返回示例题目
		c.JSON(http.StatusOK, gin.H{
			"question": "Describe a place you like to visit in your free time. You should say:\n- Where it is\n- What you do there\n- Who you usually go there with\n- And explain why you like to go there",
		})
	})

	r.Run(":8080")
}
