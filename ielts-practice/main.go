package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
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
	Choices []struct {
		Message struct {
			Content          string `json:"content"`
			ReasoningContent string `json:"reasoning_content"`
		} `json:"message"`
	} `json:"choices"`
}

// 口语题目结构体
type SpeakingQuestion struct {
	ID        int       `json:"id"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	Category  string    `json:"category"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AnswerRequest struct {
	Question string `json:"question"`
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

const DEEPSEEK_API_KEY = "sk-c6b15ffd14ff4d9199acd794d9dd35fe" // 替换为实际的API密钥

func hashPassword(password string) string {
	hasher := md5.New()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

func generateStory(examType string, score int, month string) (string, error) {
	// 读取话题文件
	topics, err := ioutil.ReadFile("question_topic.txt")
	if err != nil {
		log.Printf("读取话题文件失败: %v", err)
		return "", err
	}

	prompt := fmt.Sprintf(`你需要帮助雅思考生通过口语考试而编一个完整的故事给他背诵。根据输入的英语成绩来判断用户的英语水平，从而帮助用户生成一个符合用户英语水平的故事来让用户背诵。

请根据以下信息生成一个包含多个雅思口语题目的故事：
考试类型：%s
分数：%d
考试月份：%s

可用的口语话题：
%s

要求：
1. 生成的故事应该符合考生的英语水平
2. 故事需要自然地包含上述话题中的多个话题
3. 故事要有连贯性和趣味性
4. 故事内容要符合雅思口语考试的要求
5. 故事要适合背诵和记忆
6. 正常语速2分钟内可以说完

请生成一个完整的故事，并在故事中自然地融入这些话题。`, examType, score, month, string(topics))

	// 调用DeepSeek API
	url := "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
	requestBody, _ := json.Marshal(map[string]interface{}{
		"model": "deepseek-r1",
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": 0.7,
		"max_tokens":  2000,
	})

	log.Printf("发送API请求到: %s", url)
	log.Printf("请求内容: %s", string(requestBody))

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Printf("创建请求失败: %v", err)
		return "", err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+DEEPSEEK_API_KEY)
	httpReq.Header.Set("X-DashScope-SSE", "disable")

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("发送请求失败: %v", err)
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取响应失败: %v", err)
		return "", err
	}

	log.Printf("API响应状态码: %d", resp.StatusCode)
	log.Printf("API响应内容: %s", string(body))

	var result DeepSeekResponse
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("解析响应失败: %v", err)
		return "", err
	}

	if len(result.Choices) == 0 {
		log.Printf("API返回结果为空")
		return "", fmt.Errorf("API返回结果为空")
	}

	// 获取最终答案和推理过程
	finalAnswer := result.Choices[0].Message.Content
	reasoningContent := result.Choices[0].Message.ReasoningContent

	// 如果有推理过程，将其添加到最终答案中
	if reasoningContent != "" {
		return fmt.Sprintf("推理过程：\n%s\n\n最终答案：\n%s", reasoningContent, finalAnswer), nil
	}

	return finalAnswer, nil
}

// 爬取口语题目
func fetchSpeakingQuestions() ([]SpeakingQuestion, error) {
	url := "https://ieltscat.xdf.cn/jijing/speak/practice/1318/1/0"

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// 发送请求
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("请求失败，状态码: %d", resp.StatusCode)
	}

	// 解析HTML
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("解析HTML失败: %v", err)
	}

	var questions []SpeakingQuestion

	// 查找题目
	doc.Find(".speaking-question").Each(func(i int, s *goquery.Selection) {
		title := s.Find(".title").Text()
		content := s.Find(".content").Text()
		category := s.Find(".category").Text()

		question := SpeakingQuestion{
			Title:     strings.TrimSpace(title),
			Content:   strings.TrimSpace(content),
			Category:  strings.TrimSpace(category),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		questions = append(questions, question)
	})

	return questions, nil
}

// 保存题目到数据库
func saveQuestionsToDB(questions []SpeakingQuestion) error {
	// 准备SQL语句
	stmt, err := db.Prepare(`
		INSERT INTO speaking_questions (title, content, category, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("准备SQL语句失败: %v", err)
	}
	defer stmt.Close()

	// 开始事务
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("开始事务失败: %v", err)
	}

	// 执行插入
	for _, q := range questions {
		_, err = tx.Stmt(stmt).Exec(q.Title, q.Content, q.Category, q.CreatedAt, q.UpdatedAt)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("插入数据失败: %v", err)
		}
	}

	// 提交事务
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %v", err)
	}

	return nil
}

// 从数据库获取题目
func getQuestionsFromDB() ([]SpeakingQuestion, error) {
	rows, err := db.Query(`
		SELECT id, title, content, category, created_at, updated_at
		FROM speaking_questions
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("查询数据库失败: %v", err)
	}
	defer rows.Close()

	var questions []SpeakingQuestion
	for rows.Next() {
		var q SpeakingQuestion
		err := rows.Scan(&q.ID, &q.Title, &q.Content, &q.Category, &q.CreatedAt, &q.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("读取数据失败: %v", err)
		}
		questions = append(questions, q)
	}

	return questions, nil
}

// 从CSV文件读取题目
func readQuestionsFromCSV() ([]string, error) {
	file, err := os.Open("questions.csv")
	if err != nil {
		return nil, fmt.Errorf("打开CSV文件失败: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("读取CSV文件失败: %v", err)
	}

	var questions []string
	for _, record := range records {
		if len(record) > 0 {
			questions = append(questions, strings.TrimSpace(record[0]))
		}
	}

	return questions, nil
}

func main() {
	r := gin.Default()

	// 设置 session 中间件
	store := cookie.NewStore([]byte("secret"))
	store.Options(sessions.Options{
		Path:     "/",
		Domain:   "",
		MaxAge:   86400 * 7, // 7天
		Secure:   false,     // 开发环境设为false
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	r.Use(sessions.Sessions("mysession", store))

	// 添加调试中间件
	r.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		log.Printf("请求路径: %s, Session中的用户: %v", c.Request.URL.Path, session.Get("user"))
		c.Next()
	})

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

		log.Printf("注册尝试 - 用户名: %s", username)

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
		log.Printf("用户注册成功 - 用户名: %s", username)
		c.Redirect(http.StatusFound, "/login")
	})

	// 处理登录
	r.POST("/login", func(c *gin.Context) {
		username := strings.TrimSpace(c.PostForm("username"))
		password := c.PostForm("password")

		log.Printf("登录尝试 - 用户名: %s", username)
		log.Printf("当前用户列表: %v", users)

		if hashedPassword, exists := users[username]; exists && hashedPassword == hashPassword(password) {
			log.Printf("登录成功 - 用户名: %s", username)
			session := sessions.Default(c)
			session.Set("user", username)
			err := session.Save()
			if err != nil {
				log.Printf("保存session失败: %v", err)
				c.HTML(http.StatusInternalServerError, "login.html", gin.H{
					"error": "系统错误，请稍后重试",
				})
				return
			}

			// 验证session是否保存成功
			if session.Get("user") == nil {
				log.Printf("Session保存后验证失败")
				c.HTML(http.StatusInternalServerError, "login.html", gin.H{
					"error": "系统错误，请稍后重试",
				})
				return
			}

			log.Printf("Session保存成功，准备重定向到主页")
			c.Redirect(http.StatusFound, "/home")
			return
		}

		log.Printf("登录失败 - 用户名: %s", username)
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"error": "用户名或密码错误",
		})
	})

	// 主页（需要登录）
	r.GET("/home", func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user")
		log.Printf("访问主页 - Session中的用户: %v", user)

		if user == nil {
			log.Printf("未登录用户尝试访问主页，重定向到登录页")
			c.Redirect(http.StatusFound, "/login")
			return
		}

		log.Printf("用户 %v 成功访问主页", user)
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
			log.Printf("绑定表单数据失败: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		log.Printf("接收到的表单数据: %+v", input)

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
			log.Printf("分数验证失败: 类型=%s, 分数=%d", input.ExamType, input.Score)
			c.HTML(http.StatusBadRequest, "index.html", gin.H{
				"title": "IELTS口语练习助手",
				"error": "请输入有效的分数范围",
			})
			return
		}

		// 生成故事
		story, err := generateStory(input.ExamType, input.Score, input.ExamMonth)
		if err != nil {
			log.Printf("生成故事失败: %v", err)
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

		// 调用DeepSeek API
		url := "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
		requestBody, _ := json.Marshal(map[string]interface{}{
			"model": "deepseek-r1",
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

		if len(result.Choices) == 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "API返回结果为空"})
			return
		}

		// 获取最终答案和推理过程
		finalAnswer := result.Choices[0].Message.Content
		reasoningContent := result.Choices[0].Message.ReasoningContent

		response := gin.H{
			"response": finalAnswer,
		}

		if reasoningContent != "" {
			response["reasoning"] = reasoningContent
		}

		c.JSON(http.StatusOK, response)
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

	// 爬取题目的路由
	r.GET("/fetch-questions", func(c *gin.Context) {
		questions, err := fetchSpeakingQuestions()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		err = saveQuestionsToDB(questions)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("成功爬取 %d 个题目", len(questions)),
		})
	})

	// 获取题目的路由
	r.GET("/questions", func(c *gin.Context) {
		questions, err := readQuestionsFromCSV()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"questions": questions,
		})
	})

	// 获取答案的路由
	r.POST("/get-answer", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("user") == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "请先登录"})
			return
		}

		var answerReq AnswerRequest
		if err := c.ShouldBindJSON(&answerReq); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 构建提示
		prompt := fmt.Sprintf(`请为以下雅思口语题目生成一个高质量的答案。答案应该：
1. 符合雅思口语考试的要求
2. 40词以上，60词以内
3. 不要出现任何解释，直接给出答案

题目：%s

请生成一个完整的答案。`, answerReq.Question)

		// 调用DeepSeek API
		url := "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
		requestBody, _ := json.Marshal(map[string]interface{}{
			"model": "deepseek-r1",
			"messages": []map[string]string{
				{
					"role":    "user",
					"content": prompt,
				},
			},
		})

		log.Printf("发送API请求到: %s", url)
		log.Printf("请求内容: %s", string(requestBody))

		httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
		if err != nil {
			log.Printf("创建请求失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "处理请求时出现错误"})
			return
		}

		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+DEEPSEEK_API_KEY)

		client := &http.Client{}
		resp, err := client.Do(httpReq)
		if err != nil {
			log.Printf("发送请求失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "处理请求时出现错误"})
			return
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("读取响应失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "处理请求时出现错误"})
			return
		}

		log.Printf("API响应状态码: %d", resp.StatusCode)
		log.Printf("API响应内容: %s", string(body))

		// 检查响应状态码
		if resp.StatusCode != http.StatusOK {
			log.Printf("API返回错误状态码: %d", resp.StatusCode)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("API返回错误状态码: %d", resp.StatusCode)})
			return
		}

		var result DeepSeekResponse
		if err := json.Unmarshal(body, &result); err != nil {
			log.Printf("解析响应失败: %v", err)
			log.Printf("响应内容: %s", string(body))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "处理请求时出现错误"})
			return
		}

		if len(result.Choices) == 0 {
			log.Printf("API返回结果为空，完整响应: %+v", result)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "API返回结果为空"})
			return
		}

		// 获取最终答案和推理过程
		finalAnswer := result.Choices[0].Message.Content
		reasoningContent := result.Choices[0].Message.ReasoningContent

		log.Printf("获取到的答案: %s", finalAnswer)
		if reasoningContent != "" {
			log.Printf("获取到的推理过程: %s", reasoningContent)
		}

		response := gin.H{
			"answer": finalAnswer,
		}

		if reasoningContent != "" {
			response["reasoning"] = reasoningContent
		}

		c.JSON(http.StatusOK, response)
	})

	r.Run(":8080")
}
