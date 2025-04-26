package handlers

import (
	// Стандартные библиотеки
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"strconv"
	"math/rand"

	// Внутренние пакеты
	"imagecleaner/internal/auth"
	"imagecleaner/internal/database"
	"imagecleaner/internal/services"

	// Сторонние библиотеки
	"github.com/gin-contrib/sessions" // Сессии все еще нужны для аутентификации
	"github.com/gin-gonic/gin"
)

// Константы для ограничений загрузки
const MaxUploadSize = 10 << 20 // 10 МБ
const MaxFiles = 10            // Максимальное количество файлов
const captchaSessionKey = "captcha_answer"

// Структура для передачи результатов успешной загрузки в шаблон
type UploadResult struct {
	OriginalFilename string
	ViewURL          string
	AccessToken      string // Нужен для генерации URL превью
}

func init() {
	rand.Seed(time.Now().UnixNano())
	log.Println("Инициализация обработчиков...")
}

func generateCaptcha() (num1, num2, answer int) {
	num1 = rand.Intn(10) + 1
	num2 = rand.Intn(10) + 1
	answer = num1 + num2
	return
}
// getEnv - локальная вспомогательная функция для получения переменных окружения.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// ShowLoginPage отображает страницу входа.
// Больше не обрабатывает flash-сообщения.
func ShowLoginPage(c *gin.Context) {
	// Просто рендерим шаблон без дополнительных данных об ошибках/успехе.
	// Они будут переданы только при ответе на POST /login или после редиректа из HandleRegister.
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "Вход",
		// "error":   nil, // Можно явно передать nil или не передавать вовсе
		// "success": nil,
	})
}

// ShowRegisterPage отображает страницу регистрации.
// Больше не обрабатывает flash-сообщения.
func ShowRegisterPage(c *gin.Context) {
	session := sessions.Default(c)
	num1, num2, expectedAnswer := generateCaptcha()
	session.Set(captchaSessionKey, expectedAnswer)
	err := session.Save()
	if err != nil {
		// Ошибка сохранения сессии - критично для капчи
		log.Printf("КРИТИЧЕСКАЯ ОШИБКА: Не удалось сохранить сессию для капчи: %v", err)
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"title":   "Ошибка сервера",
			"message": "Не удалось подготовить страницу регистрации. Попробуйте обновить.",
		})
		return
	}
	// Просто рендерим шаблон. Ошибки и username будут переданы при ответе на POST /register.
	c.HTML(http.StatusOK, "register.html", gin.H{
		"title": "Регистрация",
		"CaptchaNum1": num1,
		"CaptchaNum2": num2,
		// "error":      nil,
		// "success":    nil,
		// "username":   "",
	})
}

// HandleRegister обрабатывает POST-запрос с формы регистрации.
// При ошибках рендерит register.html с сообщением.
// При успехе рендерит login.html с сообщением об успехе.
func HandleRegister(c *gin.Context) {
	session := sessions.Default(c)
	username := strings.TrimSpace(c.PostForm("username"))
	password := strings.TrimSpace(c.PostForm("password"))
	passwordConfirm := strings.TrimSpace(c.PostForm("password_confirm"))
	captchaSolutionStr := strings.TrimSpace(c.PostForm("captcha_solution")) // Получаем ответ капчи

// --- Начало: Проверка капчи ---
	expectedAnswerRaw := session.Get(captchaSessionKey)
	// Сразу удаляем капчу из сессии, чтобы ее нельзя было использовать повторно
	session.Delete(captchaSessionKey)
	errSessionSave := session.Save()
	if errSessionSave != nil {
		log.Printf("Ошибка сохранения сессии после удаления капчи: %v", errSessionSave)
		// Не критично для продолжения, но логируем
	}

	// Функция для рендеринга ошибки С НОВОЙ КАПЧЕЙ
	renderRegisterWithErrorAndNewCaptcha := func(message string) {
		// Генерируем новую капчу для следующей попытки
		num1, num2, newExpectedAnswer := generateCaptcha()
		session.Set(captchaSessionKey, newExpectedAnswer)
		err := session.Save()
		if err != nil {
			log.Printf("Ошибка сохранения сессии при рендеринге ошибки регистрации с новой капчей: %v", err)
			// Попытаться отрендерить без капчи, если не удалось сохранить
			c.HTML(http.StatusInternalServerError, "register.html", gin.H{
				"title":    "Регистрация",
				"error":    "Ошибка сервера при обработке регистрации.",
				"username": username,
			})
			return
		}

		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"title":       "Регистрация",
			"error":       message,
			"username":    username, // Возвращаем введенное имя
			"CaptchaNum1": num1,     // Новая капча
			"CaptchaNum2": num2,     // Новая капча
		})
	}

	if expectedAnswerRaw == nil {
		log.Printf("Попытка регистрации без данных капчи в сессии (user: %s, IP: %s)", username, c.ClientIP())
		renderRegisterWithErrorAndNewCaptcha("Ошибка проверки (капча не найдена). Пожалуйста, попробуйте еще раз.")
		return
	}

	expectedAnswer, ok := expectedAnswerRaw.(int)
	if !ok {
		log.Printf("Некорректный тип данных капчи в сессии (user: %s, IP: %s, type: %T)", username, c.ClientIP(), expectedAnswerRaw)
		renderRegisterWithErrorAndNewCaptcha("Ошибка проверки (неверный формат капчи). Пожалуйста, попробуйте еще раз.")
		return
	}

	captchaSolution, errConv := strconv.Atoi(captchaSolutionStr)
	if errConv != nil {
		renderRegisterWithErrorAndNewCaptcha("Ответ на капчу должен быть числом.")
		return
	}

	if captchaSolution != expectedAnswer {
		renderRegisterWithErrorAndNewCaptcha("Неверный ответ на капчу.")
		return
	}
	// --- Конец: Проверка капчи пройдена ---

	// Функция для рендеринга страницы регистрации с ошибкой
	renderRegisterWithError := func(message string) {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"title":    "Регистрация",
			"error":    message, // Передаем сообщение об ошибке
			"username": username,  // Передаем введенное имя пользователя обратно
		})
	}

	// Валидация
	if username == "" || password == "" || passwordConfirm == "" {
		renderRegisterWithError("Все поля должны быть заполнены")
		return
	}
	if len(password) < 8 {
		renderRegisterWithError("Пароль должен быть не менее 8 символов")
		return
	}
	if password != passwordConfirm {
		renderRegisterWithError("Пароли не совпадают")
		return
	}

	// Хеширование пароля
	hashedPassword, err := auth.HashPassword(password)
	if err != nil {
		log.Printf("Ошибка хеширования пароля для пользователя %s: %v", username, err)
		// Используем старый рендер ошибки, так как капча уже пройдена
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{
			"title":    "Регистрация",
			"error":    "Произошла внутренняя ошибка при обработке пароля.",
			"username": username,
			// Капчу здесь уже не нужно генерировать заново, но можно оставить пустые значения или убрать
			// "CaptchaNum1": nil,
			// "CaptchaNum2": nil,
		})
		return
	}

	// Создание пользователя
	_, err = database.CreateUser(username, hashedPassword)
	if err != nil {
		log.Printf("Ошибка создания пользователя %s: %v", username, err)
		errorMsg := "Произошла внутренняя ошибка при создании пользователя."
		if strings.Contains(err.Error(), "уже существует") {
			errorMsg = err.Error() // Показываем ошибку уникальности
		}
		// Передаем ошибку на рендер С НОВОЙ капчей, т.к. регистрация не удалась
		renderRegisterWithErrorAndNewCaptcha(errorMsg)
		return
	}

	// Успешная регистрация - рендерим страницу ВХОДА с сообщением об успехе
	log.Printf("Пользователь %s успешно зарегистрирован.", username)
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title":   "Вход",
		"success": "Вы успешно зарегистрированы! Теперь вы можете войти.",
	})
	// Редирект больше не нужен:
	// c.Redirect(http.StatusFound, "/login")
}

// HandleLogin обрабатывает POST-запрос с формы входа.
// При ошибках рендерит login.html с сообщением.
// При успехе сохраняет сессию и редиректит на /upload.
func HandleLogin(c *gin.Context) {
	username := strings.TrimSpace(c.PostForm("username"))
	password := strings.TrimSpace(c.PostForm("password"))

	// Функция для рендеринга страницы входа с ошибкой
	renderLoginWithError := func(message string) {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{ // Используем 401 для неверных данных
			"title": "Вход",
			"error": message, // Передаем сообщение об ошибке
			// Можно передать username обратно, если нужно предзаполнение при ошибке
			// "username": username,
		})
	}

	// Валидация
	if username == "" || password == "" {
		renderLoginWithError("Имя пользователя и пароль не могут быть пустыми")
		return
	}

	// Проверка пользователя
	user, err := database.GetUserByUsername(username)
	if err != nil {
		log.Printf("Ошибка получения пользователя %s из БД: %v", username, err)
		// При ошибке БД рендерим с общей ошибкой сервера
		c.HTML(http.StatusInternalServerError, "login.html", gin.H{
			"title": "Вход",
			"error": "Ошибка сервера при проверке данных.",
		})
		return
	}

	// Проверка пароля
	if user == nil || !auth.CheckPasswordHash(password, user.PasswordHash) {
		log.Printf("Неудачная попытка входа для пользователя '%s'.", username)
		renderLoginWithError("Неверное имя пользователя или пароль.")
		return
	}

	// Успешный вход - сохраняем сессию и делаем редирект (здесь редирект оправдан)
	session := sessions.Default(c)
	session.Set("userID", user.ID)
	session.Set("username", user.Username)
	err = session.Save()
	if err != nil {
		log.Printf("Ошибка сохранения сессии после успешного входа пользователя %s (ID: %d): %v", username, user.ID, err)
		// Если сессию не сохранить, рендерим ошибку на странице входа
		c.HTML(http.StatusInternalServerError, "login.html", gin.H{
			"title": "Вход",
			"error": "Не удалось сохранить данные сессии.",
		})
		return
	}

	log.Printf("Пользователь %s (ID: %d) успешно вошел в систему.", user.Username, user.ID)
	c.Redirect(http.StatusFound, "/upload") // Редирект на страницу загрузки
}

// ShowUploadPage отображает страницу загрузки (без flash).
func ShowUploadPage(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username")
	usernameStr, _ := username.(string)

	c.HTML(http.StatusOK, "upload.html", gin.H{
		"title":    "Загрузка изображения",
		"username": usernameStr,
		"errors":   nil,
		// "success_urls": nil, // Заменяем на successResults
		"successResults": nil, // Используем новое имя
	})
}

// HandleUpload обрабатывает загрузку и рендерит результат (без flash).
// (Код этой функции уже был исправлен в предыдущем шаге и не требует изменений здесь)
func HandleUpload(c *gin.Context) {
	// --- Предварительные проверки ---
	maxTotalSize := int64(MaxFiles*MaxUploadSize + 1*1024*1024)
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxTotalSize)

	userID, exists := c.Get("userID")
	if !exists {
		log.Println("КРИТИЧЕСКАЯ ОШИБКА: userID не найден в контексте /upload.")
		c.Redirect(http.StatusFound, "/login")
		return
	}
	userID64 := userID.(int64)

	session := sessions.Default(c)
	username := session.Get("username")
	usernameStr, _ := username.(string)

	// --- Парсинг формы ---
	err := c.Request.ParseMultipartForm(int64(MaxUploadSize))
	if err != nil {
		log.Printf("Ошибка парсинга multipart формы для userID %d: %v", userID64, err)
		// --- НАЧАЛО: Возвращаем определение errorMsg ---
		errorMsg := "Ошибка обработки запроса при загрузке файлов." // Объявляем и инициализируем
		if err.Error() == "http: request body too large" {
			errorMsg = fmt.Sprintf("Общий размер запроса слишком большой. Максимум около %d MB.", maxTotalSize/1024/1024)
		} else if strings.Contains(err.Error(), "multipart: NextPart") || strings.Contains(err.Error(), "unexpected EOF") || strings.Contains(err.Error(), "EOF") {
			// Это может быть ошибка из-за размера одного файла или обрыва соединения
			errorMsg = fmt.Sprintf("Ошибка чтения данных файла. Возможно, один из файлов превышает лимит в %d MB или произошла ошибка передачи.", MaxUploadSize/1024/1024)
		}
		// --- КОНЕЦ: Возвращаем определение errorMsg ---
		c.HTML(http.StatusBadRequest, "upload.html", gin.H{
			"title":          "Ошибка загрузки",
			"username":       usernameStr,
			"errors":         []string{errorMsg}, // Теперь errorMsg определена
			"successResults": nil,
		})
		return
	}

	files := c.Request.MultipartForm.File["imagefiles"]

	// ... (проверки на пустые файлы и количество - без изменений) ...
	if len(files) == 0 {
		c.HTML(http.StatusBadRequest, "upload.html", gin.H{
			"title":          "Ошибка загрузки",
			"username":       usernameStr,
			"errors":         []string{"Вы не выбрали ни одного файла."},
			"successResults": nil,
		})
		return
	}
	if len(files) > MaxFiles {
		c.HTML(http.StatusBadRequest, "upload.html", gin.H{
			"title":          "Ошибка загрузки",
			"username":       usernameStr,
			"errors":         []string{fmt.Sprintf("Можно загрузить не более %d файлов одновременно.", MaxFiles)},
			"successResults": nil,
		})
		return
	}

	// --- Обработка каждого файла ---
	// var successURLs []string // Заменяем на successResults
	var successResults []UploadResult // Используем новый тип
	var errorMessages []string
	uploadPath := getEnv("UPLOAD_PATH", "/app/uploads")
	baseURL := getEnv("BASE_URL", "")

	if baseURL == "" {
		log.Printf("КРИТИЧЕСКАЯ ОШИБКА КОНФИГУРАЦИИ: Переменная окружения BASE_URL не установлена!")
		errorMessages = append(errorMessages, "Ошибка конфигурации сервера: невозможно сгенерировать ссылки.")
	}

	for _, fileHeader := range files {
		// ... (логирование, проверка размера файла - без изменений) ...

		storedFilename, errProc := services.ProcessAndSaveImage(fileHeader, uploadPath)
		if errProc != nil {
			// ... (обработка ошибок ProcessAndSaveImage - без изменений) ...
			continue
		}

		accessToken, errToken := services.GenerateSecureToken(32)
		if errToken != nil {
			// ... (обработка ошибок GenerateSecureToken - без изменений) ...
			cleanupFile(filepath.Join(uploadPath, storedFilename))
			continue
		}

		imageID, errDB := database.CreateImageRecord(userID64, fileHeader.Filename, storedFilename, accessToken)
		if errDB != nil {
			// ... (обработка ошибок CreateImageRecord - без изменений) ...
			cleanupFile(filepath.Join(uploadPath, storedFilename))
			continue
		}

		if baseURL != "" {
			viewURL := fmt.Sprintf("%s/view/%s", baseURL, accessToken)
			// --- Собираем результат ---
			result := UploadResult{
				OriginalFilename: fileHeader.Filename,
				ViewURL:          viewURL,
				AccessToken:      accessToken, // Сохраняем токен для URL превью
			}
			successResults = append(successResults, result) // Добавляем структуру в список
			// --- Конец сбора результата ---
			log.Printf("Файл '%s' (ID: %d) успешно обработан userID %d. URL: %s", fileHeader.Filename, imageID, userID64, viewURL)
		} else {
			log.Printf("Файл '%s' (ID: %d) успешно обработан userID %d, но URL не сформирован (BASE_URL не задан).", fileHeader.Filename, imageID, userID64)
			errorMessages = append(errorMessages, fmt.Sprintf("Файл '%s': успешно загружен, но ссылка не создана (ошибка конфигурации).", fileHeader.Filename))
		}
	} // Конец цикла for по файлам

	log.Printf("Завершена обработка %d файлов для userID %d. Успешно: %d, Ошибки: %d.",
		len(files), userID64, len(successResults), len(errorMessages))

	// --- ОТРИСОВКА РЕЗУЛЬТАТА ---
	c.HTML(http.StatusOK, "upload.html", gin.H{
		"title":          "Результаты загрузки",
		"username":       usernameStr,
		"errors":         errorMessages,
		"successResults": successResults, // Передаем новый список структур
	})
}

// HandleLogout использует редирект
func HandleLogout(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("userID")

	session.Delete("userID")
	session.Delete("username")
	session.Options(sessions.Options{MaxAge: -1})
	err := session.Save()
	if err != nil {
		log.Printf("Ошибка сохранения сессии после выхода пользователя (ID: %v): %v", userID, err)
	} else {
        log.Printf("Пользователь (ID: %v) успешно вышел из системы.", userID)
    }
	c.Redirect(http.StatusFound, "/")
}


// cleanupFile - вспомогательная функция для удаления файла по полному пути.
func cleanupFile(fullPath string) {
	if fullPath != "" {
		log.Printf("Попытка удаления файла %s из-за ошибки...", fullPath)
		err := os.Remove(fullPath)
		if err != nil {
			log.Printf("ПРЕДУПРЕЖДЕНИЕ: не удалось удалить файл %s после ошибки: %v", fullPath, err)
		} else {
			log.Printf("Файл %s успешно удален после ошибки обработки.", fullPath)
		}
	}
}

// ShowConfirmViewPage отображает страницу подтверждения просмотра.
func ShowConfirmViewPage(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"title": "Ошибка запроса", "message": "Отсутствует идентификатор изображения в ссылке."})
		return
	}

	img, err := database.GetImageByToken(token)
	if err != nil {
		log.Printf("Ошибка БД при поиске токена %s в ShowConfirmViewPage: %v", token, err)
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"title": "Ошибка сервера", "message": "Произошла ошибка при поиске информации об изображении."})
		return
	}

	if img == nil {
		log.Printf("Токен %s не найден в БД (GET /view).", token)
		c.HTML(http.StatusNotFound, "error.html", gin.H{"title": "Не найдено", "message": "Ссылка недействительна или устарела."})
		return
	}

	if img.Status != "pending" {
		log.Printf("Попытка доступа (GET /view) к уже использованному токену %s (статус: %s)", token, img.Status)
		c.HTML(http.StatusGone, "error.html", gin.H{"title": "Ссылка истекла", "message": "Эта ссылка уже была использована или срок её действия истёк."})
		return
	}

	c.HTML(http.StatusOK, "confirm_view.html", gin.H{
		"title": "Подтверждение просмотра",
		"token": token,
	})
}

// HandleConfirmView обрабатывает POST-запрос подтверждения просмотра.
func HandleConfirmView(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Отсутствует токен доступа в URL."})
		return
	}

	// 1. Повторно ищем изображение в БД
	img, err := database.GetImageByToken(token)
	if err != nil {
		log.Printf("Ошибка БД при повторном поиске токена %s (POST /view): %v", token, err)
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"title": "Ошибка сервера", "message": "Ошибка сервера при проверке ссылки."})
		c.Abort()
		return
	}

	// 2. Повторно проверяем статус
	if img == nil || img.Status != "pending" {
		log.Printf("Попытка повторного доступа (POST /view) или race condition для токена %s (статус: %s)", token, img.Status)
		c.HTML(http.StatusGone, "error.html", gin.H{"title": "Ссылка истекла", "message": "Ссылка недействительна или уже была использована."})
		c.Abort()
		return
	}

	// 3. Помечаем как просмотренное
	err = database.MarkImageViewed(token)
	if err != nil {
		log.Printf("Не удалось пометить токен %s как просмотренный (ImageID: %d): %v", token, img.ID, err)
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"title": "Ошибка сервера", "message": "Не удалось обработать ваш запрос на просмотр."})
		c.Abort()
		return
	}
	log.Printf("Токен %s успешно помечен как 'viewed' в БД (ImageID: %d) перед отправкой файла", token, img.ID)

	// 4. Отправляем файл
	uploadPath := getEnv("UPLOAD_PATH", "/app/uploads")
	filePath := filepath.Join(uploadPath, img.StoredFilename)

	// 4.1 Проверяем существование файла
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("КРИТИЧЕСКАЯ ОШИБКА: Файл %s не найден на диске для токена %s (ImageID: %d)!", filePath, token, img.ID)
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"title": "Ошибка сервера", "message": "Ошибка: файл изображения не найден на сервере."})
		c.Abort()
		return
	} else if err != nil {
		log.Printf("КРИТИЧЕСКАЯ ОШИБКА: Ошибка доступа к файлу %s для токена %s (ImageID: %d): %v", filePath, token, img.ID, err)
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"title": "Ошибка сервера", "message": "Ошибка доступа к файлу изображения на сервере."})
		c.Abort()
		return
	}

	// 4.2 Устанавливаем заголовки кеширования
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	log.Printf("Отправка файла %s клиенту (Token: %s, ImageID: %d)", filePath, token, img.ID)
	// 4.3 Отправляем файл
	c.File(filePath)

	// 5. Запускаем удаление файла в горутине
	go func(pathToDelete string, imageID int64, tokenToDelete string) {
		time.Sleep(2 * time.Second) // Небольшая задержка

		log.Printf("Попытка асинхронного удаления файла %s для ImageID: %d (Token: %s) после просмотра", pathToDelete, imageID, tokenToDelete)
		err := os.Remove(pathToDelete)
		if err != nil {
			log.Printf("ОШИБКА АСИНХРОННОГО УДАЛЕНИЯ ФАЙЛА: не удалось удалить файл %s (ImageID: %d, Token: %s): %v", pathToDelete, imageID, tokenToDelete, err)
			// database.UpdateImageStatus(imageID, "delete_failed") // Опционально
		} else {
			log.Printf("Файл %s успешно удален асинхронно после просмотра (ImageID: %d, Token: %s).", pathToDelete, imageID, tokenToDelete)
			// database.UpdateImageStatus(imageID, "deleted") // Опционально
		}
	}(filePath, img.ID, token)
}

// === НОВЫЙ ОБРАБОТЧИК для превью ===
// HandlePreview отдает файл изображения для превью. Требует аутентификации.
// Не изменяет статус изображения и не удаляет его.
func HandlePreview(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Отсутствует токен в URL."})
		return
	}

	// Получаем ID пользователя из контекста (установлен middleware AuthRequired)
	userIDRaw, exists := c.Get("userID")
	if !exists {
		// Этого не должно произойти, если middleware работает
		log.Println("КРИТИЧЕСКАЯ ОШИБКА: userID не найден в контексте /preview.")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	userID := userIDRaw.(int64)

	// Ищем изображение по токену
	img, err := database.GetImageByToken(token)
	if err != nil {
		log.Printf("Ошибка БД при поиске токена %s в HandlePreview (userID: %d): %v", token, userID, err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// Проверяем, найдено ли изображение
	if img == nil {
		log.Printf("Токен %s не найден в БД (GET /preview, userID: %d).", token, userID)
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	// !!! ВАЖНО: Проверяем, принадлежит ли изображение текущему пользователю !!!
	if img.UserID != userID {
		log.Printf("Попытка доступа к чужому превью: userID %d пытается получить доступ к токену %s (принадлежит userID %d)", userID, token, img.UserID)
		c.AbortWithStatus(http.StatusForbidden) // 403 Forbidden
		return
	}

	// Статус НЕ проверяем - превью должно быть доступно для pending

	// Формируем путь к файлу
	uploadPath := getEnv("UPLOAD_PATH", "/app/uploads")
	filePath := filepath.Join(uploadPath, img.StoredFilename)

	// Проверяем существование файла на диске
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("Файл превью %s не найден на диске для токена %s (ImageID: %d, userID: %d)!", filePath, token, img.ID, userID)
		c.AbortWithStatus(http.StatusNotFound) // Отдаем 404, т.к. сам ресурс (файл) не найден
		return
	} else if err != nil {
		log.Printf("Ошибка доступа к файлу превью %s для токена %s (ImageID: %d, userID: %d): %v", filePath, token, img.ID, userID, err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// Устанавливаем заголовки кеширования для превью (можно кешировать в браузере)
	// private - т.к. доступ только для владельца
	// max-age=3600 - кешировать на 1 час
	c.Header("Cache-Control", "private, max-age=3600")
	c.Header("Pragma", "") // Убираем старый Pragma: no-cache, если он был где-то установлен
	c.Header("Expires", "") // Убираем старый Expires: 0

	log.Printf("Отправка файла превью %s клиенту (Token: %s, ImageID: %d, userID: %d)", filePath, token, img.ID, userID)
	// Отправляем файл
	c.File(filePath)
	// НЕ помечаем как просмотренное, НЕ удаляем
}