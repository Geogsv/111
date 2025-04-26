package main

import (
	// Импорт стандартных библиотек
	"log"        // Для логирования
	"os"         // Для работы с переменными окружения и файловой системой
	"path/filepath" // Для работы с путями к файлам (получение директории)

	// Импорт внутренних пакетов проекта
	"imagecleaner/internal/database"   // Для работы с базой данных
	"imagecleaner/internal/handlers"   // Для обработчиков HTTP-запросов
	"imagecleaner/internal/middleware" // Для middleware (например, проверки аутентификации)

	// Импорт сторонних библиотек
	"github.com/gin-contrib/sessions"        // Middleware для управления сессиями в Gin
	"github.com/gin-contrib/sessions/cookie" // Хранилище сессий на основе Cookie
	"github.com/gin-gonic/gin"               // Основной веб-фреймворк Gin
)

// getEnv получает значение переменной окружения по ключу.
// Если переменная не установлена, возвращает значение fallback и логирует предупреждение.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value // Возвращаем найденное значение
	}
	// Логируем, что используется значение по умолчанию
	log.Printf("Переменная окружения %s не установлена, используется значение по умолчанию: %s", key, fallback)
	return fallback // Возвращаем значение по умолчанию
}

// checkOrCreateDir проверяет существование директории по указанному пути.
// Если директория не существует, пытается её создать со всеми родительскими директориями.
// Если путь существует, но не является директорией, или произошла другая ошибка,
// логирует критическую ошибку и завершает программу.
func checkOrCreateDir(dirPath string) {
	// Базовые проверки безопасности и корректности пути
	if dirPath == "" {
		log.Fatalf("КРИТИЧЕСКАЯ ОШИБКА: Путь к директории не может быть пустым.")
	}
	// Предотвращаем случайное использование корня или текущей директории
	if dirPath == "/" || dirPath == "." {
		log.Fatalf("КРИТИЧЕСКАЯ ОШИБКА: Указан небезопасный путь для создания директории: %s", dirPath)
	}

	// Получаем информацию о файле/директории по пути
	info, err := os.Stat(dirPath)

	// Случай 1: Путь не существует
	if os.IsNotExist(err) {
		log.Printf("Папка %s не найдена, создаем...", dirPath)
		// Используем MkdirAll для создания всех необходимых родительских директорий
		// 0755 - стандартные права доступа (rwxr-xr-x)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			// Если создать не удалось, это критическая ошибка
			log.Fatalf("КРИТИЧЕСКАЯ ОШИБКА: не удалось создать папку %s: %v", dirPath, err)
		}
		log.Printf("Папка %s успешно создана.", dirPath)
		return // Директория создана, выходим
	}

	// Случай 2: Произошла другая ошибка при проверке пути
	if err != nil {
		log.Fatalf("КРИТИЧЕСКАЯ ОШИБКА: ошибка при проверке папки %s: %v", dirPath, err)
	}

	// Случай 3: Путь существует, но это не директория
	if !info.IsDir() {
		log.Fatalf("КРИТИЧЕСКАЯ ОШИБКА: Путь %s существует, но не является директорией.", dirPath)
	}

	// Случай 4: Путь существует и это директория
	log.Printf("Папка %s найдена.", dirPath)
}

// main - главная функция приложения, точка входа.
func main() {
	// --- 1. Конфигурация ---
	// Получаем конфигурацию из переменных окружения или используем значения по умолчанию.
	cookieSecret := getEnv("COOKIE_SECRET", "fallback-secret-change-in-production") // Секрет для подписи cookie
	dbPath := getEnv("DB_PATH", "/app/data/service.db")                             // Путь к файлу БД (внутри volume)
	listenPort := getEnv("LISTEN_PORT", "8080")                                     // Порт для прослушивания внутри контейнера
	uploadPath := getEnv("UPLOAD_PATH", "/app/uploads")                             // Путь для загружаемых файлов (внутри volume)

	// Проверяем и создаем необходимые директории ДО инициализации зависимых компонентов (БД).
	log.Printf("Проверка директории для БД: %s", filepath.Dir(dbPath)) // Логируем путь к папке БД
	checkOrCreateDir(filepath.Dir(dbPath))                         // Передаем путь к *директории* БД
	log.Printf("Проверка директории для загрузок: %s", uploadPath)
	checkOrCreateDir(uploadPath)                                   // Передаем путь к папке загрузок

	// --- 2. Инициализация Зависимостей ---
	// Инициализируем соединение с базой данных. При ошибке завершаем работу.
	err := database.InitDB(dbPath)
	if err != nil {
		log.Fatalf("Ошибка инициализации базы данных: %v", err)
	}
	// defer database.DB.Close() // Закрытие БД при завершении main (хотя при Fatalf не выполнится)

	// Устанавливаем режим работы Gin (ReleaseMode для продакшена - меньше логов, выше производительность).
	gin.SetMode(gin.ReleaseMode)
	// Создаем экземпляр Gin engine с настройками по умолчанию (логгер, восстановление после паник).
	router := gin.Default()

	// Настройка доверенных прокси. Важно для корректного получения IP клиента и протокола (http/https),
	// когда приложение работает за обратным прокси (Nginx).
	// `nil` доверяет ЛЮБОМУ прокси - УДОБНО для Docker, но НЕБЕЗОПАСНО, если есть риск подделки заголовков.
	// В продакшене рекомендуется указывать IP-адрес или подсеть Nginx-контейнера.
	log.Println("ПРЕДУПРЕЖДЕНИЕ: Установка доверенных прокси в nil. Убедитесь, что это безопасно в вашей среде.")
	err = router.SetTrustedProxies(nil)
	if err != nil {
		log.Fatalf("Ошибка установки доверенных прокси: %v", err)
	}

	// Устанавливаем максимальный размер multipart-формы, хранимой в памяти (остальное во временные файлы).
	// 10 << 20 = 10 * 2^20 = 10 Мегабайт.
	router.MaxMultipartMemory = 10 << 20

	// Настройка хранилища сессий на основе cookie.
	store := cookie.NewStore([]byte(cookieSecret)) // Используем секрет для шифрования/подписи cookie.
	// Настраиваем параметры cookie сессий.
	store.Options(sessions.Options{
		Path:   "/",         // Cookie доступен для всего сайта.
		MaxAge: 86400 * 7, // Время жизни cookie в секундах (7 дней).
		// HttpOnly: true - Запрещает доступ к cookie через JavaScript в браузере (защита от XSS).
		HttpOnly: true,
		// Secure: true - Cookie будет отправляться браузером ТОЛЬКО по HTTPS соединению.
		// ВАЖНО: Требует наличия HTTPS на Nginx. Для локальной разработки без HTTPS установите false.
		Secure: false,
		// SameSite: Lax - Защищает от CSRF для GET-запросов и некоторых других случаев.
		// Strict был бы еще безопаснее, но может ломать переходы с других сайтов.
	})

	// --- 3. Подключение Middleware ---
	// Middleware для управления сессиями. Делает объект сессии доступным в контексте запроса (c.Get(sessions.DefaultKey)).
	router.Use(sessions.Sessions("mysession", store)) // "mysession" - имя cookie сессии.

	// CSRF Middleware здесь НЕ используется.

	// --- 4. Настройка Статики и Шаблонов ---
	// Загружаем HTML-шаблоны из указанной директории. Gin будет использовать их для рендеринга.
	router.LoadHTMLGlob("web/templates/*")
	// Настраиваем отдачу статических файлов (CSS, JS, изображения).
	// В конфигурации с Nginx этот роут фактически не будет использоваться, так как Nginx
	// перехватит запросы к /static/ раньше. Оставляем для возможности запуска без Nginx.
	router.Static("/static", "./web/static")

	// --- 5. Определение Маршрутов (Роутинг) ---

	// Группа для публичных маршрутов (не требуют аутентификации).
	public := router.Group("/")
	{
		public.GET("/", handlers.ShowLoginPage)         // Главная страница (перенаправляет на логин или upload)
		public.GET("/login", handlers.ShowLoginPage)    // Страница входа (GET)
		public.POST("/login", handlers.HandleLogin)     // Обработка формы входа (POST)
		public.GET("/register", handlers.ShowRegisterPage) // Страница регистрации (GET)
		public.POST("/register", handlers.HandleRegister) // Обработка формы регистрации (POST)

		// Маршруты для просмотра изображений (токен в URL)
		public.GET("/view/:token", handlers.ShowConfirmViewPage) // Страница подтверждения просмотра (GET)
		public.POST("/view/:token", handlers.HandleConfirmView)  // Обработка подтверждения и отдача файла (POST)
	}

	// Группа маршрутов, требующих аутентификации пользователя.
	protected := router.Group("/")
	// Применяем middleware AuthRequired ко всем маршрутам в этой группе.
	protected.Use(middleware.AuthRequired())
	{
		protected.GET("/upload", handlers.ShowUploadPage) // Страница загрузки (GET)
		protected.POST("/upload", handlers.HandleUpload)  // Обработка формы загрузки (POST)
		protected.POST("/logout", handlers.HandleLogout)  // Обработка выхода из системы (POST)
		protected.GET("/preview/:token", handlers.HandlePreview)
	}

	// --- 6. Запуск Сервера ---
	// Формируем адрес для прослушивания (например, ":8080").
	listenAddr := ":" + listenPort
	log.Printf("Сервер запускается на порту %s внутри контейнера (доступ через Nginx)", listenPort)

	// Запускаем HTTP-сервер Gin. Он будет слушать указанный адрес.
	// router.Run() блокирует выполнение до завершения работы сервера или ошибки.
	err = router.Run(listenAddr)
	if err != nil {
		// Если сервер не смог запуститься (например, порт занят), логируем критическую ошибку.
		log.Fatalf("Не удалось запустить сервер: %v", err)
	}
}