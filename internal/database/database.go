package database

import (
	// Стандартные библиотеки
	"database/sql" // Основной пакет для работы с SQL базами данных
	"fmt"          // Для форматирования строк и ошибок
	"log"          // Для логирования
	"strings"      // Для работы со строками (поиск подстроки в ошибках)
	"time"         // Для установки времени просмотра и таймаутов соединения

	// Внутренние пакеты
	"imagecleaner/internal/models" // Для структур User и Image

	// Драйвер SQLite. Пустой импорт (_) означает, что мы импортируем пакет
	// только ради его побочных эффектов - регистрации драйвера "sqlite" в пакете database/sql.
	_ "modernc.org/sqlite"
)

// DB - Глобальная переменная для хранения пула соединений с базой данных (*sql.DB).
// Экспортируется (начинается с большой буквы), чтобы быть доступной из других пакетов.
// Примечание: Глобальные переменные могут усложнять тестирование. В больших приложениях
// часто используется внедрение зависимостей (dependency injection) вместо глобальных переменных.
var DB *sql.DB

// InitDB инициализирует соединение с базой данных SQLite.
// Принимает dataSourceName - путь к файлу БД.
// Создает таблицы, если они не существуют.
// Настраивает параметры соединения.
func InitDB(dataSourceName string) error {
	var err error // Переменная для хранения ошибок

	// Формируем строку подключения (DSN - Data Source Name) с дополнительными параметрами SQLite:
	// - _journal_mode=WAL: Write-Ahead Logging - режим журналирования, обычно более производительный
	//   для одновременного чтения и записи, чем стандартный DELETE.
	// - _busy_timeout=5000: Устанавливает таймаут (в миллисекундах) ожидания снятия блокировки
	//   базы данных при конкурентном доступе. 5000ms = 5 секунд.
	// - _foreign_keys=on: Включает принудительное соблюдение ограничений внешних ключей.
	// - _synchronous=NORMAL: Уровень синхронизации записи. NORMAL - компромисс между
	//   скоростью и надежностью (данные гарантированно записываются в ОС, но не обязательно на диск).
	//   FULL был бы надежнее, но медленнее.
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on&_synchronous=NORMAL", dataSourceName)

	// sql.Open не устанавливает соединение немедленно, а только подготавливает объект *sql.DB.
	// Первый аргумент - имя драйвера ("sqlite"), зарегистрированного через пустой импорт.
	DB, err = sql.Open("sqlite", dsn)
	if err != nil {
		// Ошибка на этапе подготовки объекта DB (редко)
		return fmt.Errorf("ошибка при открытии %s: %w", dataSourceName, err)
	}

	// Настройка пула соединений (хотя для SQLite часто используется только одно соединение).
	// SetMaxOpenConns(1): Ограничиваем пул одним активным соединением. Для SQLite это стандартная практика,
	// так как параллельная запись в один файл затруднена (WAL помогает, но не полностью решает).
	DB.SetMaxOpenConns(1)
	// SetMaxIdleConns(1): Количество соединений, которые могут оставаться открытыми в пуле в неактивном состоянии.
	DB.SetMaxIdleConns(1)
	// SetConnMaxLifetime: Максимальное время, которое соединение может быть использовано перед пересозданием.
	// Помогает избежать проблем со старыми соединениями.
	DB.SetConnMaxLifetime(time.Hour)

	// DB.Ping() проверяет фактическое соединение с базой данных.
	if err = DB.Ping(); err != nil {
		DB.Close() // Закрываем объект DB, если соединение не удалось
		return fmt.Errorf("ошибка при проверке соединения с %s: %w", dataSourceName, err)
	}

	log.Println("Успешно подключились к базе данных:", dataSourceName)

	// Вызываем функцию для создания необходимых таблиц и индексов.
	err = createTables()
	if err != nil {
		DB.Close() // Закрываем соединение, если таблицы создать не удалось
		return fmt.Errorf("ошибка при создании таблиц: %w", err)
	}
	log.Println("Таблицы и индексы успешно проверены/созданы.")
	return nil // Возвращаем nil, если инициализация прошла успешно
}

// createTables создает таблицы 'users' и 'images', а также необходимые индексы,
// если они еще не существуют в базе данных.
func createTables() error {
	// SQL для создания таблицы пользователей.
	// IF NOT EXISTS предотвращает ошибку, если таблица уже существует.
	usersTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, -- Уникальный ID пользователя (автоинкремент)
		username TEXT NOT NULL UNIQUE,                -- Имя пользователя (уникальное, не NULL)
		password_hash TEXT NOT NULL                   -- Хеш пароля (не NULL)
	);`

	// Выполняем SQL-запрос для создания таблицы users.
	_, err := DB.Exec(usersTableSQL)
	if err != nil {
		return fmt.Errorf("ошибка при создании таблицы users: %w", err)
	}

	// SQL для создания таблицы изображений.
	imagesTableSQL := `
	CREATE TABLE IF NOT EXISTS images (
		id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, -- Уникальный ID изображения
		user_id INTEGER NOT NULL,                     -- ID пользователя-владельца (внешний ключ)
		original_filename TEXT,                       -- Исходное имя файла (для информации)
		stored_filename TEXT NOT NULL UNIQUE,         -- Уникальное имя файла на сервере (для поиска файла)
		access_token TEXT NOT NULL UNIQUE,            -- Уникальный токен для доступа к ссылке
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- Время создания записи (по умолчанию текущее)
		viewed_at DATETIME NULL,                      -- Время первого просмотра (NULL, если не просмотрено)
		status TEXT NOT NULL DEFAULT 'pending',       -- Статус ('pending', 'viewed', 'deleted', 'delete_failed', 'error')
		-- Внешний ключ, связывающий user_id с таблицей users.
		-- ON DELETE CASCADE: При удалении пользователя, все связанные с ним записи изображений также будут удалены.
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);`

	// Выполняем SQL-запрос для создания таблицы images.
	_, err = DB.Exec(imagesTableSQL)
	if err != nil {
		return fmt.Errorf("ошибка при создании таблицы images: %w", err)
	}

	// --- Создание индексов для ускорения запросов ---
	// Индекс для быстрого поиска по токену доступа (должен быть уникальным).
	indexTokenSQL := `CREATE UNIQUE INDEX IF NOT EXISTS idx_images_access_token ON images (access_token);`
	// Индекс для поиска по статусу (например, для фоновых задач очистки).
	indexStatusSQL := `CREATE INDEX IF NOT EXISTS idx_images_status ON images (status);`
	// Композитный индекс для поиска изображений конкретного пользователя по статусу.
	indexUserIdStatusSQL := `CREATE INDEX IF NOT EXISTS idx_images_user_id_status ON images (user_id, status);`

	// Выполняем запросы для создания индексов.
	_, err = DB.Exec(indexTokenSQL)
	if err != nil {
		return fmt.Errorf("ошибка при создании индекса токена images: %w", err)
	}
	_, err = DB.Exec(indexStatusSQL)
	if err != nil {
		return fmt.Errorf("ошибка при создании индекса статуса images: %w", err)
	}
	_, err = DB.Exec(indexUserIdStatusSQL)
	if err != nil {
		return fmt.Errorf("ошибка при создании индекса user_id_status images: %w", err)
	}

	return nil // Все таблицы и индексы созданы успешно
}

// GetDB возвращает глобальный экземпляр *sql.DB.
// Используется другими пакетами для доступа к базе данных.
func GetDB() *sql.DB {
	return DB
}

// CreateUser создает нового пользователя в базе данных.
// Принимает имя пользователя и хеш пароля.
// Возвращает ID созданного пользователя или ошибку.
// Обрабатывает ошибку уникальности имени пользователя.
func CreateUser(username, passwordHash string) (int64, error) {
	// Используем транзакцию для гарантии атомарности операции (хотя для одного INSERT это необязательно).
	tx, err := DB.Begin()
	if err != nil {
		return 0, fmt.Errorf("ошибка начала транзакции CreateUser: %w", err)
	}
	// defer tx.Rollback() гарантирует, что транзакция будет отменена, если Commit() не будет вызван.
	// Если Commit() успешен, Rollback() ничего не делает.
	defer tx.Rollback()

	// Подготавливаем SQL-запрос с плейсхолдерами (?) для безопасности (защита от SQL-инъекций).
	// Используем подготовленный запрос внутри транзакции.
	stmt, err := tx.Prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
	if err != nil {
		return 0, fmt.Errorf("ошибка при подготовке запроса CreateUser: %w", err)
	}
	// defer stmt.Close() гарантирует закрытие prepared statement после выхода из функции.
	defer stmt.Close()

	// Выполняем подготовленный запрос, передавая реальные значения.
	res, err := stmt.Exec(username, passwordHash)
	if err != nil {
		// Проверяем специфическую ошибку SQLite для нарушения UNIQUE constraint.
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			// Если ошибка связана с уникальностью username, возвращаем кастомную ошибку.
			return 0, fmt.Errorf("пользователь с таким именем '%s' уже существует", username)
		}
		// Если другая ошибка выполнения запроса.
		return 0, fmt.Errorf("ошибка при выполнении запроса CreateUser: %w", err)
	}

	// Получаем ID последней вставленной записи.
	lastID, err := res.LastInsertId()
	if err != nil {
		// Маловероятная ошибка, но проверяем.
		return 0, fmt.Errorf("ошибка при получении ID последнего пользователя CreateUser: %w", err)
	}

	// Если все прошло успешно, фиксируем транзакцию.
	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("ошибка фиксации транзакции CreateUser: %w", err)
	}

	log.Printf("Создан пользователь: %s (ID: %d)", username, lastID)
	return lastID, nil // Возвращаем ID и nil ошибку
}

// GetUserByUsername ищет пользователя в БД по его имени.
// Возвращает указатель на найденного пользователя (*models.User) или nil, если пользователь не найден.
// Возвращает ошибку только в случае проблем с БД.
func GetUserByUsername(username string) (*models.User, error) {
	user := &models.User{} // Создаем пустую структуру для заполнения
	// QueryRow используется для запросов, которые возвращают не более одной строки.
	row := DB.QueryRow("SELECT id, username, password_hash FROM users WHERE username = ?", username)

	// Сканируем результат запроса в поля структуры user.
	// Передаем указатели на поля (&user.ID, &user.Username, &user.PasswordHash).
	err := row.Scan(&user.ID, &user.Username, &user.PasswordHash)
	if err != nil {
		// Проверяем специальную ошибку sql.ErrNoRows.
		// Она означает, что запрос выполнился успешно, но не нашел строк (пользователь не найден).
		// В этом случае мы НЕ должны возвращать ошибку приложения.
		if err == sql.ErrNoRows {
			return nil, nil // Пользователь не найден - возвращаем nil, nil
		}
		// Если произошла другая ошибка при сканировании (например, проблемы с БД), возвращаем её.
		return nil, fmt.Errorf("ошибка сканирования результата GetUserByUsername для %s: %w", username, err)
	}
	// Пользователь найден, возвращаем указатель на него и nil ошибку.
	return user, nil
}

// CreateImageRecord сохраняет информацию о загруженном изображении в БД.
// Принимает ID пользователя, оригинальное имя файла, сгенерированное имя файла на сервере и токен доступа.
// Устанавливает статус 'pending' по умолчанию.
// Возвращает ID созданной записи или ошибку.
func CreateImageRecord(userID int64, originalFilename, storedFilename, accessToken string) (int64, error) {
	// Подготавливаем запрос на вставку.
	stmt, err := DB.Prepare(`
		INSERT INTO images(user_id, original_filename, stored_filename, access_token, status)
		VALUES(?, ?, ?, ?, 'pending')
	`)
	if err != nil {
		return 0, fmt.Errorf("ошибка подготовки запроса CreateImageRecord: %w", err)
	}
	defer stmt.Close()

	// Выполняем запрос.
	res, err := stmt.Exec(userID, originalFilename, storedFilename, accessToken)
	if err != nil {
		// Проверяем ошибки нарушения UNIQUE constraint для полей stored_filename и access_token.
		// Эти ошибки не должны происходить при правильной генерации имен и токенов, но проверяем на всякий случай.
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			if strings.Contains(err.Error(), "stored_filename") {
				log.Printf("КРИТИЧЕСКАЯ ОШИБКА: Попытка вставить дубликат stored_filename '%s' для UserID %d", storedFilename, userID)
				// Эта ошибка указывает на проблему в генерации имен файлов.
				return 0, fmt.Errorf("внутренняя ошибка сервера (конфликт имен файлов)")
			} else if strings.Contains(err.Error(), "access_token") {
				log.Printf("КРИТИЧЕСКАЯ ОШИБКА: Попытка вставить дубликат access_token '%s' для UserID %d", accessToken, userID)
				// Эта ошибка указывает на проблему в генерации токенов (крайне маловероятно).
				return 0, fmt.Errorf("внутренняя ошибка сервера (конфликт токенов)")
			}
		}
		// Другая ошибка выполнения запроса.
		return 0, fmt.Errorf("ошибка выполнения запроса CreateImageRecord: %w", err)
	}

	// Получаем ID созданной записи.
	lastID, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("ошибка получения ID записи изображения CreateImageRecord: %w", err)
	}
	// Логируем успешное создание записи.
	log.Printf("Запись об изображении создана: ID=%d, Token=%s, UserID=%d, OrigName=%s, StoredName=%s", lastID, accessToken, userID, originalFilename, storedFilename)
	return lastID, nil
}

// GetImageByToken ищет запись об изображении по его уникальному токену доступа.
// Использует индекс idx_images_access_token для быстрого поиска.
// Возвращает указатель на models.Image или nil, если не найдено.
func GetImageByToken(token string) (*models.Image, error) {
	img := &models.Image{} // Структура для результата
	// Запрос выбирает все поля из таблицы images по access_token.
	row := DB.QueryRow(`
		SELECT id, user_id, original_filename, stored_filename, access_token, created_at, viewed_at, status
		FROM images
		WHERE access_token = ?`, token) // Используем плейсхолдер

	// Сканируем результат в поля структуры img.
	// Для поля viewed_at (которое может быть NULL) используется тип sql.NullTime.
	err := row.Scan(
		&img.ID,
		&img.UserID,
		&img.OriginalFilename,
		&img.StoredFilename,
		&img.AccessToken,
		&img.CreatedAt,
		&img.ViewedAt, // Сканируется в sql.NullTime
		&img.Status,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			// Запись с таким токеном не найдена - это не ошибка БД.
			return nil, nil
		}
		// Другая ошибка при сканировании.
		return nil, fmt.Errorf("ошибка сканирования GetImageByToken для токена %s: %w", token, err)
	}
	// Запись найдена, возвращаем указатель на нее.
	return img, nil
}

// MarkImageViewed обновляет статус изображения на 'viewed' и записывает время просмотра (viewed_at).
// Важно: Обновление происходит только если текущий статус изображения 'pending'.
// Это предотвращает повторную пометку уже просмотренного или удаленного изображения
// и служит механизмом защиты от race condition (если два запроса пытаются пометить один токен).
// Возвращает ошибку, если обновление не удалось или строка не была затронута (статус был не 'pending').
func MarkImageViewed(token string) error {
	// Подготавливаем запрос UPDATE.
	// Условие WHERE access_token = ? AND status = 'pending' гарантирует атомарность проверки и обновления.
	stmt, err := DB.Prepare(`
		UPDATE images
		SET status = 'viewed', viewed_at = ?
		WHERE access_token = ? AND status = 'pending'
	`)
	if err != nil {
		return fmt.Errorf("ошибка подготовки запроса MarkImageViewed: %w", err)
	}
	defer stmt.Close()

	// Выполняем запрос, передавая текущее время и токен.
	res, err := stmt.Exec(time.Now(), token)
	if err != nil {
		return fmt.Errorf("ошибка выполнения запроса MarkImageViewed для токена %s: %w", token, err)
	}

	// Проверяем, была ли действительно обновлена хотя бы одна строка.
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		// Маловероятная ошибка для SQLite при получении rowsAffected.
		return fmt.Errorf("ошибка получения rowsAffected в MarkImageViewed для токена %s: %w", token, err)
	}

	// Если ни одна строка не была обновлена (rowsAffected == 0),
	// это означает, что условие WHERE не было выполнено (скорее всего, статус был уже не 'pending').
	// Возвращаем ошибку, чтобы сигнализировать об этом в вызывающий код (хендлер).
	if rowsAffected == 0 {
		// Логировать эту ситуацию не обязательно как ошибку, т.к. хендлер уже проверил статус ранее,
		// но это может указывать на race condition.
		// log.Printf("MarkImageViewed: Строка для токена %s не была обновлена (возможно, статус уже не 'pending').", token)
		return fmt.Errorf("изображение с токеном %s не найдено в статусе 'pending' для обновления на 'viewed'", token)
	}

	// Если rowsAffected > 0 (должно быть 1 из-за уникальности токена), обновление прошло успешно.
	// log.Printf("Изображение с токеном %s помечено как 'viewed'.", token) // Логируется в хендлере после успешного вызова
	return nil // Успех
}

// UpdateImageStatus обновляет статус изображения по его ID.
// Используется опционально для установки статусов 'deleted' или 'delete_failed' после попытки удаления файла.
func UpdateImageStatus(imageID int64, newStatus string) error {
	// Подготавливаем запрос UPDATE.
	stmt, err := DB.Prepare("UPDATE images SET status = ? WHERE id = ?")
	if err != nil {
		return fmt.Errorf("ошибка подготовки запроса UpdateImageStatus: %w", err)
	}
	defer stmt.Close()

	// Выполняем запрос.
	res, err := stmt.Exec(newStatus, imageID)
	if err != nil {
		return fmt.Errorf("ошибка выполнения запроса UpdateImageStatus для ID %d на статус '%s': %w", imageID, newStatus, err)
	}

	// Проверяем, была ли обновлена строка.
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("ошибка получения rowsAffected в UpdateImageStatus для ID %d: %w", imageID, err)
	}

	// Если строка не обновлена, возможно, ID не существует. Логируем как предупреждение.
	if rowsAffected == 0 {
		log.Printf("Предупреждение: UpdateImageStatus не затронул строк при попытке обновить статус для ImageID %d на '%s' (возможно, запись удалена?).", imageID, newStatus)
		// Можно вернуть ошибку, если обновление *обязательно* должно было произойти.
		// return fmt.Errorf("изображение с ID %d не найдено для обновления статуса на '%s'", imageID, newStatus)
	} else {
		// Логируем успешное обновление статуса.
		log.Printf("Статус изображения с ID %d успешно обновлен на '%s'.", imageID, newStatus)
	}

	return nil // Успех или некритичная ситуация (ID не найден)
}