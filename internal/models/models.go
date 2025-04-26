package models

import (
	// Стандартные библиотеки
	"database/sql" // Нужен для типа sql.NullTime, представляющего NULLable значения времени в БД
	"time"         // Нужен для типа time.Time, представляющего временные метки
)

// User представляет пользователя в системе.
// Поля структуры соответствуют столбцам в таблице 'users' базы данных.
// Теги `json:"..."` используются для управления сериализацией/десериализацией в JSON (если потребуется API).
// `json:"-"` означает, что поле будет проигнорировано при JSON-маршалинге.
type User struct {
	ID           int64  `json:"id"`                 // Уникальный идентификатор пользователя (Primary Key)
	Username     string `json:"username"`           // Имя пользователя (UNIQUE)
	PasswordHash string `json:"-"`                  // Хеш пароля (НЕ ДОЛЖЕН передаваться клиенту)
}

// Image представляет запись об изображении в базе данных.
// Поля соответствуют столбцам в таблице 'images'.
type Image struct {
	ID               int64        `json:"id"`                 // Уникальный идентификатор изображения (Primary Key)
	UserID           int64        `json:"user_id"`            // ID пользователя, загрузившего изображение (Foreign Key)
	OriginalFilename string       `json:"original_filename"`  // Оригинальное имя файла, как оно было при загрузке
	StoredFilename   string       `json:"-"`                  // Уникальное имя файла, под которым он сохранен на сервере (НЕ ДОЛЖНО передаваться клиенту)
	AccessToken      string       `json:"access_token"`       // Уникальный токен для доступа к ссылке просмотра
	CreatedAt        time.Time    `json:"created_at"`         // Время создания записи в БД
	ViewedAt         sql.NullTime `json:"viewed_at"`          // Время первого просмотра (может быть NULL). Используется NullTime для корректной обработки NULL из БД.
	Status           string       `json:"status"`             // Текущий статус изображения ('pending', 'viewed', 'deleted', 'delete_failed', 'error')
}

// Примечание: Позже здесь можно добавить методы для этих структур, если потребуется.
// Например, метод для проверки статуса картинки:
// func (img *Image) IsViewed() bool {
//     return img.Status == "viewed" || img.ViewedAt.Valid
// }
// Или метод для проверки, действительна ли ссылка:
// func (img *Image) IsLinkActive() bool {
//     return img.Status == "pending"
// }