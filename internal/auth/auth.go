package auth

import (
	// Стандартные библиотеки
	"fmt" // Для форматирования ошибок

	// Сторонние библиотеки
	"golang.org/x/crypto/bcrypt" // Пакет для хеширования паролей с использованием bcrypt
)

// HashPassword принимает пароль в виде строки (string) и возвращает его bcrypt-хеш (string).
// Bcrypt автоматически генерирует соль и включает её в результирующий хеш.
func HashPassword(password string) (string, error) {
	// bcrypt.GenerateFromPassword хеширует пароль.
	// []byte(password) преобразует строку пароля в срез байт.
	// bcrypt.DefaultCost - рекомендуемая "стоимость" хеширования (work factor).
	// Более высокая стоимость делает подбор пароля медленнее, но также замедляет хеширование при логине/регистрации.
	// DefaultCost (обычно 10) является хорошим компромиссом.
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// Если произошла ошибка при хешировании, возвращаем пустую строку и ошибку.
		return "", fmt.Errorf("ошибка хэширования пароля: %w", err) // Оборачиваем ошибку для контекста
	}
	// Преобразуем результат (срез байт хеша) обратно в строку и возвращаем.
	return string(bytes), nil
}

// CheckPasswordHash сравнивает предоставленный пароль (password) с хешем (hash), полученным из базы данных.
// Возвращает true, если пароль совпадает с хешем, и false в противном случае.
func CheckPasswordHash(password, hash string) bool {
	// bcrypt.CompareHashAndPassword безопасно сравнивает хеш и пароль.
	// Она извлекает соль из хеша (hash) и использует её для хеширования предоставленного пароля (password),
	// а затем сравнивает результаты.
	// Важно: Нельзя сравнивать хеши напрямую (например, hash == HashPassword(password)),
	// так как каждый вызов HashPassword генерирует новую соль и, следовательно, новый хеш.
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	// Если ошибки нет (err == nil), значит пароли совпали.
	// Функция возвращает ошибку bcrypt.ErrMismatchedHashAndPassword, если пароли не совпадают,
	// или другую ошибку, если хеш некорректен. Мы просто проверяем, была ли ошибка (nil).
	return err == nil
}