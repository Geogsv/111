package middleware

import (
	// Стандартные библиотеки
	"log"      // Для логирования
	"net/http" // Для кодов статуса HTTP (StatusFound)

	// Сторонние библиотеки
	"github.com/gin-contrib/sessions" // Для работы с сессиями
	"github.com/gin-gonic/gin"        // Основной фреймворк
)

// AuthRequired - это Gin middleware, которое проверяет аутентификацию пользователя.
// Оно должно применяться к маршрутам, требующим входа в систему.
func AuthRequired() gin.HandlerFunc {
	// Возвращаем функцию, соответствующую сигнатуре gin.HandlerFunc
	return func(c *gin.Context) {
		// Получаем текущую сессию для данного запроса.
		// sessions.Default(c) извлекает сессию, настроенную ранее в main.go.
		session := sessions.Default(c)

		// Пытаемся получить значение 'userID' из данных сессии.
		// При успешном логине мы сохраняли его как int64.
		userIDRaw := session.Get("userID")

		// Проверяем, существует ли 'userID' в сессии.
		if userIDRaw == nil {
			// Если userID нет, пользователь не аутентифицирован.
			log.Printf("Доступ запрещен (не аутентифицирован) к %s с IP %s", c.Request.URL.Path, c.ClientIP())

			// --- Опционально: Сохранение URL для редиректа после логина ---
			// Можно сохранить URL, на который пользователь пытался перейти,
			// чтобы перенаправить его туда после успешного входа.
			// session.Set("redirect_after_login", c.Request.URL.String())
			// err := session.Save()
			// if err != nil { log.Printf("Ошибка сохранения URL для редиректа: %v", err) }
			// --- Конец опциональной части ---

			// Перенаправляем пользователя на страницу входа.
			// Используем StatusFound (302) для временного редиректа.
			c.Redirect(http.StatusFound, "/login")

			// Прерываем дальнейшую обработку запроса.
			// Это важно, чтобы следующие хендлеры в цепочке не выполнились.
			c.Abort()
			return // Выходим из middleware
		}

		// Если userID существует, проверяем его тип. Он должен быть int64.
		userID, ok := userIDRaw.(int64)
		if !ok {
			// Если тип не int64, это указывает на проблему с данными сессии (повреждение или ошибка).
			// В этом случае лучше очистить сессию и отправить пользователя на логин.
			log.Printf("ОШИБКА ТИПА ДАННЫХ СЕССИИ: Некорректный тип userID (%T) в сессии для IP %s. Сессия будет очищена.", userIDRaw, c.ClientIP())

			// Очищаем данные пользователя из сессии.
			session.Delete("userID")
			session.Delete("username")
			// Устанавливаем время жизни cookie в прошлое, чтобы браузер его удалил.
			session.Options(sessions.Options{MaxAge: -1})
			// Сохраняем изменения (удаление данных и MaxAge).
			err := session.Save()
			if err != nil {
				log.Printf("Ошибка сохранения сессии при очистке из-за некорректного типа userID: %v", err)
			}
			// Перенаправляем на логин.
			c.Redirect(http.StatusFound, "/login")
			c.Abort() // Прерываем обработку.
			return
		}

		// --- Пользователь аутентифицирован и тип userID корректен ---
		// Сохраняем userID в контексте Gin (c.Set).
		// Это позволяет последующим обработчикам легко получить доступ к ID пользователя (через c.Get("userID")).
		c.Set("userID", userID)

		// Опционально: Логирование успешной аутентификации для данного запроса.
		// log.Printf("Доступ разрешен (UserID: %d) к %s с IP %s", userID, c.Request.URL.Path, c.ClientIP())

		// Передаем управление следующему обработчику в цепочке middleware/хендлеров.
		c.Next()
	}
}