# --- Этап сборки ---
    FROM golang:1.24-alpine AS builder

    # Устанавливаем рабочую директорию внутри контейнера
    WORKDIR /app
    
    # Копируем файлы зависимостей
    COPY go.mod go.sum ./
    
    # Скачиваем зависимости (использует кеш Docker, если файлы не изменились)
    RUN go mod download
    
    # Копируем весь исходный код проекта
    COPY . .
    
    # Создаем папку uploads заранее (хотя приложение тоже ее создает)
    # Это нужно, чтобы при сборке команда COPY для web/ могла скопировать все
    RUN mkdir -p ./uploads
    
    # Собираем Go приложение
    # CGO_ENABLED=0 необходим для статической линковки без зависимостей C (часто нужно для Alpine)
    # -o main указывает имя выходного файла
    # ./cmd/imagecleaner/main.go - путь к точке входа
    RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/imagecleaner/main.go
    
    # --- Этап выполнения ---
    FROM alpine:latest
    
    # Устанавливаем рабочую директорию
    WORKDIR /app
    
    # Копируем скомпилированное приложение из этапа сборки
    COPY --from=builder /app/main .
    
    # Копируем статические файлы и шаблоны
    COPY --from=builder /app/web ./web
    
    # Копируем папку uploads (она будет пустой, но структура важна)
    # Реальные загрузки будут в volume
    COPY --from=builder /app/uploads ./uploads
    
    # Указываем порт, который будет слушать приложение внутри контейнера
    EXPOSE 8080
    
    # Команда для запуска приложения при старте контейнера
    CMD ["./main"]