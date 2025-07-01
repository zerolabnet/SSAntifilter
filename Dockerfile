FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ssantifilter main.go

RUN mkdir -p /app/geo && \
    apk add --no-cache git build-base && \
    git clone https://github.com/v2fly/geoip.git /tmp/geoip && \
    cd /tmp/geoip && \
    go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/geo/geoip ./ && \
    git clone https://github.com/v2fly/domain-list-community.git /tmp/domain-list && \
    cd /tmp/domain-list && \
    go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/geo/domain-list-community ./main.go

FROM alpine:3.22

# Создание группы и пользователя с фиксированными UID/GID
RUN addgroup -g 1000 ssagroup && \
    adduser -u 1000 -G ssagroup -D -s /bin/sh ssauser

# Установка системных зависимостей от root
RUN apk --no-cache add ca-certificates tzdata && \
    rm -rf /var/cache/apk/*

# Создание рабочей директории и установка прав доступа
RUN mkdir -p /app && \
    chown ssauser:ssagroup /app

# Переключение на не-root пользователя
USER ssauser

WORKDIR /app

ENV TZ=Europe/Moscow

# Копирование файлов с правильными правами доступа
COPY --from=builder --chown=ssauser:ssagroup /app/ssantifilter /app/
COPY --from=builder --chown=ssauser:ssagroup /app/geo /app/geo

# Установка прав на выполнение (от имени ssauser)
RUN chmod +x /app/geo/domain-list-community && \
    chmod +x /app/geo/geoip

CMD ["./ssantifilter"]