package main

import (
    "crypto/rand"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "sync"
    "time"

    "github.com/gorilla/sessions"
    "golang.org/x/crypto/bcrypt"
)

type Config struct {
    Password string `json:"password"`
}

type Response struct {
    Desc  string `json:"desc"`
    Level string `json:"level"`
}

type AppState struct {
    mu         sync.RWMutex
    LastUpdate time.Time  `json:"last_update"`
    Logs       []LogEntry `json:"logs"`
}

type LogEntry struct {
    Time    time.Time `json:"time"`
    Message string    `json:"message"`
    Level   string    `json:"level"`
}

var (
    store     *sessions.CookieStore
    config    Config
    appState  AppState
    darkTheme = false
    themeMutex sync.RWMutex
)

func init() {
    // Загружаем ключ из переменной окружения
    secretKey := os.Getenv("SESSION_SECRET_KEY")
    if secretKey == "" {
        log.Println("Warning: SESSION_SECRET_KEY environment variable not set. Using a temporary insecure key.")
        // Генерируем временный ключ для разработки
        key, err := generateRandomString(32)
        if err != nil {
            log.Fatalf("Failed to generate temporary session key: %v", err)
        }
        secretKey = key
        log.Printf("Generated temporary session key: %s", secretKey)
    }
    store = sessions.NewCookieStore([]byte(secretKey))
}

func generateRandomString(length int) (string, error) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b := make([]byte, length)
    if _, err := rand.Read(b); err != nil {
        return "", fmt.Errorf("failed to generate random bytes: %w", err)
    }
    for i := range b {
        b[i] = charset[b[i]%byte(len(charset))]
    }
    return string(b), nil
}

func addLog(message, level string) {
    appState.mu.Lock()
    defer appState.mu.Unlock()

    entry := LogEntry{
        Time:    time.Now(),
        Message: message,
        Level:   level,
    }
    appState.Logs = append(appState.Logs, entry)

    if len(appState.Logs) > 100 {
        appState.Logs = appState.Logs[len(appState.Logs)-100:]
    }
}

func initConfig() {
    configPath := "config.json"

    if _, err := os.Stat(configPath); os.IsNotExist(err) {
        password, err := generateRandomString(20)
        if err != nil {
            log.Fatal("Error generating password:", err)
        }

        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        if err != nil {
            log.Fatal("Error generating password hash:", err)
        }

        config = Config{
            Password: string(hashedPassword),
        }

        configJSON, _ := json.MarshalIndent(config, "", "  ")
        err = os.WriteFile(configPath, configJSON, 0600)
        if err != nil {
            log.Fatal("Error writing config file:", err)
        }

        fmt.Printf("Your login password: %s\n", password)
        addLog("Application initialized with new config", "info")
    } else {
        configData, err := os.ReadFile(configPath)
        if err != nil {
            log.Fatal("Error reading config file:", err)
        }

        err = json.Unmarshal(configData, &config)
        if err != nil {
            log.Fatal("Error parsing config file:", err)
        }
        addLog("Application started", "info")
    }
}

func initDirectories() {
    // Создаем необходимые директории
    dirs := []string{"rawdata", "rawdata/geosite", "geo", "lists"}
    for _, dir := range dirs {
        if err := os.MkdirAll(dir, 0755); err != nil {
            addLog(fmt.Sprintf("Failed to create directory %s: %v", dir, err), "error")
        }
    }

    // Создаем симлинки для geosite
    wd, _ := os.Getwd()
    symlinks := map[string]string{
        "rawdata/geosite/proxy-domain":  filepath.Join(wd, "rawdata/proxy-domain"),
        "rawdata/geosite/direct-domain": filepath.Join(wd, "rawdata/direct-domain"),
    }

    for linkPath, targetPath := range symlinks {
        // Удаляем существующий симлинк если есть
        os.Remove(linkPath)
        // Создаем новый симлинк
        if err := os.Symlink(targetPath, linkPath); err != nil {
            addLog(fmt.Sprintf("Failed to create symlink %s -> %s: %v", linkPath, targetPath, err), "error")
        }
    }

    // Создаем config.json для geoip
    createGeoIPConfig()
}

func createGeoIPConfig() {
    configPath := "geo/config.json"

    // Проверяем, существует ли уже конфиг
    if _, err := os.Stat(configPath); err == nil {
        return
    }

    wd, _ := os.Getwd()
    geoipConfig := map[string]interface{}{
        "input": []map[string]interface{}{
            {
                "type":   "text",
                "action": "add",
                "args": map[string]interface{}{
                    "name":       "antifilter-ip",
                    "uri":        filepath.Join(wd, "rawdata/allyouneed.lst"),
                    "onlyIPType": "ipv4",
                },
            },
            {
                "type":   "text",
                "action": "add",
                "args": map[string]interface{}{
                    "name":       "antifilter-community-ip",
                    "uri":        filepath.Join(wd, "rawdata/community.lst"),
                    "onlyIPType": "ipv4",
                },
            },
            {
                "type":   "text",
                "action": "add",
                "args": map[string]interface{}{
                    "name":       "proxy-ip",
                    "uri":        filepath.Join(wd, "rawdata/proxy-ip"),
                    "onlyIPType": "ipv4",
                },
            },
            {
                "type":   "text",
                "action": "add",
                "args": map[string]interface{}{
                    "name":       "direct-ip",
                    "uri":        filepath.Join(wd, "rawdata/direct-ip"),
                    "onlyIPType": "ipv4",
                },
            },
            {
                "type":   "private",
                "action": "add",
            },
        },
        "output": []map[string]interface{}{
            {
                "type":   "v2rayGeoIPDat",
                "action": "output",
                "args": map[string]interface{}{
                    "outputDir":   filepath.Join(wd, "lists"),
                    "outputName":  "geoip.dat",
                    "wantedList": []string{"antifilter-ip", "antifilter-community-ip", "proxy-ip", "direct-ip", "private"},
                },
            },
        },
    }

    configJSON, _ := json.MarshalIndent(geoipConfig, "", "  ")
    if err := os.WriteFile(configPath, configJSON, 0644); err != nil {
        addLog(fmt.Sprintf("Failed to create geoip config: %v", err), "error")
    }
}

var exampleFiles = map[string]string{
    "proxy-domain":  "example.com\n",
    "proxy-ip":      "192.0.2.0/24\n",
    "direct-domain": "example.net\n",
    "direct-ip":     "198.51.100.0/24\n",
}

func initExampleFiles() {
    for fileName, content := range exampleFiles {
        filePath := filepath.Join("rawdata", fileName)

        if _, err := os.Stat(filePath); os.IsNotExist(err) {
            // Создаем директорию, если не существует
            dir := filepath.Dir(filePath)
            if err := os.MkdirAll(dir, 0755); err != nil {
                addLog(fmt.Sprintf("Failed to create directory %s: %v", dir, err), "error")
                continue
            }

            // Создаем файл с примерами
            if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
                addLog(fmt.Sprintf("Failed to create example file %s: %v", filePath, err), "error")
            } else {
                addLog(fmt.Sprintf("Created example file: %s", filePath), "info")
            }
        }
    }
}

func downloadFile(url, filepath string) error {
    resp, err := http.Get(url)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("bad status: %s", resp.Status)
    }

    out, err := os.Create(filepath)
    if err != nil {
        return err
    }
    defer out.Close()

    _, err = io.Copy(out, resp.Body)
    return err
}

func updateAntifilterLists() error {
    addLog("Starting Antifilter lists update...", "info")

    // Скачиваем списки в rawdata
    downloads := map[string]string{
        "https://antifilter.download/list/allyouneed.lst":                   "rawdata/allyouneed.lst",
        "https://community.antifilter.download/list/community.lst":          "rawdata/community.lst",
        "https://community.antifilter.download/list/domains.lst":            "rawdata/geosite/antifilter-community-domain",
    }

    for url, filename := range downloads {
        addLog(fmt.Sprintf("Downloading %s...", url), "info")
        if err := downloadFile(url, filename); err != nil {
            addLog(fmt.Sprintf("Failed to download %s: %v", url, err), "error")
            continue
        }
        addLog(fmt.Sprintf("Downloaded %s successfully", filename), "success")
    }

    // Конвертируем в Shadowrocket формат
    if err := convertAntifilterToShadowrocket("rawdata/allyouneed.lst", "lists/antifilter-ip.list", "IP-CIDR,"); err != nil {
        addLog(fmt.Sprintf("Failed to convert allyouneed.lst: %v", err), "error")
    }

    if err := convertAntifilterToShadowrocket("rawdata/community.lst", "lists/antifilter-community-ip.list", "IP-CIDR,"); err != nil {
        addLog(fmt.Sprintf("Failed to convert community.lst: %v", err), "error")
    }

    if err := convertAntifilterToShadowrocket("rawdata/geosite/antifilter-community-domain", "lists/antifilter-community-domain.list", "DOMAIN-SUFFIX,"); err != nil {
        addLog(fmt.Sprintf("Failed to convert antifilter-community-domain: %v", err), "error")
    }

    // Конвертируем в Clash формат
    clashFiles := []string{
        "lists/antifilter-ip.list",
        "lists/antifilter-community-ip.list",
        "lists/antifilter-community-domain.list",
    }

    for _, file := range clashFiles {
        yamlFile := strings.Replace(file, ".list", ".yaml", 1)
        if err := convertToClash(file, yamlFile); err != nil {
            addLog(fmt.Sprintf("Failed to convert %s to Clash format: %v", file, err), "error")
        }
    }

    // Генерируем geoip.dat
    if err := generateGeoIP(); err != nil {
        addLog(fmt.Sprintf("Failed to generate geoip.dat: %v", err), "error")
    }

    // Генерируем geosite.dat
    if err := generateGeoSite(); err != nil {
        addLog(fmt.Sprintf("Failed to generate geosite.dat: %v", err), "error")
    }

    appState.mu.Lock()
    appState.LastUpdate = time.Now()
    appState.mu.Unlock()
    addLog("Antifilter lists update completed", "success")
    return nil
}

func convertAntifilterToShadowrocket(inputFile, outputFile, prefix string) error {
    content, err := os.ReadFile(inputFile)
    if err != nil {
        return err
    }

    lines := strings.Split(string(content), "\n")
    var result []string

    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        result = append(result, prefix+line)
    }

    finalContent := strings.Join(result, "\n")
    if finalContent != "" {
        finalContent += "\n"
    }

    return os.WriteFile(outputFile, []byte(finalContent), 0644)
}

func generateGeoIP() error {
    addLog("Generating geoip.dat...", "info")
    // Проверяем существование бинарника geoip в папке geo
    if _, err := os.Stat("geo/geoip"); err != nil {
        addLog("geoip binary not found at geo/geoip, skipping geoip.dat generation", "warning")
        return nil
    }

    // Проверяем существование конфига в папке geo
    if _, err := os.Stat("geo/config.json"); err != nil {
        addLog("config.json not found at geo/config.json, skipping geoip.dat generation", "warning")
        return nil
    }

    cmd := exec.Command("geo/geoip", "-c", "geo/config.json")
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("failed to execute geoip: %v", err)
    }

    addLog("geoip.dat generated successfully", "success")
    return nil
}

func generateGeoSite() error {
    addLog("Generating geosite.dat...", "info")
    // Проверяем существование бинарника domain-list-community в папке geo
    if _, err := os.Stat("geo/domain-list-community"); err != nil {
        addLog("domain-list-community binary not found at geo/domain-list-community, skipping geosite.dat generation", "warning")
        return nil
    }

    // Проверяем существование директории rawdata/geosite
    if _, err := os.Stat("rawdata/geosite"); err != nil {
        addLog("rawdata/geosite directory not found, skipping geosite.dat generation", "warning")
        return nil
    }

    wd, err := os.Getwd()
    if err != nil {
        return fmt.Errorf("failed to get working directory: %v", err)
    }

    cmd := exec.Command("geo/domain-list-community",
        "--datapath="+filepath.Join(wd, "rawdata/geosite"),
        "--exportlists=antifilter-community-domain,proxy-domain,direct-domain",
        "--outputdir="+filepath.Join(wd, "lists"),
        "--outputname=geosite.dat")

    if err := cmd.Run(); err != nil {
        return fmt.Errorf("failed to execute domain-list-community: %v", err)
    }

    addLog("geosite.dat generated successfully", "success")
    return nil
}

func startAntifilterUpdater() {
    // Запускаем первое обновление через 10 секунд после старта
    time.AfterFunc(10*time.Second, func() {
        if err := updateAntifilterLists(); err != nil {
            addLog(fmt.Sprintf("Initial Antifilter update failed: %v", err), "error")
        }
    })

    // Запускаем периодическое обновление каждые 12 часов
    ticker := time.NewTicker(12 * time.Hour)
    go func() {
        for range ticker.C {
            if err := updateAntifilterLists(); err != nil {
                addLog(fmt.Sprintf("Scheduled Antifilter update failed: %v", err), "error")
            }
        }
    }()
}

func isAuthenticated(r *http.Request) bool {
    session, _ := store.Get(r, "antifilter-session")
    loggedIn, ok := session.Values["loggedIn"].(bool)
    return ok && loggedIn
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "POST" {
        password := r.FormValue("password")
        if bcrypt.CompareHashAndPassword([]byte(config.Password), []byte(password)) == nil {
            session, _ := store.Get(r, "antifilter-session")
            session.Values["loggedIn"] = true
            session.Save(r, w)
            addLog("User logged in", "info")
            http.Redirect(w, r, "/", http.StatusFound)
            return
        } else {
            addLog("Failed login attempt", "warning")
            w.Header().Set("Content-Type", "text/html")
            fmt.Fprint(w, `<script>alert("Wrong password!"); window.location.href="/";</script>`)
            return
        }
    }

    loginTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <style>
        *, *:before, *:after {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            padding: 0;
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .login-container {
            background: white;
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            border: 1px solid #e0e0e0;
            width: 100%;
            max-width: 400px;
            text-align: center;
        }

        .input-group {
            margin-bottom: 30px;
        }

        .form-input {
            width: 100%;
            padding: 15px 20px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background: white;
            font-size: 16px;
            outline: none;
            color: #333;
        }

        .form-input:focus {
            border-color: #a8d5a8;
        }

        .form-input::placeholder {
            color: #999;
        }

        .login-btn {
            width: 100%;
            padding: 15px;
            border: none;
            border-radius: 4px;
            background: #a8d5a8;
            color: #333;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
        }

        .login-btn:hover {
            background: #95c695;
        }

        @media (max-width: 480px) {
            .login-container {
                margin: 20px;
                padding: 30px 20px;
            }
        }
    </style>
</head>
<body>
    <form class="login-container" method="POST">
        <div class="input-group">
            <input type="password" name="password" class="form-input" placeholder="Enter Password" autofocus required>
        </div>
        <button type="submit" class="login-btn">Login</button>
    </form>
</body>
</html>`

    w.Header().Set("Content-Type", "text/html")
    fmt.Fprint(w, loginTemplate)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "antifilter-session")
    delete(session.Values, "loggedIn")
    session.Save(r, w)
    addLog("User logged out", "info")

    referer := r.Header.Get("Referer")
    if referer == "" {
        referer = "/"
    }
    http.Redirect(w, r, referer, http.StatusFound)
}

func themeHandler(w http.ResponseWriter, r *http.Request) {
    if !isAuthenticated(r) {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    if r.Method == "POST" {
        theme := r.FormValue("theme")

        themeMutex.Lock()
        darkTheme = theme == "dark"
        themeMutex.Unlock()

        response := Response{Desc: "Theme updated", Level: "success"}
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
        return
    }
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
    if !isAuthenticated(r) {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Используем RLock для чтения данных
    appState.mu.RLock()
    lastUpdate := appState.LastUpdate
    // Создаем копию логов под блокировкой
    logsCopy := make([]LogEntry, len(appState.Logs))
    copy(logsCopy, appState.Logs)
    appState.mu.RUnlock()

    // Ограничиваем количество логов до 100
    if len(logsCopy) > 100 {
        logsCopy = logsCopy[len(logsCopy)-100:]
    }

    themeMutex.RLock()
    currentTheme := darkTheme
    themeMutex.RUnlock()

    status := map[string]interface{}{
        "last_update": lastUpdate,
        "logs":        logsCopy,
        "dark_theme":  currentTheme,
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(status)
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
    if !isAuthenticated(r) {
        loginHandler(w, r)
        return
    }

    themeMutex.RLock()
    currentDarkTheme := darkTheme
    themeMutex.RUnlock()

    themeClass := ""
    if currentDarkTheme {
        themeClass = "dark"
    } else {
        themeClass = "light"
    }

    mainTemplate := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" data-theme="%s">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSAntifilter</title>
    <style>
        :root {
            --bg-color: #f5f5f5;
            --card-bg: white;
            --text-color: #333;
            --text-secondary: #666;
            --border-color: #e0e0e0;
            --editor-bg: #1e1e1e;
            --editor-text: #d4d4d4;
            --shadow-color: rgba(0,0,0,0.1);
            --hover-bg: rgba(0,0,0,0.03);
        }

        [data-theme="dark"] {
            --bg-color: #121212;
            --card-bg: #1e1e1e;
            --text-color: #e0e0e0;
            --text-secondary: #b0b0b0;
            --border-color: #404040;
            --editor-bg: #0d1117;
            --editor-text: #c9d1d9;
            --shadow-color: rgba(0,0,0,0.3);
            --hover-bg: rgba(255,255,255,0.05);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-color);
            min-height: 100vh;
            color: var(--text-color);
            transition: all 0.3s ease;
        }

        .header {
            background: var(--card-bg);
            box-shadow: 0 1px 3px var(--shadow-color);
            padding: 1rem 0;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .nav-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .nav-left {
            display: flex;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .btn {
            border: none;
            padding: 12px 30px;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .save-btn {
            background: #a8d5a8;
            color: #333;
        }

        .save-btn:hover {
            background: #95c695;
        }

        .update-btn {
            background: #a8c5d5;
            color: #333;
        }

        .update-btn:hover {
            background: #95b5c6;
        }

        .update-btn.loading::after {
            content: '';
            position: absolute;
            top: 50%%;
            left: 50%%;
            width: 20px;
            height: 20px;
            margin: -10px 0 0 -10px;
            border: 2px solid #333;
            border-top: 2px solid transparent;
            border-radius: 50%%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0%% { transform: rotate(0deg); }
            100%% { transform: rotate(360deg); }
        }

        .theme-toggle-container {
            display: flex;
            align-items: center;
        }

        .theme-options {
            display: flex;
            align-items: center;
        }

        .theme-toggle {
            position: relative;
            display: inline-block;
            width: 60px;
            height: 28px;
        }

        .theme-toggle input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            border-radius: 34px;
            transition: 0.3s;
        }

        .slider:before {
            position: absolute;
            content: "";
            height: 20px;
            width: 20px;
            left: 4px;
            bottom: 4px;
            background-color: white;
            border-radius: 50%%;
            transition: 0.3s;
        }

        input:checked + .slider {
            background-color: #60a5fa;
        }

        input:checked + .slider:before {
            transform: translateX(32px);
        }

        .theme-icon {
            margin: 0 8px;
            cursor: pointer;
            opacity: 0.5;
            transition: opacity 0.3s;
            width: 18px;
            height: 18px;
            fill: var(--text-color);
        }

        .theme-icon.active {
            opacity: 1;
        }

        .theme-icon svg {
            width: 100%%;
            height: 100%%;
        }

        .auto-icon {
            margin-left: 10px;
        }

        .tabs {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }

        .tab {
            padding: 10px 20px;
            background: #f8f9fa;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            white-space: nowrap;
            color: #666;
        }

        [data-theme="dark"] .tab {
            background: #404040;
            color: #ccc;
        }

        .tab:hover {
            background: #e9ecef;
        }

        [data-theme="dark"] .tab:hover {
            background: #505050;
        }

        .tab.active {
            background: #d0d0d0;
            color: #333;
            border-color: #bbb;
        }

        [data-theme="dark"] .tab.active {
            background: #606060;
            color: #fff;
        }

        .main-container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 2rem;
        }

        .editor-container {
            background: var(--card-bg);
            border-radius: 8px;
            box-shadow: 0 2px 8px var(--shadow-color);
            overflow: hidden;
            border: 1px solid var(--border-color);
            position: relative;
        }

        .editor-header {
            background: var(--card-bg);
            padding: 10px 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 14px;
            color: var(--text-color);
        }

        .line-counter {
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            color: var(--text-secondary);
        }

        #editor {
            width: 100%%;
            height: 70vh;
            min-height: 400px;
            border: none;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 14px;
            line-height: 1.5;
            padding: 20px;
            resize: none;
            background: var(--editor-bg);
            color: var(--editor-text);
            tab-size: 4;
            outline: none;
        }

        #editor::selection {
            background: #264f78;
        }

        .status-bar {
            background: var(--card-bg);
            padding: 1rem 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px var(--shadow-color);
            border: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .last-update {
            font-size: 14px;
            color: var(--text-secondary);
        }

        .logs-container {
            background: var(--card-bg);
            border-radius: 8px;
            box-shadow: 0 2px 8px var(--shadow-color);
            border: 1px solid var(--border-color);
        }

        .logs-title {
            font-weight: 600;
            padding: 1rem 2rem;
            color: var(--text-color);
            border-bottom: 1px solid var(--border-color);
            background: var(--card-bg);
            border-radius: 8px 8px 0 0;
        }

        .logs-content {
            max-height: 200px;
            overflow-y: auto;
            padding: 0 2rem 1rem 2rem;
        }

        .log-entry {
            padding: 5px 0;
            border-bottom: 1px solid var(--border-color);
            font-size: 14px;
            display: flex;
            gap: 1rem;
        }

        .log-entry:last-child {
            border-bottom: none;
        }

        .log-time {
            color: var(--text-secondary);
            min-width: 120px;
        }

        .log-message {
            flex: 1;
        }

        .log-level-success { color: #28a745; }
        .log-level-error { color: #dc3545; }
        .log-level-warning { color: #ffc107; }
        .log-level-info { color: #17a2b8; }

        .footer {
            background: var(--card-bg);
            margin: 2rem auto;
            max-width: 1200px;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px var(--shadow-color);
            border: 1px solid var(--border-color);
        }

        .footer-section {
            margin-bottom: 1.5rem;
        }

        .footer-title {
            font-weight: 600;
            color: var(--text-color);
            margin-bottom: 0.5rem;
        }

        .footer-links {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .footer-links a {
            color: var(--text-secondary);
            text-decoration: none;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 14px;
            background: #f8f9fa;
            border: 1px solid var(--border-color);
        }

        [data-theme="dark"] .footer-links a {
            background: #404040;
            color: #ccc;
        }

        .footer-links a:hover {
            background: #e9ecef;
        }

        [data-theme="dark"] .footer-links a:hover {
            background: #505050;
        }

        .copyright {
            text-align: center;
            color: var(--text-secondary);
            font-size: 14px;
            border-top: 1px solid var(--border-color);
            padding-top: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .copyright-left {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .copyright-right {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .copyright a {
            color: var(--text-secondary);
            text-decoration: none;
        }

        .copyright a:hover {
            color: var(--text-color);
        }

        .status-message {
            position: fixed;
            top: 12px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 4px;
            color: #333;
            font-weight: 500;
            z-index: 1000;
            transform: translateX(100%%);
            transition: transform 0.3s ease;
            border: 1px solid;
        }

        .status-message.success {
            background: #d4edda;
            border-color: #c3e6cb;
        }

        .status-message.error {
            background: #f8d7da;
            border-color: #f5c6cb;
        }

        .status-message.show {
            transform: translateX(0);
        }

        .button-row {
            display: flex;
            gap: 0.5rem;
            width: 100%;
        }

        @media (max-width: 768px) {
            .nav-container {
                padding: 0 1rem;
            }

            .button-row .btn {
                flex: 1;
                text-align: center;
                font-size: 13px;
                padding: 10px 8px;
                min-width: 0;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }

            .tabs {
                order: 3;
                width: 100%%;
            }

            .tab {
                flex: 1;
                text-align: center;
                font-size: 12px;
                padding: 8px 12px;
            }

            .main-container {
                padding: 0 1rem;
            }

            .logs-title {
                padding: 1rem;
            }

            .logs-content {
                padding: 0 1rem 1rem 1rem;
            }

            #editor {
                font-size: 16px;
                height: 50vh;
            }

            .copyright {
                flex-direction: column;
                text-align: center;
            }

            .status-bar {
                flex-direction: column;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="nav-container">
            <div class="nav-left">
                <div class="button-row">
                    <button class="btn save-btn" id="saveBtn" onclick="doSave()">
                        <span id="saveStatus">Save Rules</span>
                    </button>
                    <button class="btn update-btn" id="updateBtn" onclick="updateAntifilter()">
                        <span id="updateStatus">Update Antifilter</span>
                    </button>
                </div>
                <div class="theme-toggle-container">
                    <div class="theme-options">
                        <div class="theme-icon light-icon" title="Светлая тема">
                            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M12 3V5M12 19V21M5 12H3M21 12H19M17.8 6.2L16.4 7.6M7.6 16.4L6.2 17.8M17.8 17.8L16.4 16.4M7.6 7.6L6.2 6.2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                                <circle cx="12" cy="12" r="4.5" fill="currentColor" stroke="currentColor" stroke-width="1"/>
                            </svg>
                        </div>
                        <label class="theme-toggle">
                            <input type="checkbox" id="theme-toggle-switch">
                            <span class="slider"></span>
                        </label>
                        <div class="theme-icon dark-icon" title="Темная тема">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
                                <path d="M12 3a9 9 0 1 0 9 9c0-.46-.04-.92-.1-1.36a5.389 5.389 0 0 1-4.4 2.26 5.403 5.403 0 0 1-3.14-9.8c-.44-.06-.9-.1-1.36-.1z"/>
                            </svg>
                        </div>
                    </div>
                    <div class="theme-icon auto-icon" title="Авто режим">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm0 18V4a8 8 0 1 1 0 16z"/>
                        </svg>
                    </div>
                </div>
                <div class="tabs">
                    <span class="tab active" id="tab-proxy-domain">Proxy Domain</span>
                    <span class="tab" id="tab-direct-domain">Direct Domain</span>
                    <span class="tab" id="tab-proxy-ip">Proxy IP</span>
                    <span class="tab" id="tab-direct-ip">Direct IP</span>
                </div>
            </div>
        </div>
    </div>

    <div class="main-container">
        <div class="editor-container">
            <div class="editor-header">
                <span>Editing: <strong id="current-file">proxy-domain</strong></span>
                <span class="line-counter" id="line-counter">Lines: 0</span>
            </div>
            <textarea id="editor" placeholder="Loading..."></textarea>
        </div>
    </div>

    <div class="main-container">
        <div class="status-bar">
            <div class="last-update">
                Antifilter last update: <span id="last-update">Never</span>
            </div>
        </div>
    </div>

    <div class="main-container">
        <div class="logs-container">
            <div class="logs-title">Recent Activity</div>
            <div class="logs-content" id="logs-content">
                <!-- Logs will be populated here -->
            </div>
        </div>
    </div>

    <div class="main-container">
        <div class="footer">
            <div class="footer-section">
                <div class="footer-title">Clash Text/Shadowrocket Lists</div>
                <div class="footer-links">
                    <a href="/antifilter-ip.list" target="_blank">Antifilter IP-CIDR</a>
                    <a href="/antifilter-community-ip.list" target="_blank">Antifilter Community IP-CIDR</a>
                    <a href="/antifilter-community-domain.list" target="_blank">Antifilter Community Domain</a>
                    <a href="/proxy-domain.list" target="_blank">Proxy Domain/Keyword/Full</a>
                    <a href="/direct-domain.list" target="_blank">Direct Domain/Keyword/Full</a>
                    <a href="/proxy-ip.list" target="_blank">Proxy IP-CIDR</a>
                    <a href="/direct-ip.list" target="_blank">Direct IP-CIDR</a>
                </div>
            </div>

            <div class="footer-section">
                <div class="footer-title">Clash Lists</div>
                <div class="footer-links">
                    <a href="/antifilter-ip.yaml" target="_blank">Antifilter IP-CIDR</a>
                    <a href="/antifilter-community-ip.yaml" target="_blank">Antifilter Community IP-CIDR</a>
                    <a href="/antifilter-community-domain.yaml" target="_blank">Antifilter Community Domain</a>
                    <a href="/proxy-domain.yaml" target="_blank">Proxy Domain/Keyword/Full</a>
                    <a href="/direct-domain.yaml" target="_blank">Direct Domain/Keyword/Full</a>
                    <a href="/proxy-ip.yaml" target="_blank">Proxy IP-CIDR</a>
                    <a href="/direct-ip.yaml" target="_blank">Direct IP-CIDR</a>
                </div>
            </div>

            <div class="footer-section">
                <div class="footer-title">v2ray GeoIP/GeoSite DBs</div>
                <div class="footer-links">
                    <a href="/geoip.dat" target="_blank">GeoIP Database</a>
                    <a href="/geosite.dat" target="_blank">GeoSite Database</a>
                </div>
            </div>

            <div class="copyright">
                <div class="copyright-left">
                    Created by ZeroChaos | Visit site: <a href="https://zerolab.net" target="_blank">zerolab.net</a>
                </div>
                <div class="copyright-right">
                    <span><a href="/logout">Logout</a></span>
                </div>
            </div>
        </div>
    </div>

    <script>
        let fileName = "proxy-domain";

        function postAjax(url, data, success) {
            const params = new URLSearchParams(data).toString();
            fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: params
            })
            .then(response => response.text())
            .then(success)
            .catch(error => console.error('Error:', error));
        }

        function showStatus(message, type = 'success') {
            const existing = document.querySelector('.status-message');
            if (existing) {
                existing.remove();
            }

            const statusDiv = document.createElement('div');
            statusDiv.className = 'status-message ' + type;
            statusDiv.textContent = message;
            document.body.appendChild(statusDiv);

            setTimeout(() => statusDiv.classList.add('show'), 100);

            setTimeout(() => {
                statusDiv.classList.remove('show');
                setTimeout(() => statusDiv.remove(), 300);
            }, 3000);
        }

        function updateLineCounter() {
            const editor = document.getElementById('editor');
            const lines = editor.value.split('\n').length;
            document.getElementById('line-counter').textContent = 'Lines: ' + lines;
        }

        function loadFile(file) {
            document.getElementById('editor').placeholder = 'Loading...';
            document.getElementById('current-file').textContent = file;

            postAjax('/api/retrieve', {fileName: file}, function(data) {
                document.getElementById('editor').value = data;
                document.getElementById('editor').placeholder = '';
                updateLineCounter();
            });
        }

        function doSave() {
            const saveBtn = document.getElementById('saveBtn');
            const saveStatus = document.getElementById('saveStatus');
            const editor = document.getElementById('editor');
            const logsContainer = document.getElementById('logs-content');

            // Проверяем наличие необходимых элементов
            if (!saveBtn || !saveStatus || !editor || !logsContainer) {
                console.error('Required elements not found');
                return;
            }

            saveBtn.disabled = true;
            saveStatus.textContent = 'Saving...';

            // Очищаем предыдущие сообщения об ошибках
            const existingError = document.querySelector('.status-message.error');
            if (existingError) {
                existingError.remove();
            }

            postAjax('/api/save', {
                fileName: fileName,
                content: editor.value
            }, function(data) {
                try {
                    let result;
                    try {
                        result = JSON.parse(data);
                    } catch (e) {
                        console.error('Failed to parse response:', data);
                        throw new Error('Invalid server response');
                    }

                    // Показываем статус сохранения
                    if (result.desc && result.level) {
                        showStatus(result.desc, result.level === 'fatal' ? 'error' : 'success');
                    } else {
                        showStatus('Operation completed', 'success');
                    }

                    // Добавляем новые логи в интерфейс
                    if (result.new_logs && Array.isArray(result.new_logs)) {
                        result.new_logs.forEach(log => {
                            if (!log.time || !log.message || !log.level) {
                                console.warn('Invalid log entry:', log);
                                return;
                            }

                            const logEntry = document.createElement('div');
                            logEntry.className = 'log-entry';

                            try {
                                const time = new Date(log.time).toLocaleTimeString();
                                logEntry.innerHTML =
                                    '<span class="log-time">' + time + '</span>' +
                                    '<span class="log-message log-level-' + log.level + '">' + escapeHtml(log.message) + '</span>';
                                logsContainer.appendChild(logEntry);
                            } catch (e) {
                                console.error('Error creating log entry:', e);
                            }
                        });

                        // Прокручиваем к новым логам только если есть новые записи
                        if (result.new_logs.length > 0) {
                            setTimeout(() => {
                                logsContainer.scrollTop = logsContainer.scrollHeight;
                            }, 100);
                        }
                    }

                    // Перезагрузка содержимого файла
                    setTimeout(() => {
                        loadFile(fileName);
                    }, 500);

                } catch(e) {
                    console.error('Save error:', e);
                    showStatus('Error saving file: ' + e.message, 'error');
                } finally {
                    saveBtn.disabled = false;
                    saveStatus.textContent = 'Save Rules';

                    // Обновляем статус через 1 секунду для получения актуальных данных
                    setTimeout(updateStatus, 1000);
                }
            });
        }

        // Вспомогательная функция для экранирования HTML
        function escapeHtml(unsafe) {
            return unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        function updateAntifilter() {
            const updateBtn = document.getElementById('updateBtn');
            const updateStatusEl = document.getElementById('updateStatus');
            const logsContainer = document.getElementById('logs-content');

            if (!updateBtn || !updateStatusEl || !logsContainer) {
                console.error('Required elements not found');
                return;
            }

            updateBtn.disabled = true;
            updateBtn.classList.add('loading');
            updateStatusEl.textContent = 'Updating...';

            // Очистка предыдущих сообщений об ошибках
            const existingError = document.querySelector('.status-message.error');
            if (existingError) existingError.remove();

            postAjax('/api/update-antifilter', {}, function(data) {
                try {
                    const result = JSON.parse(data);
                    showStatus(result.desc, result.level === 'fatal' ? 'error' : 'success');

                    // Принудительное обновление логов
                    fetchAndUpdateLogs();

                } catch(e) {
                    console.error('Update error:', e);
                    showStatus('Update error: ' + e.message, 'error');
                } finally {
                    updateBtn.disabled = false;
                    updateBtn.classList.remove('loading');
                    updateStatusEl.textContent = 'Update Antifilter';
                }
            });
        }

        // Новая отдельная функция для обновления логов
        function fetchAndUpdateLogs() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    if (!data.logs) return;

                    const logsContainer = document.getElementById('logs-content');
                    if (!logsContainer) return;

                    const wasScrolledToBottom =
                        logsContainer.scrollHeight - logsContainer.clientHeight <=
                        logsContainer.scrollTop + 100;

                    // Обновляем логи
                    logsContainer.innerHTML = '';
                    data.logs.slice(-100).forEach(log => {
                        const logEntry = document.createElement('div');
                        logEntry.className = 'log-entry';
                        const time = new Date(log.time).toLocaleTimeString();
                        logEntry.innerHTML =
                            '<span class="log-time">' + time + '</span>' +
                            '<span class="log-message log-level-' + log.level + '">' +
                            escapeHtml(log.message) + '</span>';
                        logsContainer.appendChild(logEntry);
                    });

                    // Прокручиваем вниз, если нужно
                    if (wasScrolledToBottom) {
                        setTimeout(() => {
                            logsContainer.scrollTop = logsContainer.scrollHeight;
                        }, 100);
                    }
                })
                .catch(error => console.error('Error fetching logs:', error));
        }

        // Функция для определения темной темы системы
        function prefersDarkTheme() {
            return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
        }

        // Установка темы
        function setTheme(theme) {
            const htmlElement = document.documentElement;
            const themeToggle = document.getElementById('theme-toggle-switch');
            const lightIcon = document.querySelector('.light-icon');
            const darkIcon = document.querySelector('.dark-icon');
            const autoIcon = document.querySelector('.auto-icon');

            if (theme === 'auto') {
                if (prefersDarkTheme()) {
                    htmlElement.setAttribute('data-theme', 'dark');
                    themeToggle.checked = true;
                } else {
                    htmlElement.setAttribute('data-theme', 'light');
                    themeToggle.checked = false;
                }
            } else {
                htmlElement.setAttribute('data-theme', theme);
                themeToggle.checked = theme === 'dark';
            }

            // Обновление активных иконок
            lightIcon.classList.remove('active');
            darkIcon.classList.remove('active');
            autoIcon.classList.remove('active');

            if (theme === 'auto') {
                autoIcon.classList.add('active');
            } else if (theme === 'light') {
                lightIcon.classList.add('active');
            } else {
                darkIcon.classList.add('active');
            }

            // Сохранение выбора в localStorage
            localStorage.setItem('theme-preference', theme);

            // Отправка на сервер
            postAjax('/api/theme', {theme: theme === 'auto' ? (prefersDarkTheme() ? 'dark' : 'light') : theme}, function(data) {});
        }

        // Загрузка сохраненной темы из localStorage или использование авто режима
        function loadSavedTheme() {
            const savedTheme = localStorage.getItem('theme-preference') || 'auto';
            setTheme(savedTheme);
        }

        function updateStatus() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    if (data.last_update) {
                        const date = new Date(data.last_update);
                        document.getElementById('last-update').textContent = date.toLocaleString();
                    }

                    if (data.logs) {
                        const logsContainer = document.getElementById('logs-content');
                        const wasScrolledToBottom =
                            logsContainer.scrollHeight - logsContainer.clientHeight <=
                            logsContainer.scrollTop + 50;

                        logsContainer.innerHTML = '';

                        data.logs.slice(-100).forEach(log => {
                            const logEntry = document.createElement('div');
                            logEntry.className = 'log-entry';
                            const time = new Date(log.time).toLocaleTimeString();
                            logEntry.innerHTML =
                                '<span class="log-time">' + time + '</span>' +
                                '<span class="log-message log-level-' + log.level + '">' +
                                escapeHtml(log.message) + '</span>';
                            logsContainer.appendChild(logEntry);
                        });

                        if (wasScrolledToBottom) {
                            setTimeout(() => {
                                logsContainer.scrollTop = logsContainer.scrollHeight;
                            }, 100);
                        }
                    }
                })
                .catch(error => console.error('Error updating status:', error));
        }

        function setupTabs() {
            const tabs = {
                'tab-proxy-domain': 'proxy-domain',
                'tab-direct-domain': 'direct-domain',
                'tab-proxy-ip': 'proxy-ip',
                'tab-direct-ip': 'direct-ip'
            };

            Object.keys(tabs).forEach(tabId => {
                document.getElementById(tabId).addEventListener('click', function() {
                    Object.keys(tabs).forEach(id => {
                        document.getElementById(id).classList.remove('active');
                    });

                    this.classList.add('active');

                    fileName = tabs[tabId];
                    loadFile(fileName);
                });
            });
        }

        document.addEventListener('DOMContentLoaded', function() {
            const themeToggle = document.getElementById('theme-toggle-switch');
            const lightIcon = document.querySelector('.light-icon');
            const darkIcon = document.querySelector('.dark-icon');
            const autoIcon = document.querySelector('.auto-icon');

            // Обработчик переключателя темы
            themeToggle.addEventListener('change', function() {
                setTheme(this.checked ? 'dark' : 'light');
            });

            // Обработчик клика по иконке светлой темы
            lightIcon.addEventListener('click', function() {
                setTheme('light');
            });

            // Обработчик клика по иконке темной темы
            darkIcon.addEventListener('click', function() {
                setTheme('dark');
            });

            // Обработчик клика по иконке авто режима
            autoIcon.addEventListener('click', function() {
                setTheme('auto');
            });

            // Отслеживание изменения системной темы
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function() {
                if (localStorage.getItem('theme-preference') === 'auto') {
                    setTheme('auto');
                }
            });

            // Загрузка темы при инициализации
            loadSavedTheme();

            setupTabs();
            loadFile(fileName);
            updateStatus();

            // Обновление счетчика строк при вводе
            document.getElementById('editor').addEventListener('input', updateLineCounter);

            // Обновляем статус каждые 10 секунд
            setInterval(updateStatus, 10000);
        });

        // Горячие клавиши
        document.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                e.preventDefault();
                doSave();
            }
            if ((e.ctrlKey || e.metaKey) && e.key === 'u') {
                e.preventDefault();
                updateAntifilter();
            }
        });
    </script>
</body>
</html>`, themeClass)

    w.Header().Set("Content-Type", "text/html")
    fmt.Fprint(w, mainTemplate)
}

func retrieveHandler(w http.ResponseWriter, r *http.Request) {
    if !isAuthenticated(r) {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    if r.Method != "POST" {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    fileName := r.FormValue("fileName")
    if fileName == "" {
        http.Error(w, "fileName is required", http.StatusBadRequest)
        return
    }

    // Ищем файл в rawdata для редактируемых файлов
    filePath := fileName
    if fileName == "proxy-domain" || fileName == "direct-domain" || fileName == "proxy-ip" || fileName == "direct-ip" {
        filePath = filepath.Join("rawdata", fileName)
    }

    content, err := os.ReadFile(filePath)
    if err != nil {
        w.Header().Set("Content-Type", "text/plain")
        w.Write([]byte(""))
        return
    }

    if len(content) == 1 && content[0] == 0 {
        content = []byte("")
    }

    w.Header().Set("Content-Type", "text/plain")
    w.Write(content)
}

func saveHandler(w http.ResponseWriter, r *http.Request) {
    if !isAuthenticated(r) {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    if r.Method != "POST" {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Запоминаем текущее количество логов
    initialLogsCount := len(appState.Logs)

    fileName := r.FormValue("fileName")
    content := strings.TrimSpace(r.FormValue("content"))

    if fileName == "" {
        response := Response{Desc: "fileName is required", Level: "fatal"}
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
        return
    }

    // Сохраняем в rawdata
    rawFilePath := filepath.Join("rawdata", fileName)
    var fileContent []byte
    // Если содержимое пустое, используем примеры из exampleFiles
    if content == "" {
        if exampleContent, exists := exampleFiles[fileName]; exists {
            fileContent = []byte(exampleContent)
            addLog(fmt.Sprintf("File %s was empty, restored default content", fileName), "info")
        } else {
            fileContent = []byte{0}
        }
    } else {
        fileContent = []byte(content + "\n")
    }

    err := os.WriteFile(rawFilePath, fileContent, 0644)
    if err != nil {
        response := Response{Desc: "Error writing file: " + err.Error(), Level: "fatal"}
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
        return
    }

    addLog(fmt.Sprintf("File %s saved successfully", fileName), "success")

    // Конвертируем и генерируем файлы
    fileActions := map[string]struct {
        shadowrocketFile string
        clashFile        string
        needsGeoGeneration bool
        geoType           string
    }{
        "proxy-domain":  {"lists/proxy-domain.list", "lists/proxy-domain.yaml", true, "geosite"},
        "direct-domain": {"lists/direct-domain.list", "lists/direct-domain.yaml", true, "geosite"},
        "proxy-ip":      {"lists/proxy-ip.list", "lists/proxy-ip.yaml", true, "geoip"},
        "direct-ip":     {"lists/direct-ip.list", "lists/direct-ip.yaml", true, "geoip"},
    }

    if action, exists := fileActions[fileName]; exists {
        // Конвертируем в Shadowrocket формат
        if err := convertToShadowrocket(rawFilePath, action.shadowrocketFile); err != nil {
            addLog(fmt.Sprintf("Failed to convert to Clash Text/Shadowrocket format: %v", err), "error")
        } else {
            addLog(fmt.Sprintf("Clash Text/Shadowrocket list generated: %s", action.shadowrocketFile), "success")
        }

        // Конвертируем в Clash формат
        if err := convertToClash(action.shadowrocketFile, action.clashFile); err != nil {
            addLog(fmt.Sprintf("Failed to convert to Clash format: %v", err), "error")
        } else {
            addLog(fmt.Sprintf("Clash config generated: %s", action.clashFile), "success")
        }

        // Генерируем geo файлы
        if action.needsGeoGeneration {
            if action.geoType == "geoip" {
                if err := generateGeoIP(); err != nil {
                    addLog(fmt.Sprintf("Failed to generate geoip.dat: %v", err), "error")
                }
            } else if action.geoType == "geosite" {
                if err := generateGeoSite(); err != nil {
                    addLog(fmt.Sprintf("Failed to generate geosite.dat: %v", err), "error")
                }
            }
        }
    }

    // Получаем все новые логи, которые появились в процессе сохранения
    appState.mu.RLock()
    var newLogs []LogEntry
    if len(appState.Logs) > initialLogsCount {
        newLogs = make([]LogEntry, len(appState.Logs)-initialLogsCount)
        copy(newLogs, appState.Logs[initialLogsCount:])
    }
    appState.mu.RUnlock()

    response := struct {
        Response
        NewLogs []LogEntry `json:"new_logs"`
    }{
        Response: Response{
            Desc:  "Saved successfully",
            Level: "success",
        },
        NewLogs: newLogs,
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

var updateInProgress sync.Mutex

func updateAntifilterHandler(w http.ResponseWriter, r *http.Request) {
    if !isAuthenticated(r) {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    if r.Method != "POST" {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    if !updateInProgress.TryLock() {
        response := Response{Desc: "Update already in progress", Level: "warning"}
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
        return
    }

    go func() {
        defer updateInProgress.Unlock()
        if err := updateAntifilterLists(); err != nil {
            addLog(fmt.Sprintf("Manual Antifilter update failed: %v", err), "error")
        }
    }()

    response := Response{Desc: "Antifilter update started", Level: "success"}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func convertToShadowrocket(fromFile, toFile string) error {
    content, err := os.ReadFile(fromFile)
    if err != nil {
        return err
    }

    if len(content) == 1 && content[0] == 0 {
        return os.WriteFile(toFile, []byte{0}, 0644)
    }

    lines := strings.Split(string(content), "\n")
    var prefix string

    if strings.Contains(fromFile, "domain") {
        prefix = "DOMAIN-SUFFIX,"
    } else if strings.Contains(fromFile, "ip") {
        prefix = "IP-CIDR,"
    }

    var result []string
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }

        if strings.HasPrefix(line, "domain:") && prefix == "DOMAIN-SUFFIX," {
            result = append(result, strings.Replace(line, "domain:", "DOMAIN-SUFFIX,", 1))
        } else if strings.HasPrefix(line, "keyword:") && prefix == "DOMAIN-SUFFIX," {
            result = append(result, strings.Replace(line, "keyword:", "DOMAIN-KEYWORD,", 1))
        } else if strings.HasPrefix(line, "full:") && prefix == "DOMAIN-SUFFIX," {
            result = append(result, strings.Replace(line, "full:", "DOMAIN,", 1))
        } else {
            result = append(result, prefix+line)
        }
    }

    finalContent := strings.Join(result, "\n")
    if finalContent != "" {
        finalContent += "\n"
    }

    return os.WriteFile(toFile, []byte(finalContent), 0644)
}

func convertToClash(fromFile, toFile string) error {
    listFile := fromFile
    if !strings.HasSuffix(fromFile, ".list") {
        listFile = fromFile + ".list"
    }

    content, err := os.ReadFile(listFile)
    if err != nil {
        return err
    }

    if len(content) == 1 && content[0] == 0 {
        return os.WriteFile(toFile, []byte("payload:\n"), 0644)
    }

    lines := strings.Split(string(content), "\n")
    var result []string
    result = append(result, "payload:")

    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        result = append(result, "  - "+line)
    }

    return os.WriteFile(toFile, []byte(strings.Join(result, "\n")+"\n"), 0644)
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
    // Получаем имя файла из URL и очищаем путь
    filename := strings.TrimPrefix(r.URL.Path, "/")
    filename = filepath.Clean(filename)

    // Проверяем базовые условия безопасности
    if filename == "" || filename == "." || filename == "lists" {
        http.Error(w, "Invalid filename", http.StatusBadRequest)
        return
    }

    // Полный путь к запрашиваемому файлу
    filePath := filepath.Join("lists", filename)

    // Получаем абсолютные пути для проверки безопасности
    absFilePath, err := filepath.Abs(filePath)
    if err != nil {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }

    absListsDir, err := filepath.Abs("lists")
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Проверяем, что файл находится внутри разрешенной директории
    if !strings.HasPrefix(absFilePath, absListsDir + string(filepath.Separator)) {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }

    // Проверяем существование файла
    fileInfo, err := os.Stat(absFilePath)
    if os.IsNotExist(err) {
        http.Error(w, "File not found", http.StatusNotFound)
        return
    }
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Проверяем, что это обычный файл (не директория и не симлинк)
    if !fileInfo.Mode().IsRegular() {
        http.Error(w, "Invalid file type", http.StatusBadRequest)
        return
    }

    // Определяем Content-Type в зависимости от расширения файла
    contentType := "text/plain"
    switch strings.ToLower(filepath.Ext(filename)) {
    case ".yaml", ".yml":
        contentType = "text/yaml"
    case ".list":
        contentType = "text/plain"
    case ".dat":
        contentType = "application/octet-stream"
    }

    // Открываем файл
    file, err := os.Open(absFilePath)
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    defer file.Close()

    // Устанавливаем заголовки и отправляем файл
    w.Header().Set("Content-Type", contentType)
    w.Header().Set("Content-Length", fmt.Sprint(fileInfo.Size()))
    http.ServeContent(w, r, filename, fileInfo.ModTime(), file)
}

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

func main() {
    initConfig()
    initDirectories()
    initExampleFiles()

    store.Options = &sessions.Options{
        Path:     "/",
        MaxAge:   86400 * 7,
        HttpOnly: true,
        Secure:   false,
        SameSite: http.SameSiteStrictMode,
    }

    // Запускаем автоматическое обновление Antifilter списков
    startAntifilterUpdater()

    mux := http.NewServeMux()

    mux.HandleFunc("/logout", logoutHandler)
    mux.HandleFunc("/api/retrieve", retrieveHandler)
    mux.HandleFunc("/api/save", saveHandler)
    mux.HandleFunc("/api/update-antifilter", updateAntifilterHandler)
    mux.HandleFunc("/api/theme", themeHandler)
    mux.HandleFunc("/api/status", statusHandler)

    // Создаем единый обработчик для всех остальных маршрутов
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        path := r.URL.Path
        if path == "/" {
            mainHandler(w, r)
            return
        }

        // Проверяем, является ли это запросом файла
        fileExtensions := []string{".yaml", ".yml", ".list", ".dat"}
        for _, extension := range fileExtensions {
            if strings.HasSuffix(path, extension) {
                fileHandler(w, r)
                return
            }
        }

        http.NotFound(w, r)
    })

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    // HTTPS опционально
    useHTTPS := os.Getenv("USE_HTTPS")
    certFile := os.Getenv("HTTPS_CERT_FILE")
    keyFile := os.Getenv("HTTPS_KEY_FILE")

    srv := &http.Server{
        Addr:              ":" + port,
        Handler:           mux,
        ReadTimeout:       15 * time.Second,
        WriteTimeout:      15 * time.Second,
        IdleTimeout:       60 * time.Second,
        ReadHeaderTimeout: 5 * time.Second,
    }

    if useHTTPS == "1" && certFile != "" && keyFile != "" {
        fmt.Printf("Server starting on port %s (HTTPS)\n", port)
        fmt.Printf("Access the application at: https://YOUR_DOMAIN:%s\n", port)
        log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
    } else {
        fmt.Printf("Server starting on port %s (HTTP)\n", port)
        fmt.Printf("Access the application at: http://YOUR_DOMAIN:%s\n", port)
        log.Fatal(srv.ListenAndServe())
    }
}
