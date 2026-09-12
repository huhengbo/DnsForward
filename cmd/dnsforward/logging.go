package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	logFileMu sync.Mutex
	recentMu  sync.RWMutex
	recentLog []string
)

const recentLogLimit = 200

func fatalf(format string, args ...interface{}) {
	serviceLogger(fmt.Sprintf(format, args...), 31, false)
	os.Exit(1)
}

func serviceLogger(message string, color int, isDebug bool) {
	if isDebug && !EnableDebug {
		return
	}
	msg := strings.ReplaceAll(message, "\n", "")
	msg = strings.Join([]string{time.Now().Format("2006/01/02 15:04:05"), " ", msg}, "")

	recentMu.Lock()
	recentLog = append(recentLog, msg)
	if len(recentLog) > recentLogLimit {
		recentLog = append([]string(nil), recentLog[len(recentLog)-recentLogLimit:]...)
	}
	recentMu.Unlock()

	if color == 0 {
		fmt.Printf("%s\n", msg)
	} else {
		fmt.Printf("%c[1;0;%dm%s%c[0m\n", 0x1B, color, msg, 0x1B)
	}
	if LogFilePath != "" {
		logFileMu.Lock()
		defer logFileMu.Unlock()
		fd, err := os.OpenFile(LogFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "日志文件打开失败: %v\n", err)
			return
		}
		defer fd.Close()
		if _, err := fd.WriteString(msg + "\n"); err != nil {
			fmt.Fprintf(os.Stderr, "日志文件写入失败: %v\n", err)
		}
	}
}

func recentLogLines() []string {
	recentMu.RLock()
	defer recentMu.RUnlock()
	return append([]string(nil), recentLog...)
}
