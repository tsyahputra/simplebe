package helper

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
)

func ResponseJSON(w http.ResponseWriter, code int, payload any) {
	respon, _ := json.Marshal(payload)
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(respon)
}

func ResponseMessage(w http.ResponseWriter, code int, message string) {
	ResponseJSON(w, code, map[string]string{"message": message})
}

func GenerateRandomString(length int) (string, error) {
	b := make([]byte, length/2)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("gagal menghasilkan byte acak: %w", err)
	}
	return hex.EncodeToString(b), nil
}
