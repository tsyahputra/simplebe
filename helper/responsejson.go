package helper

import (
	"encoding/json"
	"net/http"
)

func ResponseJSON(w http.ResponseWriter, code int, payload interface{}) {
	respon, _ := json.Marshal(payload)
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(respon)
}

func ResponseError(w http.ResponseWriter, code int, message string) {
	ResponseJSON(w, code, map[string]string{"message": message})
}
