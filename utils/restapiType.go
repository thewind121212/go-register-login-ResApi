package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		return err
	}
	return nil
}

func WriteJSONInternalError(w http.ResponseWriter, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		return err
	}
	return nil
}

type ApiError struct {
	Error string
}

// define function apiFn
type apiFunc func(http.ResponseWriter, *http.Request) error

// makeHTTPHandlerFn fn
func MakeHTTPHandlerFn(fn apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			if err := WriteJSON(w, http.StatusInternalServerError, ApiError{Error: err.Error()}); err != nil {
				fmt.Print(err)
			}
		}
	}
}
