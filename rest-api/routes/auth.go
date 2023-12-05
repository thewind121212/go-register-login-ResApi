package routes

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
)

type AuthRouter struct{}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

type ApiError struct {
	Error string
}

type apiFunc func(http.ResponseWriter, *http.Request) error

func MakeHTTPHandlerFn(fn apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			if err := WriteJSON(w, http.StatusInternalServerError, ApiError{Error: err.Error()}); err != nil {
				fmt.Print(err)
			}
		}
	}
}

func RegisterNewAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == http.MethodGet {
		fmt.Println("API Route Healthy")
	}

	if r.Method == http.MethodPost {
		fmt.Println("method Post")
	}

	return nil
}

func AuthRouterSetup(router *mux.Router) {
	authRouter := router.PathPrefix("/account").Subrouter()
	authRouter.Handle("/register", MakeHTTPHandlerFn(RegisterNewAccount)).Methods("GET")
	linh := authRouter.Handle("/register", MakeHTTPHandlerFn(RegisterNewAccount)).GetError()
	fmt.Println(linh)
}
