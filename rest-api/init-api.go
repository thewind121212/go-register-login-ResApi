package rest_api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"linhdevtran99/rest-api/models"
	"linhdevtran99/rest-api/rest-api/routes"
	"linhdevtran99/rest-api/rest-api/services"
	"linhdevtran99/rest-api/utils"
	"log"
	"net/http"
)

type APIServer struct {
	listenAddr string
}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
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

func NewAPIServer(listenAddr string) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
	}
}

func startMuxServer(s *APIServer, router *mux.Router) {
	log.Println("Listening on", s.listenAddr)

	if err := http.ListenAndServe(s.listenAddr, router); err != nil {
		log.Fatal(err)
	}
}

func (s *APIServer) Run() {
	router := mux.NewRouter()

	//authRouter := router.PathPrefix("/").Subrouter()

	routes.AuthRouterSetup(router)

	//authRouter.HandleFunc("/account", MakeHTTPHandlerFn(s.AuthRoute))

	//router.HandleFunc("/account/register", MakeHTTPHandlerFn(s.RegisterNewAccount))
	//router.HandleFunc("/account/register", MakeHTTPHandlerFn(s.AuthRoute))

	startMuxServer(s, router)
}

func (s *APIServer) AuthRoute(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	client := utils.MongoDB

	if r.Method == http.MethodGet {
		fmt.Println("hit")

		//m := mail.NewMessage()
		//
		//emailBody := utils.BuildEmail()
		//m.SetHeader("From", "kotomi.poro1@gmail.com")
		//m.SetHeader("To", "nhocdl.poro1@gmail.com")
		//m.SetHeader("Subject", "Hello!")
		//m.SetBody("text/html", emailBody)
		//
		//d := mail.NewDialer("smtp.gmail.com", 587, "kotomi.poro1@gmail.com", "btmpjudzebyspfxw")
		//d.StartTLSPolicy = mail.MandatoryStartTLS
		//
		//// Send the email to Bob, Cora and Dan.
		//if err := d.DialAndSend(m); err != nil {
		//	panic(err)
		//}

		//serect := os.Getenv("EMAIL_VERIFY_SECRET")
		//isPass, _ := generatorOtp("hello", "nhocdl.poro1@gmail.com", 12, serect)
		//fmt.Println(isPass)
		//cipherBase64 := createLinkVerify(&models.CreateUser{
		//	Username:        "thewind121212",
		//	Email:           "nhocdl.poro1@gmail.com",
		//	Password:        "linhporoQ1@",
		//	ConfirmPassword: "linhporoQ1@",
		//}, serect)
		//
		//key := []byte(serect)
		//
		//i, err := utils.DecryptAES(cipherBase64, key)
		//if err != nil {
		//	return err
		//}
		//
		//fmt.Println(string(i))

	}

	if r.Method == http.MethodPost {
		var registerInfo models.CreateUser

		_ = json.NewDecoder(r.Body).Decode(&registerInfo)
		//call function check info user type in
		validRegisterInfo := services.CheckAndValidRegisterFiled(&registerInfo, w)
		//call function check data user use in past or not
		isValidData := services.CheckAccountExist(client, registerInfo.Username, registerInfo.Email, w)

		if isValidData == false || validRegisterInfo == false {
			return errors.New("USER DON'T HAVE VALID INFO FOR REGISTER ACCOUNT")
		}

	}

	return nil
}

func (s *APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == http.MethodGet {
		ctx := context.Background()

		res, err := utils.Redis.Ping(ctx).Result()

		if err != nil {
			fmt.Println(err)
		}

		fmt.Println(res)

	}
	if r.Method == http.MethodPost {
		fmt.Println("POST")
	}
	if r.Method == http.MethodDelete {
		fmt.Println("DELETE")
	}
	if r.Method == http.MethodPut {
		fmt.Println("PUT")
	}
	if r.Method == http.MethodPatch {
		fmt.Println("PATCH")
	}

	return nil
}
