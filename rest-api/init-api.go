package rest_api

import (
	"fmt"
	"github.com/gorilla/mux"
	"linhdevtran99/rest-api/rest-api/routes"
	"log"
	"net/http"
)

type APIServer struct {
	listenAddr string
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

	routes.AuthRouterSetup(router)
	startMuxServer(s, router)
}

func (s *APIServer) AuthRoute(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")

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

	return nil
}
