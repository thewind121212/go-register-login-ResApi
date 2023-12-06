package rest_api

import (
	"fmt"
	"github.com/gorilla/mux"
	"linhdevtran99/rest-api/models"
	"linhdevtran99/rest-api/rest-api/routes"
	"linhdevtran99/rest-api/rest-api/services"
	"linhdevtran99/rest-api/utils"
	"log"
	"net/http"
	"time"
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

	router.HandleFunc("/test", utils.MakeHTTPHandlerFn(s.TestRoute))

	startMuxServer(s, router)
}

func (s *APIServer) TestRoute(w http.ResponseWriter, r *http.Request) error {

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

		//_, otp := services.GeneratorOtp("hello", "nhocdl.poro1@gmail.com", 12, serect)
		//fmt.Println(otp.HashOTP)
		//fmt.Println(otp.PureOTP)

		//utils.EncryptAESMailLink("nhocdl.poro2@gmail.com", serect, w)

		//jsonData, _ := json.Marshal(map[string]string{"email": "nhocdl.poro1@gmail.com", "user": "thewind121212"})
		////
		//utils.Redis.Set(context.Background(), "otp:nhocdl.poro1@gmail.com", string(jsonData), time.Minute)
		//
		//utils.CheckAndWriteRedis("nhocdl.poro1@gmail.com", "thewind121212", "lasdjflasdjlfj")

		services.CheckAndWritePreuser(&models.PreusersMongo{
			Username:        "thewind121212",
			Email:           "nhocdl.poro2@gmail.com",
			PhoneNumber:     "0918327132",
			VerifySentCount: 0,
			CreatedDate:     time.Now(),
			UpdateDate:      time.Now(),
		})

		//

	}

	return nil
}
