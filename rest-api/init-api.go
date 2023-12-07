package rest_api

import (
	"fmt"
	"github.com/gorilla/mux"
	"linhdevtran99/rest-api/models"
	"linhdevtran99/rest-api/rest-api/routes"
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

		//serect := os.Getenv("EMAIL_VERIFY_SECRET")

		//_, otp := services.GeneratorOtp("hello", "nhocdl.poro1@gmail.com", 12, serect)
		//fmt.Println(otp.HashOTP)
		//fmt.Println(otp.PureOTP)

		//utils.EncryptAESMailLink("nhocdl.poro2@gmail.com", serect, w)
		preUserData := &models.PreusersMongo{
			Username:        "thewind121212",
			Email:           "nhocdl.poro1@gmail.com",
			PhoneNumber:     "0918327132",
			HashPassword:    "it ok now ",
			CreatedDate:     time.Now(),
			UpdateDate:      time.Now(),
			VerifySentCount: 1,
		}

		_ = preUserData

		//services.WriteOTPInRedis(preUserData, "tranduy linh ", w)

	}

	return nil
}
