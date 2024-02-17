package rest_api

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"linhdevtran99/rest-api/models"
	"linhdevtran99/rest-api/rest-api/routes"
	"linhdevtran99/rest-api/utils"
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
	headersOk := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type"})
	originsOk := handlers.AllowedOrigins([]string{"https://app.wliafdew.dev", "http://localhost:4200"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})
	if err := http.ListenAndServe(s.listenAddr, handlers.CORS(originsOk, headersOk, methodsOk)(router)); err != nil {
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

	if r.Method == http.MethodPost {
		var linkVerifyInfo models.LinkVerify

		_ = json.NewDecoder(r.Body).Decode(&linkVerifyInfo)

		utils.DecryptAESMailLink(&linkVerifyInfo, w)
		fmt.Println("hello")
	}

	return nil
}
