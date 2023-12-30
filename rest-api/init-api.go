package rest_api

import (
	"fmt"
	"github.com/gorilla/mux"
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
		fmt.Println("hello")
	}

	return nil
}
