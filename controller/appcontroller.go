package controller

import (
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

func AppInitialize() {
	headersOk := handlers.AllowedHeaders([]string{"Accept", "Authorization", "Content-Type", "Origin"})
	originsOk := handlers.AllowedOrigins([]string{
		"http://127.0.0.1:8000", // port Flutter web allowed
	})
	methodsOk := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})

	router := mux.NewRouter()
	router.HandleFunc("/masuk", Login).Methods(http.MethodPost)
	router.HandleFunc("/verifycaptcha", VerifyCaptcha).Methods(http.MethodPost)

	userroute := router.PathPrefix("/users").Subrouter()
	userroute.Use(JwtMiddleware)
	userroute.HandleFunc("", GetUsers).Methods(http.MethodGet)
	userroute.HandleFunc("/beforeadd", BeforeAddUser).Methods(http.MethodGet)
	userroute.HandleFunc("/add", AddUser).Methods(http.MethodPost)
	userroute.HandleFunc("/view/{userid}", ViewUser).Methods(http.MethodGet)
	userroute.HandleFunc("/edit/{userid}", EditUser).Methods(http.MethodPut)
	userroute.HandleFunc("/editonly/{userid}", EditUserOnly).Methods(http.MethodPatch)
	userroute.HandleFunc("/changepassword/{userid}", ChangePassword).Methods(http.MethodPatch)
	userroute.HandleFunc("", DeleteUser).Methods(http.MethodDelete)

	instanceroute := router.PathPrefix("/instances").Subrouter()
	instanceroute.Use(JwtMiddleware)
	instanceroute.HandleFunc("", GetInstances).Methods(http.MethodGet)
	instanceroute.HandleFunc("/view/{instanceid}", ViewInstance).Methods(http.MethodGet)
	instanceroute.HandleFunc("/add", AddInstance).Methods(http.MethodPost)
	instanceroute.HandleFunc("/edit/{instanceid}", EditInstance).Methods(http.MethodPut)
	instanceroute.HandleFunc("", DeleteInstance).Methods(http.MethodDelete)

	roleroute := router.PathPrefix("/roles").Subrouter()
	roleroute.Use(JwtMiddleware)
	roleroute.HandleFunc("", GetRoles).Methods(http.MethodGet)
	roleroute.HandleFunc("/add", AddRole).Methods(http.MethodPost)
	roleroute.HandleFunc("/edit/{roleid}", EditRole).Methods(http.MethodPatch)
	roleroute.HandleFunc("", DeleteRole).Methods(http.MethodDelete)

	http.ListenAndServe(
		"127.0.0.1:8081",
		handlers.CORS(headersOk, originsOk, methodsOk)(router),
	)
}
