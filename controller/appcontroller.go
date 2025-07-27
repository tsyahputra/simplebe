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
	router.HandleFunc("/verify-captcha", VerifyCaptcha).Methods(http.MethodPost)
	router.HandleFunc("/verify-2fa-reset", Verify2FAResetPassword).Methods(http.MethodPost)
	router.HandleFunc("/reset-password", ResetPassword).Methods(http.MethodPost)

	userroute := router.PathPrefix("/users").Subrouter()
	userroute.Use(JwtMiddlewareValidateAccessToken)
	userroute.HandleFunc("", GetUsers).Methods(http.MethodGet)
	userroute.HandleFunc("/before-add", BeforeAddUser).Methods(http.MethodGet)
	userroute.HandleFunc("/add", AddUser).Methods(http.MethodPost)
	userroute.HandleFunc("/view/{userid}", ViewUser).Methods(http.MethodGet)
	userroute.HandleFunc("/edit/{userid}", EditUser).Methods(http.MethodPut)
	userroute.HandleFunc("/edit-only/{userid}", EditUserOnly).Methods(http.MethodPatch)
	userroute.HandleFunc("/change-password/{userid}", ChangePassword).Methods(http.MethodPatch)
	userroute.HandleFunc("", DeleteUser).Methods(http.MethodDelete)
	userroute.HandleFunc("/generate-secret", Generate2FASecretHandler).Methods(http.MethodGet)
	userroute.HandleFunc("/verify-enable", VerifyAndEnable2FAHandler).Methods(http.MethodPost)
	userroute.HandleFunc("/disable-2fa/{userid}", Disable2FAHandler).Methods(http.MethodGet)

	refroute := router.PathPrefix("/refresh-token").Subrouter()
	refroute.Use(JwtMiddlewareValidateRefreshToken)
	refroute.HandleFunc("", RefreshJWT).Methods(http.MethodGet)

	instanceroute := router.PathPrefix("/instances").Subrouter()
	instanceroute.Use(JwtMiddlewareValidateAccessToken)
	instanceroute.HandleFunc("", GetInstances).Methods(http.MethodGet)
	instanceroute.HandleFunc("/view/{instanceid}", ViewInstance).Methods(http.MethodGet)
	instanceroute.HandleFunc("/add", AddInstance).Methods(http.MethodPost)
	instanceroute.HandleFunc("/edit/{instanceid}", EditInstance).Methods(http.MethodPut)
	instanceroute.HandleFunc("", DeleteInstance).Methods(http.MethodDelete)

	roleroute := router.PathPrefix("/roles").Subrouter()
	roleroute.Use(JwtMiddlewareValidateAccessToken)
	roleroute.HandleFunc("", GetRoles).Methods(http.MethodGet)
	roleroute.HandleFunc("/add", AddRole).Methods(http.MethodPost)
	roleroute.HandleFunc("/edit/{roleid}", EditRole).Methods(http.MethodPatch)
	roleroute.HandleFunc("", DeleteRole).Methods(http.MethodDelete)

	http.ListenAndServe(
		"127.0.0.1:8081",
		handlers.CORS(headersOk, originsOk, methodsOk)(router),
	)
}
