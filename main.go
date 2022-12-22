package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/open-policy-agent/opa/rego"
	"log"
	"net/http"
	"strings"
)

var malformedToken = errors.New("unauthorized: malformed token")
var notAllowed = errors.New("unauthorized: denied by policy")

type OpaResponse struct {
	Result bool `json:"result"`
}

func loggingMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Println(r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}

func evaluateOpaViaHttp(user string) bool {
	postBody, _ := json.Marshal(map[string]map[string]string{
		"input": {
			"user": user,
		},
	})
	resp, err := http.Post("http://localhost:8181/v1/data/example/authz/allow", "application/json", bytes.NewBuffer(postBody))
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()

	var oResp OpaResponse

	if err := json.NewDecoder(resp.Body).Decode(&oResp); err != nil {
		log.Fatalln(err)
	}

	return oResp.Result
}

func evaluateOpaViaApi(user string) bool {
	// TODO:  How would we get this from OPA or another external source?
	module := `
		package example.authz
		import future.keywords.if
		
		default allow := false
		
		allow if {
			input.user = "john"
		}`

	ctx := context.Background()
	query, err := rego.New(
		rego.Query("data.example.authz.allow"),
		rego.Module("example.rego", module),
	).PrepareForEval(ctx)

	if err != nil {
		log.Fatalln(err)
	}

	input := map[string]interface{}{"user": user}

	results, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		log.Fatalln(err)
	}

	return results.Allowed()
}

func opaMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
			if len(authHeader) != 2 || len(authHeader[1]) == 0 {
				http.Error(w, malformedToken.Error(), http.StatusUnauthorized)
				return
			}
			//log.Println(authHeader[1])
			if evaluateOpaViaApi(authHeader[1]) != true {
				log.Println("Denied access to:", authHeader[1])
				http.Error(w, notAllowed.Error(), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func foo(w http.ResponseWriter, r *http.Request) {
	log.Println("Executing: foo")
	fmt.Fprintln(w, "foo")
}

func bar(w http.ResponseWriter, r *http.Request) {
	log.Println("Executing: bar")
	fmt.Fprintln(w, "bar")
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/foo", foo).Methods("GET")
	router.HandleFunc("/bar", bar).Methods("GET")

	router.Use(loggingMiddleware(), opaMiddleware())

	log.Println("Ready")
	err := http.ListenAndServe(":8080", router)
	if err != nil {
		log.Fatalln("There's an error with the server, ", err)
	}
}
