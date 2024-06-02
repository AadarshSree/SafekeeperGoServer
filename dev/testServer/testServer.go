package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// struct for json
type Response struct {
    Message string `json:"message"`
}

type KeyPair struct {

	KeyValue string `json:"keyValue"`
}

type ClientPublicKey struct {

	Ka string `json:"publicKey"`
}

func routeSafe(w http.ResponseWriter, r *http.Request) {
    // Create a new response object
    response := Response{Message: "Bonjour from Safekeeper server"}

    w.Header().Set("Content-Type", "application/json") //http headers

    json.NewEncoder(w).Encode(response)
}

func routeKey(w http.ResponseWriter, r *http.Request){

	fmt.Println("GET params were:", r.URL.Query())

	value := r.URL.Query().Get("kv")

	valueInt,err := strconv.Atoi(value)

	if(err != nil){
		//handle error
	}


	valueInt = valueInt * 10

	response := KeyPair{KeyValue: "KeyValue * 10 = "+strconv.Itoa(valueInt) }

	w.Header().Set("Content-Type", "application/json") 
    json.NewEncoder(w).Encode(response)

}


func dhke(w http.ResponseWriter, r *http.Request){


	if r.Method != http.MethodPost {
        http.Error(w, "BAD REQUEST 400", http.StatusMethodNotAllowed)
        return
    }

	var clientPubKey ClientPublicKey
	decoder := json.NewDecoder(r.Body)
	fmt.Println(r.Body )
    err := decoder.Decode(&clientPubKey)
    if err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    resp := ClientPublicKey{Ka: clientPubKey.Ka}

	w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)


}

func main() {

	fmt.Println("Safekeeper Server Runing on Port 9021")


    // route handler
    http.HandleFunc("/safe", routeSafe)
    http.HandleFunc("/key", routeKey) // testing only key?kv=123

	//Route to diffie hellman key establishment
    http.HandleFunc("/dhke", dhke)




    // Start the server on port
    http.ListenAndServe(":9021", nil)
}