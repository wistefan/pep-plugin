package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/request"
	"github.com/Kong/go-pdk/server"
	log "github.com/sirupsen/logrus"
)

// declarative config
type Config struct {
	AuthorizationEndpointType    string
	AuthorizationEndpointAddress string
	KeyrockAppId                 string
}

// Interface to the http-client
type httpClient interface {
	Get(url string) (*http.Response, error)
	Do(req *http.Request) (*http.Response, error)
}

type keyrockResponse struct {
	// we are only interested in that
	authorization_decision string
}

var authorizationHttpClient httpClient = &http.Client{}

func main() {
	server.StartServer(New, Version, Priority)
}

var Version = "0.0.1"
var Priority = 1

func New() interface{} {
	return &Config{}
}

func (conf Config) Access(kong *pdk.PDK) {
	request := kong.Request
	var desicion = false
	if conf.AuthorizationEndpointType == "Keyrock" {
		desicion = authorizeAtKeyrock(conf, request)
	}
	if !desicion {
		log.Infof("Request %v was not allowed.", request)
		kong.Response.Exit(403, fmt.Sprintf("Request forbidden by authorization service %s.", conf.AuthorizationEndpointType), make(map[string][]string))
	}
	log.Debugf("Request was allowed.")
}

func authorizeAtKeyrock(conf Config, request request.Request) (desicion bool) {

	authzRequest, err := http.NewRequest(http.MethodGet, conf.AuthorizationEndpointAddress, nil)
	// its false until proven otherwise.
	desicion = false
	if err != nil {
		log.Errorf("[Keyrock]Was not able to create authz request to %s. Err: %v", conf.AuthorizationEndpointAddress, err)
		return
	}
	authHeader, err := request.GetHeader("Authorization")
	if err != nil {
		log.Errorf("[Keyrock]No auth header was provided. Err: %v", err)
		return
	}
	authHeader = cleanAuthHeader(authHeader)

	requestMethod, err := request.GetMethod()
	if err != nil {
		log.Errorf("[Keyrock]Was not able to retrieve method from request. Err: %v", err)
		return
	}
	requestPath, err := request.GetPath()
	if err != nil {
		log.Errorf("[Keyrock]Was not able to retrieve path from request. Err: %v", err)
		return
	}

	query := authzRequest.URL.Query()
	query.Add("action", requestMethod)
	query.Add("resource", requestPath)
	query.Add("access-token", authHeader)
	query.Add("app-id", conf.KeyrockAppId)
	authzRequest.URL.RawQuery = query.Encode()

	response, err := authorizationHttpClient.Do(authzRequest)
	if err != nil {
		log.Errorf("[Keyrock]Was not able to call authorization endpoint. Err: %v", err)
		return
	}
	if response.StatusCode != 200 {
		log.Errorf("[Keyrock]Did not receive a successfull response. %v", response)
		return
	}

	var authzResponse keyrockResponse
	err = json.NewDecoder(response.Body).Decode(&authzResponse)
	if err != nil {
		log.Errorf("[Keyrock]Response body was not valid. Err: %v", err)
		return
	}
	if authzResponse.authorization_decision == "Permit" {
		log.Debugf("[Keyrock]Successfully authorized the request.")
		return true
	} else {
		log.Debugf("[Keyrock]Request was not allowed.")
		return
	}
}

func cleanAuthHeader(authHeader string) (cleanedHeader string) {
	cleanedHeader = strings.ReplaceAll("Bearer ", authHeader, "")
	cleanedHeader = strings.ReplaceAll("bearer ", cleanedHeader, "")
	return cleanedHeader
}
