package request

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/markuta/go-security-txt/parser"
)

func handleRequest(domain string) (r []byte, statusCode int, err error) {

	url := []string{
		"https://" + domain + securityTXTAlt,
		"https://" + domain + securityTXTAlt2,
		"https://" + domain + securityTXTAlt3,
		"https://" + domain + securityTXTAlt4,
		"https://" + domain + securityTXTAlt5,
		"https://" + domain + securityTXTAlt6,
		"https://" + domain + securityTXTAlt7,
		"https://" + domain + securityTXTAlt8,
		"https://" + domain + securityTXTAlt9,
		"https://" + domain + securityTXTAlt10,
		"https://" + domain + securityTXTAlt11,
		"https://" + domain + securityTXTAlt12,
		"https://" + domain + securityTXTAlt13,
		"https://" + domain + securityTXTAlt14,
		"https://" + domain + securityTXTAlt15,
		"https://" + domain + securityTXTAlt16,
		"https://" + domain + securityTXTAlt17,
		"https://" + domain + securityTXTAlt18,
		"https://" + domain + securityTXTAlt19,
		"https://" + domain + securityTXTAlt20,
		"https://" + domain + securityTXTAlt21,
		"https://" + domain + securityTXTAlt22,
		"https://" + domain + securityTXTAlt23,
		"https://" + domain + securityTXTAlt24,
		"https://" + domain + securityTXTAlt25,
		"https://" + domain + securityTXTAlt26,
		"https://" + domain + securityTXTAlt27,
		"https://" + domain + securityTXTAlt28,
		"https://" + domain + securityTXTAlt29,
		"https://" + domain + securityTXTAlt30,
	}

	req, _ := http.NewRequest("GET", url[0], nil)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")
	//if err != nil {
	//	return nil, "", fmt.Errorf("HTTP request failed: %s", err.Error())
	//}

	//ctx, cancel := context.WithTimeout(context.Background(), HTTPtimeoutSecs*time.Second)
	//defer cancel()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout: 10 * time.Second,
				//KeepAlive: 30 * time.Second,
			}).Dial,
			// Avoid: "x509: certificate signed by unknown authority"
			TLSClientConfig: &tls.Config{
				//InsecureSkipVerify: true,
			},
			ForceAttemptHTTP2: true,
			IdleConnTimeout:   2 * time.Second,
		},
	}

	//req = req.WithContext(ctx)
	res, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("HTTP response error: %s", err)
	}
	// Close handle
	defer res.Body.Close()

	// Try with alternative PATH
	if res.StatusCode == 404 || res.StatusCode == 403 {
		req, _ = http.NewRequest("GET", url[1], nil)
		res, err = client.Do(req)
		if err != nil {
			return nil, 0, fmt.Errorf("HTTP response error: %s", err)
		}
		// Close handle
		defer res.Body.Close()
	}

	// Accept HTTP 2xx responses with content type text/plain
	if !isHTTPResponseValid(res.StatusCode) {
		return nil, res.StatusCode, fmt.Errorf("%s %s%d", res.Request.URL, HTTPError, res.StatusCode)
	} else if !(strings.HasPrefix(res.Header.Get("Content-type"), "text/plain")) {
		return nil, res.StatusCode, fmt.Errorf("Content-type (%s) is not valid", res.Header.Get("Content-type"))
	}

	// Fetch response body
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("Cannot read response body: %s", err)
	}

	return data, res.StatusCode, nil
}

// Process performs the calls to request functions
func Process(d string) (*parser.Domain, error) {

	domain := parser.Domain{Name: d}

	body, status, err := handleRequest(d)
	domain.StatusCode = strconv.Itoa(status)

	if err != nil {
		return &domain, err
	}

	domain.IsFileFound = true

	// Check body size
	if len(body) < 5 {
		return &domain, fmt.Errorf("File is empty")
	}

	// Parse and extract data from security.txt
	// Store within the Domain.Result struct
	secTxtPtr := parser.ParseSecTXT(body)
	domain.Result = *secTxtPtr

	if !checkAllFieldsEmpty(domain) {
		domain.IsFieldFound = true
	}

	return &domain, nil
}

// A really ugly way to check if struct is empty
func checkAllFieldsEmpty(domain parser.Domain) bool {
	return domain.Result.Acknowledgments == "" && domain.Result.Contact == nil && domain.Result.Encryption == "" &&
		domain.Result.Expires == "" && domain.Result.Hiring == "" && domain.Result.Policy == "" &&
		domain.Result.PreferredLanguages == nil
}

// checkHTTPResponse()
func isHTTPResponseValid(statusCode int) bool {
	return statusCode >= statusOK && statusCode <= statusIMUsed
}
