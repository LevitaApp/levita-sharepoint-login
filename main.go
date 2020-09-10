package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type EnvelopeRequestLogin struct {
	XMLName xml.Name `xml:"Envelope"`
	Text    string   `xml:",chardata"`
	S       string   `xml:"s,attr"`
	A       string   `xml:"a,attr"`
	U       string   `xml:"u,attr"`
	Header  struct {
		Text   string `xml:",chardata"`
		Action struct {
			Text           string `xml:",chardata"`
			MustUnderstand string `xml:"mustUnderstand,attr"`
		} `xml:"Action"`
		ReplyTo struct {
			Text    string `xml:",chardata"`
			Address string `xml:"Address"`
		} `xml:"ReplyTo"`
		To struct {
			Text           string `xml:",chardata"`
			MustUnderstand string `xml:"mustUnderstand,attr"`
		} `xml:"To"`
		Security struct {
			Text           string `xml:",chardata"`
			O              string `xml:"o,attr"`
			MustUnderstand string `xml:"mustUnderstand,attr"`
			UsernameToken  struct {
				Text     string `xml:",chardata"`
				Username string `xml:"Username"`
				Password string `xml:"Password"`
			} `xml:"UsernameToken"`
		} `xml:"Security"`
	} `xml:"Header"`
	Body struct {
		Text                 string `xml:",chardata"`
		RequestSecurityToken struct {
			Text      string `xml:",chardata"`
			T         string `xml:"t,attr"`
			AppliesTo struct {
				Text              string `xml:",chardata"`
				Wsp               string `xml:"wsp,attr"`
				EndpointReference struct {
					Text    string `xml:",chardata"`
					Address string `xml:"Address"`
				} `xml:"EndpointReference"`
			} `xml:"AppliesTo"`
			KeyType     string `xml:"KeyType"`
			RequestType string `xml:"RequestType"`
			TokenType   string `xml:"TokenType"`
		} `xml:"RequestSecurityToken"`
	} `xml:"Body"`
}

type EnvelopeResponseLogin struct {
	XMLName xml.Name `xml:"Envelope"`
	Text    string   `xml:",chardata"`
	Wsa     string   `xml:"wsa,attr"`
	Wsse    string   `xml:"wsse,attr"`
	Wsu     string   `xml:"wsu,attr"`
	Wsp     string   `xml:"wsp,attr"`
	Wst     string   `xml:"wst,attr"`
	S       string   `xml:"S,attr"`
	Header  struct {
		Text   string `xml:",chardata"`
		Action struct {
			Text           string `xml:",chardata"`
			MustUnderstand string `xml:"mustUnderstand,attr"`
			ID             string `xml:"Id,attr"`
		} `xml:"Action"`
		To struct {
			Text           string `xml:",chardata"`
			MustUnderstand string `xml:"mustUnderstand,attr"`
			ID             string `xml:"Id,attr"`
		} `xml:"To"`
		Security struct {
			Text           string `xml:",chardata"`
			MustUnderstand string `xml:"mustUnderstand,attr"`
			Timestamp      struct {
				Text    string `xml:",chardata"`
				Wsu     string `xml:"wsu,attr"`
				ID      string `xml:"Id,attr"`
				Created string `xml:"Created"`
				Expires string `xml:"Expires"`
			} `xml:"Timestamp"`
		} `xml:"Security"`
	} `xml:"Header"`
	Body struct {
		Text                         string `xml:",chardata"`
		S                            string `xml:"S,attr"`
		RequestSecurityTokenResponse struct {
			Text      string `xml:",chardata"`
			Wsu       string `xml:"wsu,attr"`
			Wsp       string `xml:"wsp,attr"`
			Wst       string `xml:"wst,attr"`
			TokenType string `xml:"TokenType"`
			AppliesTo struct {
				Text              string `xml:",chardata"`
				EndpointReference struct {
					Text    string `xml:",chardata"`
					Wsa     string `xml:"wsa,attr"`
					Address string `xml:"Address"`
				} `xml:"EndpointReference"`
			} `xml:"AppliesTo"`
			Lifetime struct {
				Text    string `xml:",chardata"`
				Created string `xml:"Created"`
				Expires string `xml:"Expires"`
			} `xml:"Lifetime"`
			RequestedSecurityToken struct {
				Text                string `xml:",chardata"`
				BinarySecurityToken struct {
					Text string `xml:",chardata"`
					Wsse string `xml:"wsse,attr"`
					ID   string `xml:"Id,attr"`
				} `xml:"BinarySecurityToken"`
			} `xml:"RequestedSecurityToken"`
			RequestedAttachedReference struct {
				Text                   string `xml:",chardata"`
				SecurityTokenReference struct {
					Text      string `xml:",chardata"`
					Wsse      string `xml:"wsse,attr"`
					Reference struct {
						Text string `xml:",chardata"`
						URI  string `xml:"URI,attr"`
					} `xml:"Reference"`
				} `xml:"SecurityTokenReference"`
			} `xml:"RequestedAttachedReference"`
			RequestedUnattachedReference struct {
				Text                   string `xml:",chardata"`
				SecurityTokenReference struct {
					Text      string `xml:",chardata"`
					Wsse      string `xml:"wsse,attr"`
					Reference struct {
						Text string `xml:",chardata"`
						URI  string `xml:"URI,attr"`
					} `xml:"Reference"`
				} `xml:"SecurityTokenReference"`
			} `xml:"RequestedUnattachedReference"`
		} `xml:"RequestSecurityTokenResponse"`
	} `xml:"Body"`
}

func GetCookie(email, password, domain string) string {

	getEmailInfo(email)
	secret := login(email, password, domain)
	cookie := getCookieForDomain(secret, domain)

	return cookie

}

func main() {
	fmt.Println("OK")
}

func getEmailInfo(email string) {

	emailEncoded := url.QueryEscape(email)
	// Generated by curl-to-Go: https://mholt.github.io/curl-to-go

	body := strings.NewReader(`login=` + emailEncoded)
	req, err := http.NewRequest("POST", "https://login.microsoftonline.com/GetUserRealm.srf", body)
	if err != nil {
		// handle err
		panic(err)
	}
	req.Host = "login.microsoftonline.com"
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", "close")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
		// handle err
	}
	defer resp.Body.Close()

}

func login(email, password, domain string) string {

	// Generated by curl-to-Go: https://mholt.github.io/curl-to-go

	body := strings.NewReader(`
		<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
			<s:Header>
				<a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
				<a:ReplyTo>
					<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
				</a:ReplyTo>
				<a:To s:mustUnderstand="1">https://login.microsoftonline.com/extSTS.srf</a:To>
				<o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
					<o:UsernameToken>
						<o:Username>` + email + `</o:Username>
						<o:Password>` + password + `</o:Password>
					</o:UsernameToken>
				</o:Security>
			</s:Header>
			<s:Body>
				<t:RequestSecurityToken xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">
					<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
						<a:EndpointReference>
							<a:Address>https://` + domain + `/_forms/default.aspx?wa=wsignin1.0</a:Address>
						</a:EndpointReference>
					</wsp:AppliesTo>
					<t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
					<t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
					<t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>
				</t:RequestSecurityToken>
			</s:Body>
		</s:Envelope>
	`)
	req, err := http.NewRequest("POST", "https://login.microsoftonline.com/extSTS.srf", body)
	if err != nil {
		// handle err
	}
	req.Host = "login.microsoftonline.com"
	req.Header.Set("Connection", "close")
	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// handle err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	envelopeResponseLogin := new(EnvelopeResponseLogin)
	xml.Unmarshal(bodyBytes, envelopeResponseLogin)

	// fmt.Println("XML")
	// xmlBytes, err := xml.MarshalIndent(envelopeResponseLogin, "", " ")
	// fmt.Println(envelopeResponseLogin.Body.RequestSecurityTokenResponse.RequestedSecurityToken.BinarySecurityToken.Text)
	// fmt.Println(string(xmlBytes), err)

	// fmt.Println("Status")
	// fmt.Println(resp.Status)

	return envelopeResponseLogin.Body.RequestSecurityTokenResponse.RequestedSecurityToken.BinarySecurityToken.Text
}

func getCookieForDomain(secret, domain string) string {

	body := strings.NewReader(secret)
	contentLength := strconv.Itoa(len(secret))
	req, err := http.NewRequest("POST", "https://"+domain+"/_forms/default.aspx?wa=wsignin1.0", body)
	if err != nil {
		fmt.Println(err)
		return ""
		// handle err
	}
	req.Host = domain
	req.Header.Set("Connection", "close")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)")
	req.Header.Set("Content-Length", contentLength)

	client := http.DefaultClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Do(req)
	if err != nil {
		// handle err
		fmt.Println(err)
		return ""
	}
	defer resp.Body.Close()

	cookies := []string{}
	for _, cookie := range resp.Cookies() {
		if cookie.Value != "" {
			cookies = append(cookies, cookie.Name+"="+cookie.Value)
		}
	}

	endCookie := strings.Join(cookies, "; ")

	return endCookie

}
