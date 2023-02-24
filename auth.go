package auth

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/wqyjh/openai-auth-go/errorx"
)

const (
	DefaultUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
)

type Authenticator struct {
	proxy     string
	userAgent string
}

type Credential struct {
	SessionToken string  `json:"accessToken"`
	Session      Session `json:"session"`
}

type Option func(*Authenticator)

func WithProxy(proxy string) Option {
	return func(a *Authenticator) {
		a.proxy = proxy
	}
}

func WithUserAgent(ua string) Option {
	return func(a *Authenticator) {
		a.userAgent = ua
	}
}

func NewAuthenticator(opts ...Option) (*Authenticator, error) {
	a := &Authenticator{
		userAgent: DefaultUserAgent,
	}
	for _, o := range opts {
		o(a)
	}

	return a, nil
}

func (a *Authenticator) AuthUser(email, password string) (Credential, error) {
	ua := &userAuth{
		Authenticator: a,
		Email:         email,
		Password:      password,
	}
	return ua.Auth()
}

type userAuth struct {
	*Authenticator
	client     *http.Client
	stateRegex *regexp.Regexp
	Email      string
	Password   string
	err        error
	cred       Credential
}

func noRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

func (a *userAuth) getClient(enableRedirect bool) *http.Client {
	if enableRedirect {
		a.client.CheckRedirect = nil
	} else {
		a.client.CheckRedirect = noRedirect
	}
	return a.client
}

func (a *userAuth) Auth() (Credential, error) {
	var cred = Credential{}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return cred, err
	}
	client := &http.Client{
		Jar: jar,
	}
	if a.proxy != "" {
		proxyUrl, err := url.Parse(a.proxy)
		if err != nil {
			return cred, err
		}
		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
		}
		client.Transport = transport
	}
	a.client = client

	re, err := regexp.Compile(`state=(.*)`)
	if err != nil {
		return cred, err
	}
	a.stateRegex = re

	a.step0Csrf()
	return a.credential()
}

type csrfResponse struct {
	CsrfToken string `json:"csrfToken"`
}

func (a *userAuth) step0Csrf() {
	url := "https://explorer.api.openai.com/api/auth/csrf"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		a.err = err
		return
	}
	req.Header.Set("Host", "explorer.api.openai.com")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Accept-Language", "en-GB,en-US;q=0.9,en;q=0.8")
	req.Header.Set("Referer", "https://explorer.api.openai.com/auth/login")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	response, err := a.performRequest(a.getClient(true), req)
	if err != nil {
		a.err = err
		return
	}
	var csrfResponse csrfResponse
	err = getResponseObject(response, &csrfResponse)
	if err != nil {
		a.err = err
		return
	}

	a.step1Auth0(csrfResponse.CsrfToken)
}

type auth0Response struct {
	Url string `json:"url"`
}

func (a *userAuth) step1Auth0(csrfToken string) {
	if a.err != nil {
		return
	}

	link := "https://explorer.api.openai.com/api/auth/signin/auth0?prompt=login"

	payload := url.Values{}
	payload.Set("callbackUrl", "/chat")
	payload.Set("csrfToken", csrfToken)
	payload.Set("json", "true")

	req, err := http.NewRequest(http.MethodPost, link, strings.NewReader(payload.Encode()))
	if err != nil {
		a.err = err
		return
	}
	req.Header.Set("Host", "explorer.api.openai.com")
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Gpc", "1")
	req.Header.Set("Accept-Language", "en-US,en;q=0.8")
	req.Header.Set("Origin", "https://explorer.api.openai.com")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Referer", "https://explorer.api.openai.com/auth/login")
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	response, err := a.getClient(true).Do(req)
	if err != nil {
		a.err = err
		return
	}

	if response.StatusCode != 302 && response.StatusCode != 200 {
		a.err = bodyError(response)
		return
	}

	log.Printf("code: %d", response.StatusCode)

	var auth0Response auth0Response
	err = getResponseObject(response, &auth0Response)
	if err != nil {
		a.err = err
		return
	}

	if strings.Contains(auth0Response.Url, "error") {
		a.err = errors.Errorf("redirected: %s", auth0Response.Url)
		return
	}

	a.step2GetState(auth0Response.Url)
}

func (a *userAuth) step2GetState(link string) {
	if a.err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		a.err = err
		return
	}
	req.Header.Set("Host", "auth0.openai.com")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Referer", "https://explorer.api.openai.com/")

	response, err := a.getClient(true).Do(req)
	if err != nil {
		a.err = err
		return
	}

	if response.StatusCode != 302 && response.StatusCode != 200 {
		a.err = bodyError(response)
		return
	}

	state, err := a.parseState(response)
	if err != nil {
		a.err = err
		return
	}

	a.step3IdentifyState(state)
}

func (a *userAuth) step3IdentifyState(state string) {
	if a.err != nil {
		return
	}

	link := "https://auth0.openai.com/u/login/identifier?state=" + url.QueryEscape(state)
	req, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		a.err = err
		return
	}

	req.Header.Set("Host", "auth0.openai.com")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Referer", "https://explorer.api.openai.com/")

	_, err = a.performRequest(a.getClient(true), req)
	if err != nil {
		a.err = err
		return
	}

	a.step4GetIdentifyEmail(state)
}

func (a *userAuth) step4GetIdentifyEmail(state string) {
	if a.err != nil {
		return
	}

	link := "https://auth0.openai.com/u/login/identifier?state=" + url.QueryEscape(state)

	payload := url.Values{}
	payload.Set("state", state)
	payload.Set("username", a.Email)
	payload.Set("js-available", "false")
	payload.Set("webauthn-available", "true")
	payload.Set("is-brave", "false")
	payload.Set("webauthn-platform-available", "true")
	payload.Set("action", "default")

	log.Printf("payload: %s", payload.Encode())
	req, err := http.NewRequest(http.MethodPost, link, strings.NewReader(payload.Encode()))
	if err != nil {
		a.err = err
		return
	}

	req.Header.Set("Host", "auth0.openai.com")
	req.Header.Set("Origin", "https://auth0.openai.com")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Referer", link)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := a.getClient(true).Do(req)
	if err != nil {
		a.err = err
		return
	}

	if response.StatusCode != 302 && response.StatusCode != 200 {
		a.err = bodyError(response)
		return
	}

	a.step5Password(state)
}

func (a *userAuth) step5Password(state string) {
	if a.err != nil {
		return
	}

	link := "https://auth0.openai.com/u/login/password?state=" + url.QueryEscape(state)

	payload := url.Values{}
	payload.Set("state", state)
	payload.Set("username", a.Email)
	payload.Set("password", a.Password)
	payload.Set("action", "default")

	req, err := http.NewRequest(http.MethodPost, link, strings.NewReader(payload.Encode()))
	if err != nil {
		a.err = err
		return
	}

	req.Header.Set("Host", "auth0.openai.com")
	req.Header.Set("Origin", "https://auth0.openai.com")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Referer", link)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := a.getClient(false).Do(req)
	if err != nil {
		a.err = err
		return
	}

	if response.StatusCode != 302 && response.StatusCode != 200 {
		a.err = bodyError(response)
		return
	}

	newState, err := a.parseState(response)
	if err != nil {
		a.err = err
		return
	}

	a.step6Resume(state, newState)
}

func (a *userAuth) step6Resume(oldState, newState string) {
	if a.err != nil {
		return
	}

	refer := "https://auth0.openai.com/u/login/password?state=" + url.QueryEscape(oldState)
	link := "https://auth0.openai.com/authorize/resume?state=" + url.QueryEscape(newState)

	req, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		a.err = err
		return
	}

	req.Header.Set("Host", "auth0.openai.com")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Accept-Language", "en-GB,en-US;q=0.9,en;q=0.8")
	req.Header.Set("Referer", refer)

	response, err := a.getClient(false).Do(req)
	if err != nil {
		a.err = err
		return
	}

	if response.StatusCode != 302 {
		a.err = bodyError(response)
		return
	}

	redirectUrl := response.Header.Get("location")

	a.step7Redirect(redirectUrl, link)

}

func (a *userAuth) step7Redirect(redirectUrl, prevUrl string) {
	if a.err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodGet, redirectUrl, nil)
	if err != nil {
		a.err = err
		return
	}

	req.Header.Set("Host", "explorer.api.openai.com")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Accept-Language", "en-GB,en-US;q=0.9,en;q=0.8")
	req.Header.Set("Referer", prevUrl)

	response, err := a.getClient(false).Do(req)
	if err != nil {
		a.err = err
		return
	}

	if response.StatusCode != 302 {
		a.err = bodyError(response)
		return
	}

	for _, c := range response.Cookies() {
		if c.Name == "__Secure-next-auth.session-token" {
			a.cred.SessionToken = c.Value
		}
	}

	if a.cred.SessionToken == "" {
		a.err = errors.New("session token no found")
		return
	}

	a.step8AccessToken()
}

type User struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	Picture string `json:"picture"`
}

type Session struct {
	AccessToken string `json:"accessToken"`
	Expires     string `json:"expires"`
	User        User   `json:"user"`
}

func (a *userAuth) step8AccessToken() {
	if a.err != nil {
		return
	}

	link := "https://explorer.api.openai.com/api/auth/session"

	req, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		a.err = err
		return
	}

	// Set the cookie in the request
	cookie := &http.Cookie{Name: "__Secure-next-auth.session-token", Value: a.cred.SessionToken}
	req.AddCookie(cookie)

	response, err := a.performRequest(a.getClient(false), req)
	if err != nil {
		a.err = err
		return
	}

	err = getResponseObject(response, &a.cred.Session)
	if err != nil {
		a.err = err
		return
	}
}

func (a *userAuth) parseState(resp *http.Response) (string, error) {
	s, err := getResponseString(resp)
	if err != nil {
		return "", err
	}

	result := a.stateRegex.FindStringSubmatch(s)
	if len(result) <= 1 {
		return "", errors.Errorf("no match found: %s", s)
	}
	state := result[1]
	state = strings.Split(state, "\"")[0]
	return state, nil
}

func (a *userAuth) credential() (Credential, error) {
	if a.err != nil {
		return Credential{}, a.err
	}
	return a.cred, nil
}

func (a *userAuth) performRequest(client *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if err := checkForSuccess(resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func bodyError(resp *http.Response) error {
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Errorf("failed to read from body: %w", err)
	}
	return errorx.NewCodeError(resp.StatusCode, string(data))
}

// returns an error if this response includes an error.
func checkForSuccess(resp *http.Response) error {
	if resp.StatusCode == 200 {
		return nil
	}
	return bodyError(resp)
}

func getResponseString(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Errorf("failed to read from body: %w", err)
	}
	return string(data), nil
}

func getResponseObject(rsp *http.Response, v interface{}) error {
	defer rsp.Body.Close()
	if err := json.NewDecoder(rsp.Body).Decode(v); err != nil {
		return errors.Errorf("invalid json response: %w", err)
	}
	return nil
}
