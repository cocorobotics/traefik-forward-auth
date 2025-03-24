package tfa

import (
	"html/template"
	"net/http"
	"net/url"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/thomseddon/traefik-forward-auth/internal/provider"
	muxhttp "github.com/traefik/traefik/v2/pkg/muxer/http"
)

// Server contains muxer and handler methods
type Server struct {
	muxer *muxhttp.Muxer
	unauthorizedTemplate string
	serverErrorTemplate  string
}

// NewServer creates a new server object and builds muxer
func NewServer() *Server {
	s := &Server{
		unauthorizedTemplate: "../templates/unauthorized.html",
		serverErrorTemplate:  "../templates/server_error.html",
	}
	s.buildRoutes()
	return s
}

func (s *Server) buildRoutes() {
	var err error
	s.muxer, err = muxhttp.NewMuxer()
	if err != nil {
		log.Fatal(err)
	}

	// Let's build a muxer
	for name, rule := range config.Rules {
		matchRule := rule.formattedRule()
		if rule.Action == "allow" {
			_ = s.muxer.AddRoute(matchRule, 1, s.AllowHandler(name))
		} else {
			_ = s.muxer.AddRoute(matchRule, 1, s.AuthHandler(rule.Provider, name))
		}
	}

	// Add callback handler
	s.muxer.Handle(config.Path, s.AuthCallbackHandler())

	// Add logout handler
	s.muxer.Handle(config.Path+"/logout", s.LogoutHandler())

	// Add a default handler
	if config.DefaultAction == "allow" {
		s.muxer.NewRoute().Handler(s.AllowHandler("default"))
	} else {
		s.muxer.NewRoute().Handler(s.AuthHandler(config.DefaultProvider, "default"))
	}
}

// RootHandler Overwrites the request method, host and URL with those from the
// forwarded request so it's correctly routed by mux
func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Modify request
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")

	// Read URI from header if we're acting as forward auth middleware
	if _, ok := r.Header["X-Forwarded-Uri"]; ok {
		r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))
	}

	// Pass to mux
	s.muxer.ServeHTTP(w, r)
}

// AllowHandler Allows requests
func (s *Server) AllowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, "Allow", rule, "Allowing request")
		w.WriteHeader(200)
	}
}

// AuthHandler Authenticates requests
func (s *Server) AuthHandler(providerName, rule string) http.HandlerFunc {
	p, _ := config.GetConfiguredProvider(providerName)

	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "Auth", rule, "Authenticating request")

		// Get auth cookie
		c, err := r.Cookie(config.CookieName)
		if err != nil {
			s.authRedirect(logger, w, r, p)
			return
		}

		// Validate cookie
		email, err := ValidateCookie(r, c)
		if err != nil {
			if err.Error() == "Cookie has expired" {
				logger.Info("Cookie has expired")
				s.authRedirect(logger, w, r, p)
			} else {
				logger.WithField("error", err).Warn("Invalid cookie")
				s.renderErrorPage(w, 401, s.unauthorizedTemplate, map[string]interface{}{
					"message": "Invalid authentication cookie",
					"error":   err.Error(),
				})
			}
			return
		}

		// Validate user
		valid := ValidateEmail(email, rule)
		if !valid {
			logger.WithField("email", email).Warn("Invalid email")
			s.renderErrorPage(w, 401, s.unauthorizedTemplate, map[string]interface{}{
				"message": "Invalid email address",
				"email":   email,
			})
			return
		}

		jwtCookie, err := r.Cookie("forward_auth_jwt")
		if err != nil {
			if err.Error() == "Cookie has expired" {
				logger.Info("Cookie has expired")
				s.authRedirect(logger, w, r, p)
			} else {
				logger.WithField("error", err).Warn("Invalid JWT")
				s.renderErrorPage(w, 401, s.unauthorizedTemplate, map[string]interface{}{
					"message": "Invalid JWT",
				})
			}
			return
		}
		claims, err := ValidateToken(jwtCookie.Value)
		if err != nil {
			logger.WithField("claims", claims).Debug("Claims")
			logger.WithField("err", err).Debug("Error")
			s.renderErrorPage(w, 500, s.serverErrorTemplate, map[string]interface{}{
				"message": "An internal server error occurred",
			})
			return
		}
		rolesClaim, ok := claims["https://cocodelivery.com/schemas/identity/claims/roles"]
		if !ok {
			logger.WithField("rolesClaim", rolesClaim).Warn("Roles claims not found")
			s.renderErrorPage(w, 403, s.unauthorizedTemplate, map[string]interface{}{
				"message": "Roles claims not found",
			})
			return
		}

		roles, ok := rolesClaim.([]interface{})
		if !ok {
			logger.WithField("rolesClaim", rolesClaim).Warn("Roles claim is not in the expected format")
			s.renderErrorPage(w, 403, s.unauthorizedTemplate, map[string]interface{}{
				"message": "Roles claim is not in the expected format",
			})
			return
		}

		var roleList []string
		for _, role := range roles {
			if roleStr, ok := role.(string); ok {
				roleList = append(roleList, roleStr)
			}
		}
		logger.WithField("roleList", roleList).Debug("Role list")
		if !HasRequiredRole(roleList) {
			s.renderErrorPage(w, 403, s.unauthorizedTemplate, map[string]interface{}{
				"message": "You don't have the required role to access this resource",
				"roles":   roleList,
			})
			return
		}

		// Valid request
		logger.Debug("Allowing valid request")
		w.Header().Set("X-Forwarded-User", email)
		w.WriteHeader(200)
	}
}

// AuthCallbackHandler Handles auth callback request
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "AuthCallback", "default", "Handling callback")

		// Check state
		state := r.URL.Query().Get("state")
		if err := ValidateState(state); err != nil {
			logger.WithFields(logrus.Fields{
				"error": err,
			}).Warn("Error validating state")
			s.renderErrorPage(w, 401, s.unauthorizedTemplate, map[string]interface{}{
				"message": "Invalid state parameter",
				"error":   err.Error(),
			})
			return
		}

		// Check for CSRF cookie
		c, err := FindCSRFCookie(r, state)
		if err != nil {
			logger.Info("Missing csrf cookie")
			s.renderErrorPage(w, 401, s.unauthorizedTemplate, map[string]interface{}{
				"message": "Missing CSRF cookie",
			})
			return
		}

		// Validate CSRF cookie against state
		valid, providerName, redirect, err := ValidateCSRFCookie(c, state)
		if !valid {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
			}).Warn("Error validating csrf cookie")
			s.renderErrorPage(w, 401, s.unauthorizedTemplate, map[string]interface{}{
				"message": "Invalid CSRF cookie",
				"error":   err.Error(),
			})
			return
		}

		// Get provider
		p, err := config.GetConfiguredProvider(providerName)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
				"provider":    providerName,
			}).Warn("Invalid provider in csrf cookie")
			s.renderErrorPage(w, 401, s.unauthorizedTemplate, map[string]interface{}{
				"message": "Invalid authentication provider",
				"error":   err.Error(),
			})
			return
		}

		// Clear CSRF cookie
		http.SetCookie(w, ClearCSRFCookie(r, c))

		// Exchange code for token
		token, err := p.ExchangeCode(redirectUri(r), r.URL.Query().Get("code"))
		if err != nil {
			logger.WithField("error", err).Error("Code exchange failed with provider")
			s.renderErrorPage(w, 503, s.serverErrorTemplate, map[string]interface{}{
				"message": "Failed to authenticate with provider",
				"error":   err.Error(),
			})
			return
		}

		// Get user
		user, err := p.GetUser(token)
		if err != nil {
			logger.WithField("error", err).Error("Error getting user")
			s.renderErrorPage(w, 503, s.serverErrorTemplate, map[string]interface{}{
				"message": "Failed to get user information",
				"error":   err.Error(),
			})
			return
		}

		// Generate cookie
		http.SetCookie(w, MakeCookie(r, user.Email))
		logger.WithFields(logrus.Fields{
			"provider": providerName,
			"redirect": redirect,
			"user":     user.Email,
		}).Info("Successfully generated auth cookie, redirecting user.")

		http.SetCookie(w, MakeJWTCookie(r, token))

		logger.WithField("token", token).Debug("Token")
		// Redirect
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

// LogoutHandler logs a user out
func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Clear cookie
		http.SetCookie(w, ClearCookie(r))

		logger := s.logger(r, "Logout", "default", "Handling logout")
		logger.Info("Logged out user")

		if config.LogoutRedirect != "" {
			http.Redirect(w, r, config.LogoutRedirect, http.StatusTemporaryRedirect)
		} else {
			s.renderErrorPage(w, 401, s.unauthorizedTemplate, map[string]interface{}{
				"message": "You have been logged out",
			})
		}
	}
}

func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, p provider.Provider) {
	// Error indicates no cookie, generate nonce
	err, nonce := Nonce()
	if err != nil {
		logger.WithField("error", err).Error("Error generating nonce")
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Set the CSRF cookie
	csrf := MakeCSRFCookie(r, nonce)
	http.SetCookie(w, csrf)

	if !config.InsecureCookie && r.Header.Get("X-Forwarded-Proto") != "https" {
		logger.Warn("You are using \"secure\" cookies for a request that was not " +
			"received via https. You should either redirect to https or pass the " +
			"\"insecure-cookie\" config option to permit cookies via http.")
	}

	// Forward them on
	loginURL := p.GetLoginURL(redirectUri(r), MakeState(r, p, nonce))
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)

	logger.WithFields(logrus.Fields{
		"csrf_cookie": csrf,
		"login_url":   loginURL,
	}).Debug("Set CSRF cookie and redirected to provider login url")
}

func (s *Server) logger(r *http.Request, handler, rule, msg string) *logrus.Entry {
	// Create logger
	logger := log.WithFields(logrus.Fields{
		"handler":   handler,
		"rule":      rule,
		"method":    r.Header.Get("X-Forwarded-Method"),
		"proto":     r.Header.Get("X-Forwarded-Proto"),
		"host":      r.Header.Get("X-Forwarded-Host"),
		"uri":       r.Header.Get("X-Forwarded-Uri"),
		"source_ip": r.Header.Get("X-Forwarded-For"),
	})

	// Log request
	logger.WithFields(logrus.Fields{
		"cookies": r.Cookies(),
	}).Debug(msg)

	return logger
}

func (s *Server) renderErrorPage(w http.ResponseWriter, status int, templatePath string, data map[string]interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	
	// Read and render template
	content, err := os.ReadFile(templatePath)
	if err != nil {
		// Fallback to plain text if template fails
		http.Error(w, "Not authorized", status)
		return
	}
	
	tmpl, err := template.New("error").Parse(string(content))
	if err != nil {
		http.Error(w, "Not authorized", status)
		return
	}
	
	tmpl.Execute(w, data)
}
