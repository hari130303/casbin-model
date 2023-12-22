package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	pgadapter "github.com/casbin/casbin-pg-adapter"
	"github.com/casbin/casbin/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-pg/pg/v10"
	_ "github.com/lib/pq"
)

// User represents a user in the system
type User struct {
	Username string `json:"username"`
}

// PostgreSQL database connection parameters
const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "12345"
	dbname   = "casbin"
)

var db *sql.DB
var enforcer *casbin.Enforcer // Global enforcer variable
func initDB() {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		panic(err)
	}

	fmt.Println("Connected to PostgreSQL database")

	opts, _ := pg.ParseURL(fmt.Sprintf("postgresql://%s:%s@%s:%d/%s?sslmode=disable", user, password, host, port, dbname))
	if err != nil {
		panic(err)
	}
	db := pg.Connect(opts)
	defer db.Close()

	a, _ := pgadapter.NewAdapterByDB(db, pgadapter.WithTableName("casbin_rule"))

	enforcer, err = casbin.NewEnforcer("casbin/model/model.conf", a)
	if err != nil {
		fmt.Println("Error initializing Casbin enforcer:", err)
		panic(err)
	}

	// Load the policy from DB.
	enforcer.LoadPolicy()
}

func CasbinMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var user User

		// Parse JSON from the request body
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Get user role from the database
		userRole := getUserRoleFromRequest(user.Username)

		path := r.URL.Path
		method := r.Method
		// Check if the user is authorized
		authorized, err := enforcer.Enforce(userRole, path, method)

		if err != nil {
			http.Error(w, "Error checking authorization", http.StatusInternalServerError)
			return
		}

		if authorized {
			next.ServeHTTP(w, r) // User is authorized; continue the request.
		} else {
			http.Error(w, "Forbidden", http.StatusForbidden) // User is not authorized.
		}
	})
}

func main() {
	// Initialize the PostgreSQL database connection and Casbin enforcer
	initDB()

	r := chi.NewRouter()

	// Serve static files (CSS, JS, etc.)
	FileServer(r, "/static", http.Dir("static"))

	// Define routes
	r.With(CasbinMiddleware).Post("/content", contentHandler)

	// Start the server
	http.ListenAndServe(":9999", r)
}

// contentHandler handles the content page
func contentHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "templates/content.html")
	fmt.Println("casbin worked")
}

// getUserRoleFromRequest retrieves the user role from the database based on the username
func getUserRoleFromRequest(username string) string {
	var role string
	row := db.QueryRow("SELECT role_name FROM users WHERE name = $1", username)
	err := row.Scan(&role)
	if err != nil {
		// Handle the error, e.g., return a default role or an empty string
		fmt.Println("Error retrieving user role:", err)
		role = "user" // Set a default role or handle the error as needed
	}
	return role
}

// FileServer conveniently sets up an http.FileServer handler to serve static files.
func FileServer(r chi.Router, path string, root http.FileSystem) {
	r.Get(path, http.StripPrefix(path, http.FileServer(root)).ServeHTTP)
}
