package main

import (
	"net/http"
	"github.com/gorilla/mux"
	"encoding/json"
	"log"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/dgrijalva/jwt-go"
	"fmt"
	"strings"
	"time"
	//"github.com/codegangsta/negroni"
	"restful/authentication"
)

const SecretKey  = "welcome to wangshubo's blog"

//简单声明俩结构
type Person struct {
	Id string `json:"id,omitempty"`
	FirstName string `json:"firstname,omitempty"`
	LastName string `json:"lastname,omitempty"`
	Address *Address `json:",omitempty"`
}

type Address struct {
	Province string `json:",omitempty"`
	City string `json:",omitempty"`
	County string `json:"county,omitempty"`
}

type UserCredentials struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	Id int `json:"id"`
	Name string `json:"name"`
	UserName string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Data string `json:"data"`
}

type Token struct {
	Token []byte `json:"token"`
}


//初始化Person
var people []Person


//获取单条数据
func getPerson(w http.ResponseWriter, r *http.Request){
	params := mux.Vars(r)

	for _,v := range people{
		if v.Id == params["id"] {
			json.NewEncoder(w).Encode(v)
			return
		}
	}

	//json.NewEncoder(w).Encode(people)
}

//获取全部数据
func getPeople(w http.ResponseWriter,r *http.Request){
	json.NewEncoder(w).Encode(people)
}

//添加一条数据
func postPerson(w http.ResponseWriter, r *http.Request){
	params := mux.Vars(r)
	var person Person
	_ =json.NewDecoder(r.Body).Decode(&person)
	person.Id = params["id"]
	people = append(people,person)
	json.NewEncoder(w).Encode(people)
}


//删除一条数据
func deletePerson(w http.ResponseWriter,r *http.Request)  {
	params := mux.Vars(r)
	for k,v :=range people{
		if v.Id == params["id"] {
			people = append(people[:k],people[k+1:]...)
			break
		}
	}
	json.NewEncoder(w).Encode(people)
}
func main() {



	router := mux.NewRouter()

	//people = append(people,Person{Id:"1",FirstName:"Liu",LastName:"ming",Address:&Address{Province:"shandong",City:"jinan",County:"lixia"}})
	//people = append(people,Person{Id:"2",FirstName:"Li",LastName:"kui",Address:&Address{Province:"shandong",City:"liaocheng",County:"dongchang"}})

	//router.HandleFunc("/people",getPeople).Methods("GET")
	//router.HandleFunc("/people/{id}",getPerson).Methods("GET")
	//router.HandleFunc("/people/{id}",postPerson).Methods("POST")
	//router.HandleFunc("/people/{id}",deletePerson).Methods("DELETE")

	//router.HandleFunc("/login",PostLogin).Methods("POST")
	//
	//router.Handle("/resource",
	//	negroni.New(
	//		negroni.HandlerFunc(func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	//
	//			token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor,
	//				func(token *jwt.Token) (interface{}, error) {
	//					return []byte(SecretKey), nil
	//				})
	//			if err == nil {
	//				if token.Valid {
	//					next(w, r)
	//				} else {
	//					w.WriteHeader(http.StatusUnauthorized)
	//					fmt.Fprint(w, "Token is not valid")
	//				}
	//			} else {
	//				//fmt.Println(err.Error())
	//				w.WriteHeader(http.StatusUnauthorized)
	//				fmt.Fprint(w, "Unauthorized access to this resource")
	//			}
	//		}),
	//		negroni.Wrap(http.HandlerFunc(ProtectedHandler)),
	//	))
	router.HandleFunc("/login",authentication.Login).Methods("POST")
	router.HandleFunc("/validate",authentication.VailidateToken).Methods("GET")
	router.Use(simpleMw)

	log.Println("Now listening...")
	if err :=http.ListenAndServe(":8888",router); err !=nil{
		log.Fatal(err.Error())
	}
}

func simpleMw(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ss()
		fmt.Println(r.Body)
		fmt.Println(r.Header.Get("keep-alive"))
		// Do stuff here
		// Call the next handler, which can be another middleware in the chain, or the final handler.
		w.Header().Set("X-We-Modified-This", "Yup")
		next.ServeHTTP(w, r)
	})
}

func ss()  {
	fmt.Println("sssss")
}

func PostLogin(w http.ResponseWriter, r *http.Request)  {
	var user UserCredentials

	err := json.NewDecoder(r.Body).Decode(&user)

	if err !=nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w,"Error in request")
		return
	}

	if strings.ToLower(user.UserName) != "admin888" || strings.ToLower(user.Password) != "secret"{
		w.WriteHeader(http.StatusForbidden)
		fmt.Println("Error logging in")
		fmt.Fprint(w,"Invalid credentials")
		return
	}

	token :=jwt.New(jwt.SigningMethodHS256)
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour*time.Duration(1)).Unix()
	claims["iat"] = time.Now().Unix()
	token.Claims =claims

    tokenString,err := token.SignedString([]byte(SecretKey))

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error extracting the key")
		if err != nil {
			log.Fatal(err)
		}
	}

	response := Token{[]byte(tokenString)}
	JsonResponse(response,w)
}


func ProtectedHandler(w http.ResponseWriter, r *http.Request) {

	response := Response{"Gained access to protected resource"}
	JsonResponse(response, w)

}

func JsonResponse(response interface{}, w http.ResponseWriter) {

	jsons,err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsons)
}

func middlewares(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor,
			func(token *jwt.Token) (interface{}, error) {
				return []byte(SecretKey), nil
			})

		if err == nil {
			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, "Token is not valid")
			}
		} else {
			//fmt.Println(err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Unauthorized access to this resource")
		}

	})
}

func ValidateTokenMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {


	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SecretKey), nil
		})

	if err == nil {
		if token.Valid {
			next(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Token is not valid")
		}
	} else {
		fmt.Println(err.Error())
		//w.WriteHeader(http.StatusUnauthorized)
		//fmt.Fprint(w, "Unauthorized access to this resource")
	}

}
