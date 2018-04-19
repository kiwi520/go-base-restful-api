package main

import (
	"net/http"
	"github.com/gorilla/mux"
	"encoding/json"
	"log"
)

//简单声明俩结构
type Person struct {
	Id string `json:"id,omitempty"`
	FirstName string `json:"firstname,omitempty"`
	LastName string `json:"lastname,omitempty"`
	Address *Address `json:",omitempty"`
}

type Address struct {
	Province string `json:",omitemty"`
	City string `json:",omitempty"`
	County string `json:"county,omitempty"`
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

	people = append(people,Person{Id:"1",FirstName:"Liu",LastName:"ming",Address:&Address{Province:"shandong",City:"jinan",County:"lixia"}})
	people = append(people,Person{Id:"2",FirstName:"Li",LastName:"kui",Address:&Address{Province:"shandong",City:"liaocheng",County:"dongchang"}})

	router.HandleFunc("/people",getPeople).Methods("GET")
	router.HandleFunc("/people/{id}",getPerson).Methods("GET")
	router.HandleFunc("/people/{id}",postPerson).Methods("POST")
	router.HandleFunc("/people/{id}",deletePerson).Methods("DELETE")

	if err :=http.ListenAndServe(":8888",router); err !=nil{
		log.Fatal(err.Error())
	}

}
