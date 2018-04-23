package authentication

import (
	"crypto/rsa"
	"io/ioutil"
	"log"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"restful/models"
	"time"
	"net/http"
	"fmt"
	"errors"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"encoding/json"
	"golang.org/x/crypto/scrypt"
	"encoding/hex"
	"strings"
)

var privateKey  *rsa.PrivateKey
var publicKey *rsa.PublicKey



func init()  {
	privateBytes ,err := ioutil.ReadFile("./rsa_private_linux.rsa")
	//privateBytes ,err := ioutil.ReadFile("./private.rsa")

	if err != nil{
		log.Fatal("读取 私钥 失败")
	}

	publicBytes ,err := ioutil.ReadFile("./rsa_public_linux.rsa.pub")
	//publicBytes ,err := ioutil.ReadFile("./public.rsa.pub")

	if err != nil{
		log.Fatal("读取 公钥 失败")
	}

	privateKey , err = jwt.ParseRSAPrivateKeyFromPEM(privateBytes)

	if err != nil{
		log.Fatal("生成私钥key 失败")
	}

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicBytes)
	if err != nil{
		log.Fatal("生成公钥key 失败")
	}

}

func GenerateJWT(user models.User) (string,error){
	claims := models.Claim{
		User:user,
		StandardClaims:jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour*1).Unix(),
			Issuer:"User token",
		},
	}

	token:= jwt.NewWithClaims(jwt.SigningMethodRS256,claims)

	res,err := token.SignedString(privateKey)

	if err != nil{
		log.Fatal("获取不到token")
	}

	return res,nil
}

func Login(w http.ResponseWriter, r *http.Request){


	Session, err := mgo.Dial("localhost:27017")
	if err != nil {
		panic(err.Error())
	}
	defer Session.Close()
	mgUser := Session.DB("test").C("users")


	var user models.User
	errs := json.NewDecoder(r.Body).Decode(&user)
	//
	if errs != nil{
		fmt.Fprint(w,"参数错误")
		return
	}

	result := models.User{}
	err = mgUser.Find(bson.M{"name": user.Name}).One(&result)
	if err != nil {
		log.Fatal(err)
	}


	//把api获取过来的passwd数据进行加密
	dk,err:= scrypt.Key([]byte(user.Password), []byte("mongodb-golang"), 16384, 8, 1, 32)

	if err != nil {
		panic(err.Error())
	}

	userPassword := hex.EncodeToString(dk)
	if strings.ToLower(user.Name) =="admin888" && result.Password ==userPassword {
		user.Password =""
		user.Role ="admin"

		token,err := GenerateJWT(user)

		if err != nil {
			fmt.Fprint(w,"获取token失败")
			return
		}

		jsonResult,err :=json.Marshal(token)

		if err != nil {
			fmt.Fprint(w,"获取token失败")
			return
		}
		if err :=Session.DB("test").C("tokens").Insert(bson.M{"username":user.Name,"token":token}); err == nil{
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type","application/json")
			w.Write(jsonResult)
		}else{
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("token 存取失败"))
		}


	}else{
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w,"用户名或密码 错误")
	}
}


func VailidateToken(w http.ResponseWriter, r *http.Request){
	token ,err :=request.ParseFromRequest(r,request.OAuth2Extractor,func(token *jwt.Token)(interface{},error){
		return publicKey,nil
	},request.WithClaims(&models.Claim{}))
	
	if err != nil{
		switch err.(type) {
		case *jwt.ValidationError:
			vErr := err.(*jwt.ValidationError)
			switch vErr.Errors {
			case jwt.ValidationErrorExpired:
				w.Header().Add("If-None-Match", `W/"wyzzy"`)
				w.WriteHeader(http.StatusExpectationFailed)

				fmt.Fprintln(w,"token 过期失效")
				return
			case jwt.ValidationErrorSignatureInvalid:
				fmt.Fprintln(w,"签名验证失败")
				return
			default:
				fmt.Fprintln(w,"token 校验错误")
				return
			}
		default:
			fmt.Println("wqeq")
			fmt.Fprintln(w,"token 校验错误")
			return
		}
	}

	if token.Valid{
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(w,"token验证通过")
	}else{
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w,"token 验证失败，没有权限访问资源")
	}

}

func RefreshToken(tokenString string) (string, error) {
	jwt.TimeFunc = func() time.Time {
		return time.Unix(0, 0)
	}
	token, err := jwt.ParseWithClaims(tokenString, &models.Claim{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	//res,err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(*models.Claim); ok && token.Valid {
		jwt.TimeFunc = time.Now
		claims.StandardClaims.ExpiresAt = time.Now().Add(1 * time.Hour).Unix()
		token:= jwt.NewWithClaims(jwt.SigningMethodRS256,claims)

		res,err := token.SignedString(privateKey)

		if err != nil{
			log.Fatal("获取不到token")
		}

		return res,nil
	}
	return "", errors.New("Couldn't handle this token:")
}