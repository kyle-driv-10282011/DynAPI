package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
	"io/ioutil"
	"net/url"
	"strconv"

	"go.reizu.org/servemux"
	"github.com/Jeffail/gabs"

	"github.com/bdwilliams/go-jsonify/jsonify"
	_ "github.com/lib/pq"
)






//$$$$$$$$$$$$$$$$$$$$$$$$$$$
//https://mholt.github.io/json-to-go/
//STRUCTS
//$$$$$$$$$$$$$$$$$$$$$$$$$$$
	type structjson []struct {
		URLPath					string  `json:"URL_path"`
		SQLGETKeyField			string	`json:"SQL_GET_key_field"`
		SQLGETQuery				string  `json:"SQL_GET_query"`
		SQLPOSTTable			string	`json:"SQL_POST_table"`
		SQLDELETETable			string	`json:"SQL_DELETE_table"`
		POSTFields				[]string `json:"POST_fields"`
		DELETEFields			[]string `json:"DELETE_fields"`
	}
	type structdbconnection struct {
		Driver        string `json:"Driver"`
		User          string `json:"User"`
		Pass          string `json:"Pass"`
		DatabaseName  string `json:"DatabaseName"`
		ServerIP      string `json:"ServerIP"`
		ServerPort    string `json:"ServerPort"`
		ServerTimeout bool   `json:"ServerTimeout"`
	}
//$$$$$$$$$$$$$$$$$$$$$$$$$$$
// END STRUCTS
//$$$$$$$$$$$$$$$$$$$$$$$$$$$

//LoadPGDBConfiguration function
func LoadDBConfiguration(file string) structdbconnection {
	var config structdbconnection
    configFile, err := os.Open(file)
    defer configFile.Close()
	checkerr(err)
    jsonParser := json.NewDecoder(configFile)
    jsonParser.Decode(&config)
	//Check if DB is up
	hostName := config.ServerIP
	portNum := config.ServerPort
	seconds := 5
	timeOut := time.Duration(seconds) * time.Second
  	_, err2 := net.DialTimeout("tcp", hostName+":"+portNum, timeOut)
	//don't proceed if it isn't  
	if err2 != nil {
	   config.ServerTimeout = true
	   log.Println("PG DB("+config.ServerIP+") is down!")
	   return config
	}
    return config
}

//defalt error function
func checkerr(e error) {
	if e != nil {
		pc := make([]uintptr, 15)
		n := runtime.Callers(2, pc)
		frames := runtime.CallersFrames(pc[:n])
		frame, _ := frames.Next()
		log.Println(frame.File, frame.Line, frame.Function)
		panic(e)
	}
}


//----
 	//https://www.restapitutorial.com/lessons/httpmethods.html
//----

//POST function
// The POST verb is most-often utilized to **create** new resources. In particular, it's used to create subordinate resources. That is, subordinate to some other (e.g. parent) resource. In other words, when creating a new resource, POST to the parent and the service takes care of associating the new resource with the parent, assigning an ID (new resource URI), etc.
// On successful creation, return HTTP status 201, returning a Location header with a link to the newly-created resource with the 201 HTTP status.
// POST is neither safe nor idempotent. It is therefore recommended for non-idempotent resource requests. Making two identical POST requests will most-likely result in two resources containing the same information.
func POSTFunction(POSTFields []string, SQLPOSTTable string, RequestData []byte)(ID int, ExitStatus bool, Message string){
	//Parse Request Data
	//https://github.com/Jeffail/gabs
	jsonParsed, err := gabs.ParseJSON(RequestData)
	checkerr(err)
	//Create Field and Data variables for SQL statement
	SQLFields := ""
	SQLData := ""
	exit := false
	//Loop through the post fields and find correlating post data, put into appropriate variables
	for _, field := range POSTFields{
		if fmt.Sprint(jsonParsed.Search(field)) != "{}"{
			SQLFields += fmt.Sprint("," + field)
			SQLData += fmt.Sprint(strings.ReplaceAll(fmt.Sprint(",",jsonParsed.Search(field)),"\"","'"))
		}else{
			//missing field input
			Message = "Missing POST Input "+field
			exit = true
		}
	}
	//if data verification passed
	if !exit{
		//Trim leading comma from lists
		SQLFields = strings.TrimLeft(SQLFields, ",")
		SQLData = strings.TrimLeft(SQLData, ",") 
		//convert double quotes to single quotes
		strings.ReplaceAll(SQLData,"\"","'")

		//concatenate sql statement
		SQLQuery := fmt.Sprint("INSERT INTO ",SQLPOSTTable,"(",SQLFields,")VALUES(",SQLData,") RETURNING id;")
		log.Println(SQLQuery)
		//Connect to db using config file
		dbconfig := LoadDBConfiguration("db.json")
		con, err := sql.Open(dbconfig.Driver, "host="+dbconfig.ServerIP+" port="+dbconfig.ServerPort+" user="+dbconfig.User+" password="+dbconfig.Pass+" dbname="+dbconfig.DatabaseName+" sslmode=disable")
		checkerr(err)

		var id int
		err = con.QueryRow(SQLQuery).Scan(&id)
		
		defer con.Close()
		return id, false, ""
	}else{
		return 0, true, Message
	}
}
//GET function
// The HTTP GET method is used to **read** (or retrieve) a representation of a resource. In the “happy” (or non-error) path, GET returns a representation in XML or JSON and an HTTP response code of 200 (OK). In an error case, it most often returns a 404 (NOT FOUND) or 400 (BAD REQUEST).
// According to the design of the HTTP specification, GET (along with HEAD) requests are used only to read data and not change it. Therefore, when used this way, they are considered safe. That is, they can be called without risk of data modification or corruption—calling it once has the same effect as calling it 10 times, or none at all. Additionally, GET (and HEAD) is idempotent, which means that making multiple identical requests ends up having the same result as a single request.
// Do not expose unsafe operations via GET—it should never modify any resources on the server.
func GETFunction(SQLQuery string)string{
	//Connect to db using config file
	dbconfig := LoadDBConfiguration("db.json")
	con, err := sql.Open(dbconfig.Driver, "host="+dbconfig.ServerIP+" port="+dbconfig.ServerPort+" user="+dbconfig.User+" password="+dbconfig.Pass+" dbname="+dbconfig.DatabaseName+" sslmode=disable")
	checkerr(err)

	//run query
	rows, err := con.Query(SQLQuery)
	checkerr(err)

	defer rows.Close()
	defer con.Close()
	//jsonify the data and return
	return fmt.Sprint(jsonify.Jsonify(rows))
}

//DELETE function
// DELETE is pretty easy to understand. It is used to **delete** a resource identified by a URI.
// On successful deletion, return HTTP status 200 (OK) along with a response body, perhaps the representation of the deleted item (often demands too much bandwidth), or a wrapped response (see Return Values below). Either that or return HTTP status 204 (NO CONTENT) with no response body. In other words, a 204 status with no body, or the JSEND-style response and HTTP status 200 are the recommended responses.
// HTTP-spec-wise, DELETE operations are idempotent. If you DELETE a resource, it's removed. Repeatedly calling DELETE on that resource ends up the same: the resource is gone. If calling DELETE say, decrements a counter (within the resource), the DELETE call is no longer idempotent. As mentioned previously, usage statistics and measurements may be updated while still considering the service idempotent as long as no resource data is changed. Using POST for non-idempotent resource requests is recommended.
//There is a caveat about DELETE idempotence, however. Calling DELETE on a resource a second time will often return a 404 (NOT FOUND) since it was already removed and therefore is no longer findable. This, by some opinions, makes DELETE operations no longer idempotent, however, the end-state of the resource is the same. Returning a 404 is acceptable and communicates accurately the status of the call.
func DELETEFunction(DELETEFields []string, SQLDELETETable string, ID int, RequestData []byte)(ExitStatus bool, Message string){
	exit := false
	//Create Field and Data variables for SQL statement
	SQLData := ""
	//ID should take priority over RequestData, if supplied
	if ID == 0{	
		//Parse Request Data
		//https://github.com/Jeffail/gabs
		jsonParsed, err := gabs.ParseJSON(RequestData)
		checkerr(err)


		//Loop through the post fields and find correlating post data, put into appropriate variables
		for _, field := range DELETEFields{
			if fmt.Sprint(jsonParsed.Search(field)) != "{}"{
				SQLData += fmt.Sprint(" AND ",field," = ",jsonParsed.Search(field))
			}else{
				//missing field input
				Message = "Missing DELETE Input "+field
				exit = true
			}
		}
	}else{
		intID := strconv.Itoa(ID)
		SQLData = "ID = "+ intID
	}

	if !exit{
		//Trim leading comma from lists
		SQLData = strings.TrimLeft(SQLData, " AND ") 
		//concatenate sql statement
		SQLQuery := fmt.Sprint("DELETE FROM ",SQLDELETETable," WHERE ",SQLData,";")
		log.Println(SQLQuery)
		//Connect to db using config file
		dbconfig := LoadDBConfiguration("db.json")
		con, err := sql.Open(dbconfig.Driver, "host="+dbconfig.ServerIP+" port="+dbconfig.ServerPort+" user="+dbconfig.User+" password="+dbconfig.Pass+" dbname="+dbconfig.DatabaseName+" sslmode=disable")
		checkerr(err)
		insForm, err := con.Prepare(SQLQuery)
		checkerr(err)
		insForm.Exec()
		defer insForm.Close()
		defer con.Close()
		return exit, "{\"status\":\"Success\"}"
	}else{
		return exit, Message
	}
}


func ROUTERfunction(w http.ResponseWriter, r *http.Request) {
	//Set Access control headers to wide open, Yikes!
	w.Header().Set("Access-Control-Allow-Origin","*")
	w.Header().Set("Access-Control-Allow-Methods","*")
	w.Header().Set("Access-Control-Allow-Headers","*")
	var configs structjson
	file := "api-routing-config.json"
	configFile, err := os.Open(file)
	checkerr(err)
	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&configs)
	defer configFile.Close()


	//Read body of request
	bodyBytes, err := ioutil.ReadAll(r.Body)
	checkerr(err)

	//Parse URL, force to lower case for routing
	u, err := url.Parse(strings.ToLower(r.URL.Path))
	//get each section of URL path
	URLSplit := strings.Split(u.Path, "/")

	//loop through all configs in routing file "api-routing-config"
	for _, config := range configs{
		//Use the first "real" object in the split URL
		//http://domain.com/__<USE THIS PART OF THE URL>__/____/____/____
		if config.URLPath == "/"+URLSplit[1]{
			switch r.Method{
			case "GET":
				SQLQuery := ""
				//If there are more than one "parts" to the URL, use the second as the key field to search
				if len(URLSplit)  > 2{
					SQLQuery = config.SQLGETQuery + " where "+config.SQLGETKeyField + " = "+URLSplit[2]
				}else{
					//otherwise continue to get all 
					SQLQuery = config.SQLGETQuery
				}
				//if orderbydesc is a querystring, order by field provided
				OrderByDesc := r.URL.Query().Get("orderbydesc")
				if OrderByDesc != ""{
					SQLQuery += " ORDER BY "+ OrderByDesc + " DESC"
				}
				//if orderbyasc is a querystring, order by field provided
				OrderByAsc := r.URL.Query().Get("orderbyasc")
				if OrderByAsc != ""{
					SQLQuery += " ORDER BY "+ OrderByAsc + " ASC"
				}
				//log the query
				fmt.Fprintln(w,GETFunction(SQLQuery))
			case "POST":
				//trigger PostFunction
				ID, _, Message := POSTFunction(config.POSTFields, config.SQLPOSTTable, bodyBytes)
				fmt.Fprintln(w,ID, Message)
			case "DELETE":
				//If there are more than one "parts" to the URL, use the second as the key field to delete
				if len(URLSplit)  > 2{
					intID,_ := strconv.Atoi(URLSplit[2])
					_, Message := DELETEFunction(config.DELETEFields, config.SQLDELETETable,intID, bodyBytes)
					fmt.Fprintln(w, Message)
				}else{
					_, Message := DELETEFunction(config.DELETEFields, config.SQLDELETETable,0, bodyBytes)
					fmt.Fprintln(w, Message)
				}
			default:
				fmt.Fprintln(w,"No Proper HTTP method detected.")
			}
		}
	}
}

// Contains tells whether a contains x.
func Contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func main() {
	var configs structjson
	file := "api-routing-config.json"
	configFile, err := os.Open(file)
	checkerr(err)
	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&configs)
	defer configFile.Close()

	//verify there aren't errors in config file
	coll := []string{}
	for _,config := range configs{
		//Check if any duplicates
		if Contains(coll, config.URLPath){
			log.Println("Duplicate entry \""+config.URLPath+"\" found.")
		}else{
			coll = append(coll, config.URLPath)
		}
		//make sure that if SQLGETQuery is populated, so is SQLGETKeyField
		if config.SQLGETQuery != "" && config.SQLGETKeyField == ""{
			log.Println(config.URLPath + " is missing SQLGETKeyField.")
		}
		//make sure that if POSTFields is populated, so is SQLPOSTTable
		if len(config.POSTFields) != 0 && config.SQLPOSTTable == ""{
			log.Println(config.URLPath + " is missing SQLPOSTTable.")
		}
		//make sure that if SQLPOSTTable is populated, so is POSTFields
		if config.SQLPOSTTable != "" && len(config.POSTFields) == 0{
			log.Println(config.URLPath + " is missing POSTFields.")
		}
		//make sure that if DELETEFields is populated, so is SQLDELETETable
		if len(config.DELETEFields) != 0 && config.SQLDELETETable == ""{
			log.Println(config.URLPath + " is missing SQLDELETETable.")
		}
		//make sure that if SQLDELETETable is populated, so is DELETEFields
		if config.SQLDELETETable != "" && len(config.DELETEFields) == 0{
			log.Println(config.URLPath + " is missing DELETEFields.")
		}
	}

	mux := servemux.New()
	mux.HandleFunc("/*", ROUTERfunction)


	//Start Webserver
		//r.RunTLS(":8444", "Excludes/letsencrypt/cert.pem", "Excludes/letsencrypt/privkey.pem")
		log.Fatal(http.ListenAndServe(":8444", mux))

}