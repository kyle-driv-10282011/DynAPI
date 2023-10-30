package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"log"
	"os"
	"runtime"
	"strings"
	"io/ioutil"
	"net/url"
	"strconv"
	// "bytes"
	// "io"
	"time"
	"net"
	"database/sql"
	"math/rand"
	//"crypto-js"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"crypto/sha256"
	"encoding/hex"

	"go.reizu.org/servemux"
	"github.com/Jeffail/gabs"

	_ "github.com/lib/pq"
)






//$$$$$$$$$$$$$$$$$$$$$$$$$$$
//https://mholt.github.io/json-to-go/
//STRUCTS
//$$$$$$$$$$$$$$$$$$$$$$$$$$$
type structjson []struct {
	URLPath         string   `json:"URL_path"`
	SQLGETQuery     string   `json:"SQL_GET_query,omitempty"`
	SQLGETKeyField  string   `json:"SQL_GET_key_field,omitempty"`
	SQLPOSTTable    string   `json:"SQL_POST_table,omitempty"`
	POSTFields      []string `json:"POST_fields,omitempty"`
	SQLDELETETable  string   `json:"SQL_DELETE_table,omitempty"`
	DELETEFields    []string `json:"DELETE_fields,omitempty"`
	SQLGETVariables []string `json:"SQL_GET_Variables,omitempty"`
}
type struct_response_rqlite struct {
	Results []struct {
		Columns []string `json:"columns"`
		Types   []string `json:"types"`
		Values  [][]any  `json:"values"`
	} `json:"results"`
}
type structresponse struct {
	Results []struct {
		LastInsertID int `json:"last_insert_id"`
		RowsAffected int `json:"rows_affected"`
	} `json:"results"`
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
type struct_player struct {
	PlayerName     string `json:"player_name"`
	PlayerPassword string `json:"player_password"`
}
//$$$$$$$$$$$$$$$$$$$$$$$$$$$
// END STRUCTS
//$$$$$$$$$$$$$$$$$$$$$$$$$$$

var conn *sql.DB




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

// LoadDBConfiguration function
func LoadDBConfiguration(file string) structdbconnection {
	var config structdbconnection
	configFile, err := os.Open(file)
	defer configFile.Close()
	checkerr(err)
	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&config)
	// Check if DB is up
	hostName := config.ServerIP
	portNum := config.ServerPort
	seconds := 5
	timeOut := time.Duration(seconds) * time.Second
	_, err2 := net.DialTimeout("tcp", hostName+":"+portNum, timeOut)
	// Don't proceed if it isn't
	if err2 != nil {
		config.ServerTimeout = true
		log.Println("PG DB(" + config.ServerIP + ") is down!")
		return config
	}
	return config
}

func SQLQuery(Query string)string {
	var response struct_response_rqlite


	rows, err := conn.Query(Query)
	checkerr(err)

	var column_arr []string
	columns, _ := rows.Columns()
	for _, column := range columns {
		column_arr = append(column_arr, column)
	}

	var type_arr []string
	types, _ := rows.ColumnTypes()
	for _, column_type := range types {
		type_arr = append(type_arr, column_type.DatabaseTypeName())
	}

	var data_arr [][]interface{}

	count := len(columns)
	for rows.Next() {
		values := make([]interface{}, count)
		valuePtrs := make([]interface{}, count)
		for i := range columns {
			valuePtrs[i] = &values[i]
		}
		err := rows.Scan(valuePtrs...)
		checkerr(err)
		data_arr = append(data_arr, values)
	}

	response.Results = append(response.Results, struct {
		Columns []string        `json:"columns"`
		Types   []string        `json:"types"`
		Values  [][]interface{} `json:"values"`
	}{
		Columns: column_arr,
		Types:   type_arr,
		Values:  data_arr,
	})

	jsonData, err := json.Marshal(response)
	checkerr(err)


	return string(jsonData)
}

func SQLExec(Query string)string{

	type Result struct {
		LastInsertID  int64   `json:"last_insert_id"`
		RowsAffected  int64   `json:"rows_affected"`
		TimeInSeconds float64 `json:"time"`
	}
	type Response struct {
		Results []Result `json:"results"`
		Time    float64  `json:"time"`
	}
		startTime := time.Now()
		result, err := conn.Exec(Query)
		checkerr(err)


		var lastID int64
		var rowsAffected int64
		err = conn.QueryRow("SELECT lastval()").Scan(&lastID)
		if err != nil {
			if strings.Contains(err.Error(), "pq: lastval is not yet defined in this session") {
				lastID = 0
				rowsAffected = 0
			}else{
				rowsAffected, err = result.RowsAffected()
				if err != nil{
					rowsAffected = 0
				}
			}
		}
		
	
		elapsedTime := time.Since(startTime).Seconds()
	
		response := Response{
			Results: []Result{
				{
					LastInsertID:  lastID,
					RowsAffected:  rowsAffected,
					TimeInSeconds: elapsedTime,
				},
			},
			Time: elapsedTime,
		}
		responseJSON, err := json.Marshal(response)
		checkerr(err)
	return string(responseJSON)
	
}

func playerExists(playerName string)bool{
	SQLQ := "select count(*) as count from list_player where player_name = '"+playerName+"'"
	
	var jsonRes struct_response_rqlite
	_ = json.Unmarshal([]byte(SQLQuery(SQLQ)), &jsonRes) // Unmarshalling


	strValue := fmt.Sprintf("%v", jsonRes.Results[0].Values[0][0])

	if (strValue == "0"){
		return false
	}else{
		return true
	}
}

func passwordMatch(playerName string, playerPassword string)bool{
	SQuery := "SELECT count(id) from list_player WHERE player_name = '"+playerName+"' AND player_password = '"+playerPassword+"'"
	var jsonRes struct_response_rqlite
	_ = json.Unmarshal([]byte(SQLQuery(SQuery)), &jsonRes) // Unmarshalling
	strValue := fmt.Sprintf("%v", jsonRes.Results[0].Values[0][0])

	if (strValue == "0"){
		return false
	}else{
		return true
	}
}

func getUnixTime() int64 {
	return time.Now().Unix()
}

func getRandomLetter() string {
	// Seed the random number generator with the current time
	rand.Seed(time.Now().UnixNano())

	// Generate a random alphabet letter (lowercase)
	randomLetter := rune('a' + rand.Intn('z'-'a'+1))

	return string(randomLetter)
}

func createToken() (string) {
	rand.Seed(time.Now().UnixNano())
	// Define the range (inclusive)
	min := 1
	max := 999
	expireMinutes := int64(15)
	// Generate a random number between min and max
	randomNumber := rand.Intn(max-min+1) + min

	//int64
	unixTime := getUnixTime()
	strUnixTime := strconv.FormatInt(unixTime, 10)

	expireTime := unixTime + expireMinutes*60
	strExpireTime := strconv.FormatInt(expireTime,10)

	madeUpNumber := (getUnixTime()*int64(randomNumber) + 1/int64(randomNumber)+5)
	strMadeUpNumber := strconv.FormatInt(madeUpNumber,10)
	madeUpNumber2 := madeUpNumber + int64(randomNumber)
	strMadeUpNumber2 := strconv.FormatInt(madeUpNumber2,10)



	tokenData := map[string]string{
		"token": strUnixTime +getRandomLetter()+ strMadeUpNumber2 + getRandomLetter() + strExpireTime + getRandomLetter() + strMadeUpNumber,
	}

	tokenJSON, err := json.Marshal(tokenData)
	checkerr(err)

	return string(tokenJSON)
}

func encrypt(secretKey []byte, plaintext string){
	// Create the AES cipher block
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		fmt.Println("Error creating cipher block:", err)
		return
	}

	// Create a GCM encrypter
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("Error creating GCM encrypter:", err)
		return
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		fmt.Println("Error generating nonce:", err)
		return
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Encode the encrypted data to base64
	encryptedData := base64.StdEncoding.EncodeToString(append(nonce, ciphertext...))

	fmt.Println("Encrypted data:", encryptedData)
}

func hash(plaintext string)string{

	// Create a new SHA-256 hasher
	hasher := sha256.New()

	// Write the input string to the hasher
	hasher.Write([]byte(plaintext))

	// Get the hash as a byte slice
	hashBytes := hasher.Sum(nil)

	// Convert the hash to a hexadecimal string
	hashHex := hex.EncodeToString(hashBytes)

	// fmt.Println("Input:", inputString)
	// fmt.Println("SHA-256 Hash:", hashHex)
	return hashHex
}

func sessionExists(sessionToken string)bool{
	SQLQ := "select count(id) as count from list_session where session_token = '"+sessionToken+"' AND session_enabled;"
	var jsonRes struct_response_rqlite
	_ = json.Unmarshal([]byte(SQLQuery(SQLQ)), &jsonRes) // Unmarshalling


	strValue := fmt.Sprintf("%v", jsonRes.Results[0].Values[0][0])

	if (strValue == "0"){
		return false
	}else{
		return true
	}
}

func sessionActive(sessionToken string)bool{
	SQLQ := "select count(id) as count from list_session where session_token = '"+sessionToken+"' AND session_enabled AND (select extract(epoch from now())) < session_expire;"
	var jsonRes struct_response_rqlite
	_ = json.Unmarshal([]byte(SQLQuery(SQLQ)), &jsonRes) // Unmarshalling


	strValue := fmt.Sprintf("%v", jsonRes.Results[0].Values[0][0])

	if (strValue == "0"){
		return false
	}else{
		return true
	}
}

func replaceVariablesInQuery(URL string,Query string)string{
	u, _ := url.Parse(URL)
	queryParams := u.Query()
	for key, values := range queryParams {
		Query = strings.Replace(Query, key, values[0], -1)
	}
	return Query
}

func requiredVariablesExist(URL string, variables []string)(funcError bool, message string){

	// Create a URL object
	u, _ := url.Parse(URL)
	queryParams := u.Query()
	varName := ""

	for v := range variables {
		varName = variables[v]
		if len(queryParams[variables[v]]) == 0{
			return false, "Variable \""+varName+"\" is missing in query string."
		}

	}
	return true, ""
}

func isInteger(v interface{}) bool {
    switch v.(type) {
    case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
        return true
    default:
        return false
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
			SQLFields += ","+field
			SQLData += fmt.Sprint(",",jsonParsed.Index(0).Search(field))
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
		SQLData = strings.ReplaceAll(SQLData,"\"","'")
		//concatenate sql statement
		SQLQuery := fmt.Sprint("INSERT INTO ",SQLPOSTTable,"(",SQLFields,")VALUES(",SQLData,");")
		var jsonRes structresponse
		_ = json.Unmarshal([]byte(SQLExec(SQLQuery)), &jsonRes) // Unmarshalling

		return jsonRes.Results[0].LastInsertID, false, ""
	}else{

		return 0, true, Message
	}
}
//GET function
// The HTTP GET method is used to **read** (or retrieve) a representation of a resource. In the “happy” (or non-error) path, GET returns a representation in XML or JSON and an HTTP response code of 200 (OK). In an error case, it most often returns a 404 (NOT FOUND) or 400 (BAD REQUEST).
// According to the design of the HTTP specification, GET (along with HEAD) requests are used only to read data and not change it. Therefore, when used this way, they are considered safe. That is, they can be called without risk of data modification or corruption—calling it once has the same effect as calling it 10 times, or none at all. Additionally, GET (and HEAD) is idempotent, which means that making multiple identical requests ends up having the same result as a single request.
// Do not expose unsafe operations via GET—it should never modify any resources on the server.
func GETFunction(Query string)string{
	return SQLQuery(Query)
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
				SQLData += fmt.Sprint(" AND ",field," = ",jsonParsed.Index(0).Search(field))
			}else{
				//missing field input
				Message = "Missing DELETE Input "+field
				exit = true
			}
		}
	}else{
		//ID is not 0
		intID := strconv.Itoa(ID)
		SQLData = "ID = "+ intID
	}

	if !exit{
		//Trim leading comma from lists
		SQLData = strings.TrimLeft(SQLData, " AND ") 
		//concatenate sql statement
		SQLQuery := fmt.Sprint("DELETE FROM ",SQLDELETETable," WHERE ",SQLData,";")
		log.Println(SQLQuery)
		SQLExec(SQLQuery)

		return exit, "{\"status\":\"Success\"}"
	}else{
		return exit, Message
	}
}

func loginFunction(RequestData []byte)(funcError bool, message string){


	// Parse the JSON
	var players []struct_player
	err := json.Unmarshal(RequestData, &players)
	checkerr(err)

	playerName := strings.ToLower(players[0].PlayerName)
	playerPassword := hash(players[0].PlayerPassword)

	//verify RequestData has all fields populated
	if (playerName == ""){
		return true, "Missing POST Input player_name"
	}
	if (playerPassword == ""){
		return true, "Missing POST Input player_password"
	}

	var sessionLength int64 = 15

	if playerExists(playerName) && passwordMatch(playerName, playerPassword){
		createTokenResponse := createToken()
		type TokenResponse struct {
			Token string `json:"token"`
		}
		
			var tokenResponse TokenResponse
	
			err := json.Unmarshal([]byte(createTokenResponse), &tokenResponse)
			checkerr(err)
		
			sessionToken := tokenResponse.Token
		sessionCreate := strconv.FormatInt(getUnixTime(),10)
		sessionExpire := strconv.FormatInt((getUnixTime() + sessionLength*60),10)
		
		query := "INSERT into list_session (player_id, session_token, session_create, session_enabled, session_expire) VALUES ((select id from list_player where player_name = '"+playerName+"'), '"+sessionToken+"', "+sessionCreate+",true,"+sessionExpire+")"
		SQLExec(query)
		//insert the token value into db, but return JSON with token
		return false, createTokenResponse
	}else{
		return true, "Incorrect player - password combo."
	}
}

func logoutFunction(sessionToken string){
	query := "update list_session SET session_enabled = false where session_token = '"+sessionToken+"'"
	SQLExec(query)
}

func createPlayerFunction(RequestData []byte)(funcError bool, message string){


	// Parse the JSON
	var players []struct_player
	err := json.Unmarshal(RequestData, &players)
	checkerr(err)
	var jsonRes structresponse

	playerName := players[0].PlayerName
	playerPassword := hash(players[0].PlayerPassword)

	//verify RequestData has all fields populated
	if (playerName == ""){
		return true, "Missing POST Input player_name"
	}
	if (playerPassword == ""){
		return true, "Missing POST Input player_password"
	}

	if playerExists(playerName){
		return true, "Duplicate, player_name exists."
	}else{
		_ = json.Unmarshal([]byte(SQLExec("INSERT into list_player (player_name, player_password) VALUES ('"+playerName+"', '"+playerPassword+"')")), &jsonRes) // Unmarshalling
		query := "insert into relation_player_role (player_id, role_id)VALUES((select id from list_player where player_name = '"+playerName+"'),(select id from list_role where role_name = 'everyone'))"
		SQLExec(query)
		return false, strconv.Itoa(jsonRes.Results[0].LastInsertID)
	}
}

func tokenCheckFunction(RequestData []byte)(bool){

	type struct_token struct {
		Token	string `json:"token"`
	}


	if(len(RequestData) == 0){
		return false
	}else{
		// Parse the JSON
		var token []struct_token
		err := json.Unmarshal(RequestData, &token)
		checkerr(err)
		
		return sessionActive(token[0].Token)
	}
}


func advanceDayFunction(RequestData []byte, sessionCookie string)(message string){

	type struct_day struct {
		GameID			int `json:"game_id"`
	}

		// Parse the JSON
		var eData []struct_day
		err := json.Unmarshal(RequestData, &eData)
		checkerr(err)

		//get current day number
		var day_number, game_id int
		game_id = eData[0].GameID
		err = conn.QueryRow("select day_number from list_game_calendar where game_id = $1", game_id).Scan(&day_number)
		if err == sql.ErrNoRows {
			day_number = 0
		}else{
			checkerr(err)
			
		}

		//make sure requestor is owner of game

		// select id from list_game where owner_id = (select player_id from list_session where session_token = 'kyle')
		var searchgame_id int
		err = conn.QueryRow("select id as player_id from list_game where owner_id = (select player_id from list_session where session_token = $1)", sessionCookie).Scan(&searchgame_id)

		if searchgame_id != game_id{
			strGameID := strconv.Itoa(game_id)
			message = "{\"status\":\"Unauthorized, you are not the game owner of game["+strGameID+"]\"}"
			return message
		}
		checkerr(err)

		//get random weather day
		var id, month, day, year int
		var city, country string
		//because the column is numeric, it puts the data into a byte array, stupid I know	
		//this is to retrieve the avg_temp as []byte, to be converted later
		var avg_temperatureBytes []byte
		//this is used as a placeholder for column state, 
		//which as an interface can be used to tell if it is null or not
		var rand_state sql.NullString

		err = conn.QueryRow("select id, month, day, year, city, state as rand_state, country, avg_temperature as avg_temperatureBytes from list_weather where id = (SELECT id FROM list_weather where avg_temperature > -99 ORDER BY RANDOM() LIMIT 1)").Scan(&id, &month, &day, &year, &city, &rand_state, &country, &avg_temperatureBytes)
		checkerr(err)

		//because the column is numeric, it puts the data into a byte array, stupid I know	
		//this is to retrieve the rand_avg_temp as []byte, to be converted later
		var rand_avg_tempBytes []byte

		var state string
		//use the interface to determine if the column state is null
		//if it's not put the value into the state variable
		//likewise, use the state in the query if Valid
		if rand_state.Valid {
			state = rand_state.String
			err = conn.QueryRow("select avg(avg_temperature) as rand_avg_tempBytes from list_weather where month = $1 AND day = $2 AND country = $3 AND city = $4 AND state = $5",month, day, country, city, state).Scan(&rand_avg_tempBytes)
			checkerr(err)
		}else{
			err = conn.QueryRow("select avg(avg_temperature) as rand_avg_tempBytes from list_weather where month = $1 AND day = $2 AND country = $3 AND city = $4",month, day, country, city).Scan(&rand_avg_tempBytes)
			checkerr(err)
		}
		//convert average temperature to float64
		avg_temperatureStr := string(avg_temperatureBytes)
		avg_temperature, err := strconv.ParseFloat(avg_temperatureStr, 64)
		checkerr(err)

		//(-------------------------------------------------)
		//get average of all years for random month/day aka
		//(-------------------------------------------------)	
		//convert rand average temperature to float64
		rand_avg_temperatureStr := string(rand_avg_tempBytes)
		rand_avg_temperature, err := strconv.ParseFloat(rand_avg_temperatureStr, 64)
		checkerr(err)

		//(-------------------------------------------------)
		//calculate economy score
		//(-------------------------------------------------)
		economy_score := avg_temperature - rand_avg_temperature

		//(-------------------------------------------------)
		//calculate day number
		//(-------------------------------------------------)
		new_day_number := day_number + 1

		//(-------------------------------------------------)
		//enter new day into database
		//(-------------------------------------------------)

		insForm, err := conn.Prepare("INSERT INTO list_game_calendar (day_number, economy_score, weather_id, game_id) VALUES ($1,$2,$3,$4)")
		checkerr(err)
		insForm.Exec(new_day_number, economy_score, id, game_id)



		// log.Println(new_day_number, economy_score, id, game_id)
		return "{\"status\":\"Success\"}"

}

func ROUTERfunction(w http.ResponseWriter, r *http.Request) {

	// Read the request body
	bodyBytes, err := ioutil.ReadAll(r.Body)
	checkerr(err)
	
	if len(bodyBytes) > 0 && bodyBytes[0] != '[' {
		bodyBytes = append([]byte{'['}, bodyBytes...)
	}

	if len(bodyBytes) > 0 && bodyBytes[len(bodyBytes)-1] != ']' {
		bodyBytes = append(bodyBytes, ']')
	}

	sessionCookie := r.Header.Get("X-Session-Cookie")
	w.Header().Set("Access-Control-Allow-Origin","*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Session-Cookie")


	if strings.ToLower(r.Method) == "options"{
		fmt.Fprintln(w, "")
	//***UNAUTHENTICATED PATH***Is the URL /login & Is the request a POST
	}else if strings.ToLower(r.URL.Path) == "/login" && strings.ToLower(r.Method) == "post"{
		err, message := loginFunction(bodyBytes)
		if err {
			http.Error(w, message, http.StatusBadRequest)
		}else{
			fmt.Fprintln(w, message)
		}
	//***UNAUTHENTICATED PATH***Is the URL /logout & is the request a POST
	}else if strings.ToLower(r.URL.Path) == "/logout" && strings.ToLower(r.Method) == "post"{
		logoutFunction(sessionCookie)
		fmt.Fprintln(w,  "{\"status\":\"Success\"}")
	//***UNAUTHENTICATED PATH***Is the url /create & is the request a POST
	}else if strings.ToLower(r.URL.Path) == "/create" && strings.ToLower(r.Method) == "post"{
		err, message := createPlayerFunction(bodyBytes)
		if err && message == "Duplicate, player_name exists."{
			http.Error(w, message, http.StatusConflict)
		}else if err {
			http.Error(w, message, http.StatusBadRequest)
		}
		if !err{
			fmt.Fprintln(w, message)
		}
	//***UNAUTHENTICATED PATH***Is the url /tokencheck & is the request a POST
	}else if strings.ToLower(r.URL.Path) == "/tokencheck" && strings.ToLower(r.Method) == "post"{
		status := tokenCheckFunction(bodyBytes)
		statusStr := strconv.FormatBool(status)
		fmt.Fprintln(w, "{\"Status\":\""+statusStr+"\"}")
	//Is the url /advanceday & is the request a POST
	}else if strings.ToLower(r.URL.Path) == "/advanceday" && strings.ToLower(r.Method) == "post" && sessionActive(sessionCookie){
		message := advanceDayFunction(bodyBytes, sessionCookie)
		fmt.Fprintln(w, message)
	//check if value in cookie exists in session table
	//i.e. are they logged in
	}else if sessionActive(sessionCookie){
		var configs structjson
		file := "api-routing-config.json"
		configFile, err := os.Open(file)
		checkerr(err)
		jsonParser := json.NewDecoder(configFile)
		jsonParser.Decode(&configs)
		defer configFile.Close()



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
					cont, message := requiredVariablesExist(r.URL.String(), config.SQLGETVariables)
					if(!cont){
						http.Error(w, message, http.StatusBadRequest)
					}else{
						SQLQuery := ""
						//If there are more than one "parts" to the URL, use the second as the key field to search
						if len(URLSplit)  > 2{
							if(isInteger(URLSplit[2])){
								SQLQuery = config.SQLGETQuery + " where "+config.SQLGETKeyField + " = "+URLSplit[2]
							}else{
								SQLQuery = config.SQLGETQuery + " where "+config.SQLGETKeyField + " = '"+URLSplit[2]+"'"
							}
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
		
						SQLQuery = replaceVariablesInQuery(r.URL.String(), SQLQuery)
	
						//log the query
						fmt.Fprintln(w,GETFunction(SQLQuery))
					}
					

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
	//session doesn't exist or expired
	}else if sessionExists(sessionCookie) && !sessionActive(sessionCookie){
		http.Error(w, "Token Expired", http.StatusForbidden)
	//is the session cookie empty/not there
	}else{
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func main() {
	var configs structjson
	file := "api-routing-config.json"
	configFile, err := os.Open(file)
	checkerr(err)
	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&configs)
	defer configFile.Close()

	DatabaseName := "tycoon"
	// Connect to db using config file
	dbconfig := LoadDBConfiguration("db.json")
	var connerr error
	conn, connerr = sql.Open(dbconfig.Driver, "host="+dbconfig.ServerIP+" port="+dbconfig.ServerPort+" user="+dbconfig.User+" password="+dbconfig.Pass+" dbname="+DatabaseName+" sslmode=disable")
	checkerr(connerr)



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
		log.Println("DynAPI is running!")
		log.Fatal(http.ListenAndServe(":8444", mux))

}