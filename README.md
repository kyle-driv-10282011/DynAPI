# Dynamic API for relational DB

This is a sleek GO program written to allow all API configs to be held in a json file, and not need code updates to add API routes. In short, it accepts web requests, checks if a path matches and performs the config. 

## Installation

The below "imports" are used.

```
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
```
clone to local and ```go run DynAPI.go```

## Files

* DynAPI.go
* api-routing-config.json
	*JSON Array
        *JSON Object
            * URL_path (STRING)
                * Routing path for API request http://ip:port/<URL_path>
                * Must include \ at beginning
            * SQL_GET_query (STRING)
                * The SQL query used for GET requests
            * SQL_GET_key_field (STRING)
                * The default column for GET queries (order by, where, etc)
            * SQL_POST_table (STRING)
                * The table used for POST requests (INSERT)
            * POST_fields (OBJECT[])
                * Fields required for POST requests to be valid, all fields must be included in request and cannot be optional
            * SQL_DELETE_table (STRING)
                * Table for DELETE requests
            * DELETE_fields (OBJECT[])
                * The default column for DELETE queries


```    
{
    "URL_path": "/thing",
    "SQL_GET_query": "select * from table_thing",
    "SQL_GET_key_field": "ID",
    "SQL_POST_table": "table_thing",
    "POST_fields": ["thing_name","thing_description","thing_size","thing_age"],
    "SQL_DELETE_table": "list_thing",
    "DELETE_fields":["id"]
}
```
        

* db.json




