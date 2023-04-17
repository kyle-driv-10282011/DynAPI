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
		* URL_path
			* Routing path for API request http://ip:port/<URL_path>
* db.json


**
```
[
    {
		##
        "URL_path": "/thing",
		##The SQL query used for GET requests
        "SQL_GET_query": "select * from list_material",
		##The default column for GET queries (order by, where, etc)
        "SQL_GET_key_field": "ID",
		##The table used for POST requests (INSERT)
        "SQL_POST_table": "list_material",
		##Fields required for POST requests to be valid, all fields must be included in request and cannot be optional
        "POST_fields": ["material_name","material_cost","material_currency","material_quantity_type"],
		##Table for DELETE requests
        "SQL_DELETE_table": "list_material",
		##The default column for DELETE queries
        "DELETE_fields":["id"]
    },
    {
		##Example config
        "URL_path": "/thing",
        "SQL_GET_query": "select * from list_currency",
        "SQL_GET_key_field": "ID",
        "SQL_POST_table": "list_currency",
        "POST_fields": ["currency_name","currency_iso","currency_symbol","usd_conversion"],
        "SQL_DELETE_table": "list_currency",
        "DELETE_fields":["id"]
    },
    {
        "URL_path": "/quantitytype",
        "SQL_GET_query": "select * from list_quantity_type",
        "SQL_GET_key_field": "ID",
        "SQL_POST_table": "list_quantity_type",
        "POST_fields": ["type_name"],
        "SQL_DELETE_table": "list_quantity_type",
        "DELETE_fields":["id"]
    },
    {
        "URL_path": "/qualitytype",
        "SQL_GET_query": "select * from list_quality_type",
        "SQL_GET_key_field": "ID",
        "SQL_POST_table": "list_quality_type",
        "POST_fields": ["type_name"],
        "SQL_DELETE_table": "list_quality_type",
        "DELETE_fields":["id"]
    },
    {
        "URL_path": "/product",
        "SQL_GET_query": "select * from list_product",
        "SQL_GET_key_field": "ID",
        "SQL_POST_table": "list_product",
        "POST_fields": ["product_name"],
        "SQL_DELETE_table": "list_product",
        "DELETE_fields":["id"]
    },
    {
        "URL_path": "/businesstitlehierarchy",
        "SQL_GET_query": "select * from list_business_title_hierarchy",
        "SQL_GET_key_field": "ID"
    },
    {
        "URL_path": "/materialfull",
        "SQL_GET_query": "select lm.id,lm.material_name,lm.material_cost,lm.material_cost * lc.usd_conversion as cost_converted, lm.material_currency,lm.material_quantity_type,lc.currency_name,lc.currency_iso,lc.currency_symbol,lc.usd_conversion,lqt.type_name from list_material as lm join list_currency as lc on lm.material_currency = lc.ID join list_quantity_type as lqt on lm.material_quantity_type = lqt.ID",
        "SQL_GET_key_field": "lm.ID"
    }
]


