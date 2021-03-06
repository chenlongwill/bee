// Copyright 2013 bee authors
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package apiapp

import (
	"fmt"
	"os"
	path "path/filepath"
	"strings"

	"github.com/chenlongwill/bee/cmd/commands"
	"github.com/chenlongwill/bee/cmd/commands/version"
	"github.com/chenlongwill/bee/generate"
	beeLogger "github.com/chenlongwill/bee/logger"
	"github.com/chenlongwill/bee/utils"
)

var CmdApiapp = &commands.Command{
	// CustomFlags: true,
	UsageLine: "api [appname]",
	Short:     "Creates a Beego API application",
	Long: `
  The command 'api' creates a Beego API application.

  {{"Example:"|bold}}
      $ bee api [appname] [-tables=""] [-driver=mysql] [-conn=root:@tcp(127.0.0.1:3306)/test]

  If 'conn' argument is empty, the command will generate an example API application. Otherwise the command
  will connect to your database and generate models based on the existing tables.

  The command 'api' creates a folder named [appname] with the following structure:

	    ├── main.go
	    ├── {{"conf"|foldername}}
	    │     └── app.conf
	    ├── {{"controllers"|foldername}}
	    │     └── object.go
	    │     └── user.go
	    ├── {{"routers"|foldername}}
	    │     └── router.go
	    ├── {{"tests"|foldername}}
	    │     └── default_test.go
	    └── {{"models"|foldername}}
	          └── object.go
	          └── user.go
`,
	PreRun: func(cmd *commands.Command, args []string) { version.ShowShortVersionBanner() },
	Run:    createAPI,
}
var apiconf = `appname = {{.Appname}}
runmode = dev
autorender = false
copyrequestbody = true
# 跨域域名
origins = localhost

# API请求超时时间s
ServerTimeOut = 5

# 日志方式配置 file：文件  print：命令行输出
logmode = print
# 日志路径配置
logpath = ~/logs/{{.Appname}}.log

# 是否开启api接口文档
EnableDocs = true

# http服务端口
httpport = 8030

# https服务端口
EnableHTTPS = false
HTTPSPort = 8031
HTTPSCertFile = conf/{{.Appname}}.crt
HTTPSKeyFile = conf/{{.Appname}}.key

# mysql连接池跃连接数
mysql_maxidle = 10
# mysql最大连接数
mysql_maxconn = 100
# mysql数据库连接地址，读写分离
mysql_read = {{.conn}}
mysql_write = {{.conn}}

# redis数据库名
dbname = {{.Appname}}
# redis链接地址
redis = ":6379"
# redis默认数据库
redisdefaultdb = 0
# redis连接池最大空闲数，超时回收
redismaxidle = 20

# session过期时间设定，默认24小时（秒）
session_timeout = 86400
# 短信验证码超时设置5分钟（秒）
vcode_timeout = 300

# 消息推送地址
push_addr = localhost:57172

# 静态文件上传存放地址
static_upload = ~/static
# 静态文件下载访问地址
static_down = http://static.{{.Appname}}.com

# 短信通道配置
vcode_tag = 商城
vcode_key = xxxx
vcode_pwd = xxxx
`
var apiMaingo = `package main

import (
	_ "{{.Appname}}/routers"

	"github.com/astaxie/beego"
)

func main() {
	if beego.BConfig.RunMode == "dev" {
		beego.BConfig.WebConfig.DirectoryIndex = true
		beego.BConfig.WebConfig.StaticDir["/swagger"] = "swagger"
	}
	beego.Run()
}
`

var apiMainconngo = `package main

import (
	"fmt"
	
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
	"github.com/astaxie/beego/orm"
	"github.com/astaxie/beego/plugins/cors"
	"github.com/astaxie/beego/toolbox"
	"github.com/chenlongwill/lib"
	{{.DriverPkg}}

	"{{.Appname}}/controllers"
	_ "{{.Appname}}/routers"
)

var ps = fmt.Sprintf

func main() {
	// 系统化初始化，优先级最高
	LogInit()
	MysqlInit()
	OriginInit()
	SwaggerInit()
	lib.RedisConnect()

	// 时间初始化，包含定时器任务
	controllers.TimeInit()
	controllers.BatchInitSystemParam()

	//批量任务开始执行
	toolbox.StartTask()
	defer toolbox.StopTask()

	beego.Run()
}

// 日志配置
func LogInit() {
	// 日志配置:
	// filename 保存的文件名
	// maxlines 每个文件保存的最大行数，默认值 1000000
	// maxsize 每个文件保存的最大尺寸，默认值是 1 << 28, //256 MB
	// daily 是否按照每天 logrotate，默认是 true
	// maxdays 文件最多保存多少天，默认保存 7 天
	// rotate 是否开启 logrotate，默认是 true
	// level 日志保存的时候的级别，默认是 Trace 级别
	// perm 日志文件权限
	if beego.AppConfig.DefaultString("logmode", "print") == "file" {
		logs.SetLogger(logs.AdapterFile, ps("{\"filename\":\"%s\"}", beego.AppConfig.DefaultString("logpath", "./logs/{{.Appname}}.log")))
	}
	// 输出调用的文件名和文件行号
	logs.EnableFuncCallDepth(true)
	// 异步输出日志
	logs.Async(1e3)
	logs.GetLogger("init").Println("日志配置成功...")
	return
}

// mysql数据库配置
func MysqlInit() {
	err := orm.RegisterDataBase("default", "mysql", beego.AppConfig.String("mysql_read"), beego.AppConfig.DefaultInt("mysql_maxidle", 10), beego.AppConfig.DefaultInt("mysql_maxconn", 50))
	if err != nil {
		panic("mysql数据库mysql_read连接失败")
	}
	err = orm.RegisterDataBase("write", "mysql", beego.AppConfig.String("mysql_write"), beego.AppConfig.DefaultInt("mysql_maxidle", 10), beego.AppConfig.DefaultInt("mysql_maxconn", 50))
	if err != nil {
		panic("mysql数据库mysql_read连接失败")
	}
	logs.GetLogger("init").Println("数据库[%s]连接成功...", beego.AppConfig.String("mysql_vv_core"))
	return
}

// 跨域设置
func OriginInit() {
	beego.InsertFilter("*", beego.BeforeRouter, cors.Allow(&cors.Options{
		AllowOrigins:     beego.AppConfig.DefaultStrings("origins", []string{"*"}),
		AllowMethods:     []string{"POST", "OPTIONS"},
		AllowHeaders:     []string{"X-Requested-With", "accept", "Origin", "content-type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))
	logs.GetLogger("init").Println("跨域配置成功...")
	return
}

// api接口页面
func SwaggerInit() {
	if beego.BConfig.RunMode == "dev" {
		beego.BConfig.WebConfig.DirectoryIndex = true
		beego.BConfig.WebConfig.StaticDir[beego.AppConfig.DefaultString("doc", "/doc")] = "swagger"
		logs.GetLogger("init").Println("开发环境开启自动化API文档成功...")
	}
	return
}

`

var apirouter = `// @APIVersion 1.0.0
// @Title beego Test API
// @Description beego has a very cool tools to autogenerate documents for your API
// @Contact astaxie@gmail.com
// @TermsOfServiceUrl http://beego.me/
// @License Apache 2.0
// @LicenseUrl http://www.apache.org/licenses/LICENSE-2.0.html
package routers

import (
	"{{.Appname}}/controllers"

	"github.com/astaxie/beego"
)

func init() {
	ns := beego.NewNamespace("/v1",
		beego.NSNamespace("/object",
			beego.NSInclude(
				&controllers.ObjectController{},
			),
		),
		beego.NSNamespace("/user",
			beego.NSInclude(
				&controllers.UserController{},
			),
		),
	)
	beego.AddNamespace(ns)
}
`

var APIModels = `package models

import (
	"errors"
	"strconv"
	"time"
)

var (
	Objects map[string]*Object
)

type Object struct {
	ObjectId   string
	Score      int64
	PlayerName string
}

func init() {
	Objects = make(map[string]*Object)
	Objects["hjkhsbnmn123"] = &Object{"hjkhsbnmn123", 100, "astaxie"}
	Objects["mjjkxsxsaa23"] = &Object{"mjjkxsxsaa23", 101, "someone"}
}

func AddOne(object Object) (ObjectId string) {
	object.ObjectId = "astaxie" + strconv.FormatInt(time.Now().UnixNano(), 10)
	Objects[object.ObjectId] = &object
	return object.ObjectId
}

func GetOne(ObjectId string) (object *Object, err error) {
	if v, ok := Objects[ObjectId]; ok {
		return v, nil
	}
	return nil, errors.New("ObjectId Not Exist")
}

func GetAll() map[string]*Object {
	return Objects
}

func Update(ObjectId string, Score int64) (err error) {
	if v, ok := Objects[ObjectId]; ok {
		v.Score = Score
		return nil
	}
	return errors.New("ObjectId Not Exist")
}

func Delete(ObjectId string) {
	delete(Objects, ObjectId)
}

`

var APIModels2 = `package models

import (
	"errors"
	"strconv"
	"time"
)

var (
	UserList map[string]*User
)

func init() {
	UserList = make(map[string]*User)
	u := User{"user_11111", "astaxie", "11111", Profile{"male", 20, "Singapore", "astaxie@gmail.com"}}
	UserList["user_11111"] = &u
}

type User struct {
	Id       string
	Username string
	Password string
	Profile  Profile
}

type Profile struct {
	Gender  string
	Age     int
	Address string
	Email   string
}

func AddUser(u User) string {
	u.Id = "user_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	UserList[u.Id] = &u
	return u.Id
}

func GetUser(uid string) (u *User, err error) {
	if u, ok := UserList[uid]; ok {
		return u, nil
	}
	return nil, errors.New("User not exists")
}

func GetAllUsers() map[string]*User {
	return UserList
}

func UpdateUser(uid string, uu *User) (a *User, err error) {
	if u, ok := UserList[uid]; ok {
		if uu.Username != "" {
			u.Username = uu.Username
		}
		if uu.Password != "" {
			u.Password = uu.Password
		}
		if uu.Profile.Age != 0 {
			u.Profile.Age = uu.Profile.Age
		}
		if uu.Profile.Address != "" {
			u.Profile.Address = uu.Profile.Address
		}
		if uu.Profile.Gender != "" {
			u.Profile.Gender = uu.Profile.Gender
		}
		if uu.Profile.Email != "" {
			u.Profile.Email = uu.Profile.Email
		}
		return u, nil
	}
	return nil, errors.New("User Not Exist")
}

func Login(username, password string) bool {
	for _, u := range UserList {
		if u.Username == username && u.Password == password {
			return true
		}
	}
	return false
}

func DeleteUser(uid string) {
	delete(UserList, uid)
}
`

var apiControllers = `package controllers

import (
	"{{.Appname}}/models"
	"encoding/json"

	"github.com/astaxie/beego"
)

// Operations about object
type ObjectController struct {
	beego.Controller
}

// @Title Create
// @Description create object
// @Param	body		body 	models.Object	true		"The object content"
// @Success 200 {string} models.Object.Id
// @Failure 403 body is empty
// @router / [post]
func (o *ObjectController) Post() {
	var ob models.Object
	json.Unmarshal(o.Ctx.Input.RequestBody, &ob)
	objectid := models.AddOne(ob)
	o.Data["json"] = map[string]string{"ObjectId": objectid}
	o.ServeJSON()
}

// @Title Get
// @Description find object by objectid
// @Param	objectId		path 	string	true		"the objectid you want to get"
// @Success 200 {object} models.Object
// @Failure 403 :objectId is empty
// @router /:objectId [get]
func (o *ObjectController) Get() {
	objectId := o.Ctx.Input.Param(":objectId")
	if objectId != "" {
		ob, err := models.GetOne(objectId)
		if err != nil {
			o.Data["json"] = err.Error()
		} else {
			o.Data["json"] = ob
		}
	}
	o.ServeJSON()
}

// @Title GetAll
// @Description get all objects
// @Success 200 {object} models.Object
// @Failure 403 :objectId is empty
// @router / [get]
func (o *ObjectController) GetAll() {
	obs := models.GetAll()
	o.Data["json"] = obs
	o.ServeJSON()
}

// @Title Update
// @Description update the object
// @Param	objectId		path 	string	true		"The objectid you want to update"
// @Param	body		body 	models.Object	true		"The body"
// @Success 200 {object} models.Object
// @Failure 403 :objectId is empty
// @router /:objectId [put]
func (o *ObjectController) Put() {
	objectId := o.Ctx.Input.Param(":objectId")
	var ob models.Object
	json.Unmarshal(o.Ctx.Input.RequestBody, &ob)

	err := models.Update(objectId, ob.Score)
	if err != nil {
		o.Data["json"] = err.Error()
	} else {
		o.Data["json"] = "update success!"
	}
	o.ServeJSON()
}

// @Title Delete
// @Description delete the object
// @Param	objectId		path 	string	true		"The objectId you want to delete"
// @Success 200 {string} delete success!
// @Failure 403 objectId is empty
// @router /:objectId [delete]
func (o *ObjectController) Delete() {
	objectId := o.Ctx.Input.Param(":objectId")
	models.Delete(objectId)
	o.Data["json"] = "delete success!"
	o.ServeJSON()
}

`
var apiControllers2 = `package controllers

import (
	"{{.Appname}}/models"
	"encoding/json"

	"github.com/astaxie/beego"
)

// Operations about Users
type UserController struct {
	beego.Controller
}

// @Title CreateUser
// @Description create users
// @Param	body		body 	models.User	true		"body for user content"
// @Success 200 {int} models.User.Id
// @Failure 403 body is empty
// @router / [post]
func (u *UserController) Post() {
	var user models.User
	json.Unmarshal(u.Ctx.Input.RequestBody, &user)
	uid := models.AddUser(user)
	u.Data["json"] = map[string]string{"uid": uid}
	u.ServeJSON()
}

// @Title GetAll
// @Description get all Users
// @Success 200 {object} models.User
// @router / [get]
func (u *UserController) GetAll() {
	users := models.GetAllUsers()
	u.Data["json"] = users
	u.ServeJSON()
}

// @Title Get
// @Description get user by uid
// @Param	uid		path 	string	true		"The key for staticblock"
// @Success 200 {object} models.User
// @Failure 403 :uid is empty
// @router /:uid [get]
func (u *UserController) Get() {
	uid := u.GetString(":uid")
	if uid != "" {
		user, err := models.GetUser(uid)
		if err != nil {
			u.Data["json"] = err.Error()
		} else {
			u.Data["json"] = user
		}
	}
	u.ServeJSON()
}

// @Title Update
// @Description update the user
// @Param	uid		path 	string	true		"The uid you want to update"
// @Param	body		body 	models.User	true		"body for user content"
// @Success 200 {object} models.User
// @Failure 403 :uid is not int
// @router /:uid [put]
func (u *UserController) Put() {
	uid := u.GetString(":uid")
	if uid != "" {
		var user models.User
		json.Unmarshal(u.Ctx.Input.RequestBody, &user)
		uu, err := models.UpdateUser(uid, &user)
		if err != nil {
			u.Data["json"] = err.Error()
		} else {
			u.Data["json"] = uu
		}
	}
	u.ServeJSON()
}

// @Title Delete
// @Description delete the user
// @Param	uid		path 	string	true		"The uid you want to delete"
// @Success 200 {string} delete success!
// @Failure 403 uid is empty
// @router /:uid [delete]
func (u *UserController) Delete() {
	uid := u.GetString(":uid")
	models.DeleteUser(uid)
	u.Data["json"] = "delete success!"
	u.ServeJSON()
}

// @Title Login
// @Description Logs user into the system
// @Param	username		query 	string	true		"The username for login"
// @Param	password		query 	string	true		"The password for login"
// @Success 200 {string} login success
// @Failure 403 user not exist
// @router /login [get]
func (u *UserController) Login() {
	username := u.GetString("username")
	password := u.GetString("password")
	if models.Login(username, password) {
		u.Data["json"] = "login success"
	} else {
		u.Data["json"] = "user not exist"
	}
	u.ServeJSON()
}

// @Title logout
// @Description Logs out current logged in user session
// @Success 200 {string} logout success
// @router /logout [get]
func (u *UserController) Logout() {
	u.Data["json"] = "logout success"
	u.ServeJSON()
}

`

var apiTests = `package test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"runtime"
	"path/filepath"
	_ "{{.Appname}}/routers"

	"github.com/astaxie/beego"
	. "github.com/smartystreets/goconvey/convey"
)

func init() {
	_, file, _, _ := runtime.Caller(1)
	apppath, _ := filepath.Abs(filepath.Dir(filepath.Join(file, ".." + string(filepath.Separator))))
	beego.TestBeegoInit(apppath)
}

// TestGet is a sample to run an endpoint test
func TestGet(t *testing.T) {
	r, _ := http.NewRequest("GET", "/v1/object", nil)
	w := httptest.NewRecorder()
	beego.BeeApp.Handlers.ServeHTTP(w, r)

	beego.Trace("testing", "TestGet", "Code[%d]\n%s", w.Code, w.Body.String())

	Convey("Subject: Test Station Endpoint\n", t, func() {
	        Convey("Status Code Should Be 200", func() {
	                So(w.Code, ShouldEqual, 200)
	        })
	        Convey("The Result Should Not Be Empty", func() {
	                So(w.Body.Len(), ShouldBeGreaterThan, 0)
	        })
	})
}

`

func init() {
	CmdApiapp.Flag.Var(&generate.Tables, "tables", "List of table names separated by a comma.")
	CmdApiapp.Flag.Var(&generate.SQLDriver, "driver", "Database driver. Either mysql, postgres or sqlite.")
	CmdApiapp.Flag.Var(&generate.SQLConn, "conn", "Connection string used by the driver to connect to a database instance.")
	commands.AvailableCommands = append(commands.AvailableCommands, CmdApiapp)
}

func createAPI(cmd *commands.Command, args []string) int {
	output := cmd.Out()

	if len(args) < 1 {
		beeLogger.Log.Fatal("Argument [appname] is missing")
	}

	if len(args) > 1 {
		err := cmd.Flag.Parse(args[1:])
		if err != nil {
			beeLogger.Log.Error(err.Error())
		}
	}

	appPath, packPath, err := utils.CheckEnv(args[0])
	if err != nil {
		beeLogger.Log.Fatalf("%s", err)
	}
	if generate.SQLDriver == "" {
		generate.SQLDriver = "mysql"
	}

	beeLogger.Log.Info("Creating API...")

	os.MkdirAll(appPath, 0755)
	fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", appPath, "\x1b[0m")
	os.Mkdir(path.Join(appPath, "conf"), 0755)
	fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "conf"), "\x1b[0m")
	os.Mkdir(path.Join(appPath, "controllers"), 0755)
	fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "controllers"), "\x1b[0m")
	os.Mkdir(path.Join(appPath, "tests"), 0755)
	fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "tests"), "\x1b[0m")
	os.Mkdir(path.Join(appPath, "logs"), 0755)
	fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "logs"), "\x1b[0m")
	fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "conf", "app.conf"), "\x1b[0m")
	configGoContent := strings.Replace(apiconf, "{{.conn}}", generate.SQLConn.String(), -1)
	utils.WriteToFile(path.Join(appPath, "conf", "app.conf"),
		strings.Replace(configGoContent, "{{.Appname}}", path.Base(args[0]), -1))
	fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "README.md"), "\x1b[0m")
	utils.WriteToFile(path.Join(appPath, "README.md"),
		strings.Replace(api_read_me, "{{.conn}}", generate.SQLConn.String(), -1))

	if generate.SQLConn != "" {
		fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "main.go"), "\x1b[0m")
		mainGoContent := strings.Replace(apiMainconngo, "{{.Appname}}", packPath, -1)
		mainGoContent = strings.Replace(mainGoContent, "{{.DriverName}}", string(generate.SQLDriver), -1)
		if generate.SQLDriver == "mysql" {
			mainGoContent = strings.Replace(mainGoContent, "{{.DriverPkg}}", `_ "github.com/go-sql-driver/mysql"`, -1)
		} else if generate.SQLDriver == "postgres" {
			mainGoContent = strings.Replace(mainGoContent, "{{.DriverPkg}}", `_ "github.com/lib/pq"`, -1)
		}
		utils.WriteToFile(path.Join(appPath, "main.go"),
			strings.Replace(
				mainGoContent,
				"{{.conn}}",
				generate.SQLConn.String(),
				-1,
			),
		)
		beeLogger.Log.Infof("Using '%s' as 'driver'", generate.SQLDriver)
		beeLogger.Log.Infof("Using '%s' as 'conn'", generate.SQLConn)
		beeLogger.Log.Infof("Using '%s' as 'tables'", generate.Tables)
		generate.GenerateAppcode(string(generate.SQLDriver), string(generate.SQLConn), "3", string(generate.Tables), appPath)
	} else {
		os.Mkdir(path.Join(appPath, "models"), 0755)
		fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "models"), "\x1b[0m")
		os.Mkdir(path.Join(appPath, "routers"), 0755)
		fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "routers")+string(path.Separator), "\x1b[0m")

		fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "controllers", "object.go"), "\x1b[0m")
		utils.WriteToFile(path.Join(appPath, "controllers", "object.go"),
			strings.Replace(apiControllers, "{{.Appname}}", packPath, -1))

		fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "controllers", "user.go"), "\x1b[0m")
		utils.WriteToFile(path.Join(appPath, "controllers", "user.go"),
			strings.Replace(apiControllers2, "{{.Appname}}", packPath, -1))

		fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "tests", "default_test.go"), "\x1b[0m")
		utils.WriteToFile(path.Join(appPath, "tests", "default_test.go"),
			strings.Replace(apiTests, "{{.Appname}}", packPath, -1))

		fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "routers", "router.go"), "\x1b[0m")
		utils.WriteToFile(path.Join(appPath, "routers", "router.go"),
			strings.Replace(apirouter, "{{.Appname}}", packPath, -1))

		fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "models", "object.go"), "\x1b[0m")
		utils.WriteToFile(path.Join(appPath, "models", "object.go"), APIModels)

		fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "models", "user.go"), "\x1b[0m")
		utils.WriteToFile(path.Join(appPath, "models", "user.go"), APIModels2)

		fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "main.go"), "\x1b[0m")
		utils.WriteToFile(path.Join(appPath, "main.go"),
			strings.Replace(apiMaingo, "{{.Appname}}", packPath, -1))
	}
	/* ==============================api_base_controller============================== */
	beeLogger.Log.Info("Creating Base Controller File For API...")
	fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "controllers", "base_controller.go"), "\x1b[0m")
	utils.WriteToFile(path.Join(appPath, "controllers", "base_controller.go"),
		strings.Replace(api_base_controller, "{{.Appname}}", packPath, -1))
	fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "controllers", "base_batch.go"), "\x1b[0m")
	utils.WriteToFile(path.Join(appPath, "controllers", "base_batch.go"),
		strings.Replace(api_base_batch, "{{.Appname}}", packPath, -1))
	fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "controllers", "base_define.go"), "\x1b[0m")
	utils.WriteToFile(path.Join(appPath, "controllers", "base_define.go"),
		strings.Replace(api_base_define, "{{.Appname}}", packPath, -1))
	fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "controllers", "base_session.go"), "\x1b[0m")
	utils.WriteToFile(path.Join(appPath, "controllers", "base_session.go"),
		strings.Replace(api_base_session, "{{.Appname}}", packPath, -1))
	fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "controllers", "base_time.go"), "\x1b[0m")
	utils.WriteToFile(path.Join(appPath, "controllers", "base_time.go"),
		strings.Replace(api_base_time, "{{.Appname}}", packPath, -1))
	fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "controllers", "base_user.go"), "\x1b[0m")
	utils.WriteToFile(path.Join(appPath, "controllers", "base_user.go"),
		strings.Replace(api_base_user, "{{.Appname}}", packPath, -1))
	fmt.Fprintf(output, "\t%s%screate%s\t %s%s\n", "\x1b[32m", "\x1b[1m", "\x1b[21m", path.Join(appPath, "models", "var_sys_user.go"), "\x1b[0m")
	utils.WriteToFile(path.Join(appPath, "models", "var_sys_user.go"),
		strings.Replace(api_var_sys_user, "{{.Appname}}", packPath, -1))
	/* ==============================api_base_controller============================== */
	beeLogger.Log.Success("New API successfully created!!")
	return 0
}
