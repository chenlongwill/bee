package apiapp

var api_base_controller = `package controllers

import (
	"encoding/json"
	"io/ioutil"
	"strings"
	"sync"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
	"github.com/chenlongwill/lib"

	"{{.Appname}}/models"
)

// 控制请求频率
type OptionPinLvMap struct {
	Lock   sync.RWMutex
	Bucket map[string]int64
}

// 路由map
type SysAuthMap struct {
	Lock   sync.RWMutex
	Bucket map[string]*models.SysAuth
}

// 角色map
type SysRoleMap struct {
	Lock   sync.RWMutex
	Bucket map[string]*models.SysRole
}

var optionPinLv OptionPinLvMap
var maprouter SysAuthMap
var maprole SysRoleMap

func InitSysRoleMap() {
	maprole.Lock.Lock()
	maprole.Bucket = make(map[string]*models.SysRole, 100)
	maprole.Lock.Unlock()
}

func InitSysAuthMap() {
	maprouter.Lock.Lock()
	maprouter.Bucket = make(map[string]*models.SysAuth, 100)
	maprouter.Lock.Unlock()
}

func InitOptionPinLvMap() {
	optionPinLv.Lock.Lock()
	optionPinLv.Bucket = make(map[string]int64, 1024)
	optionPinLv.Lock.Unlock()
}

type Tmp struct {
	Code int
	Msg  string
}

func JsonCheck(by []byte, req *Request) {
	var tmp Tmp
	if err := json.Unmarshal(by, &tmp); err == nil {
		req.Code = tmp.Code
		req.Msg = tmp.Msg
	}
	var num bool = false
	var start int = 0
	var end int = 0
	for k, v := range by {
		if v == '{' && !num {
			num = true
			continue
		}
		if v == '{' && num {
			start = k
			break
		}
	}
	num = false
	for i := len(by) - 1; i > 1; i-- {
		if by[i] == '}' && !num {
			num = true
			continue
		}
		if by[i] == '}' && num {
			end = i
			break
		}
	}
	req.Data = by[start : end+1]
	return
}

type InitController struct {
	beego.Controller
	Res *Response
}

// 统一返回格式
func (this *InitController) Finish() {
	if this.Res == nil {
		logs.Error("请求失败，无标准返回结构体")
		this.Res = &Response{1, "请求失败", ""}
	}
	this.Ctx.Output.JSON(this.Res, false, false)
	return
}

/* =================================移动前端无权限校验请求接口=========================== */
type BaseController struct {
	InitController
	Req *Request
}

func (this *BaseController) Success(data interface{}, format string, v ...interface{}) {
	logs.Info(format, v...)
	if data == nil {
		this.Res = &Response{0, ps(format, v...), ""}
	} else {
		this.Res = &Response{0, ps(format, v...), data}
	}
	return
}

func (this *BaseController) Debug(data interface{}, format string, v ...interface{}) {
	logs.Debug(format, v...)
	logs.Debug("%s", data)
	if data == nil {
		this.Res = &Response{0, ps(format, v...), ""}
	} else {
		this.Res = &Response{0, ps(format, v...), data}
	}
	return
}

func (this *BaseController) Error(err error, format string, v ...interface{}) {
	logs.Error(format, v...)
	logs.Error(err)
	this.Res = &Response{1, ps(format, v...), ""}
	return
}

func (this *BaseController) Prepare() {
	var req Request
	JsonCheck(this.Ctx.Input.RequestBody, &req)
	this.Req = &req
}

/* =================================移动前端有权限校验请求接口=========================== */
type OnlineController struct {
	InitController
	Req  *Request
	User *models.SysUser
}

func (this *OnlineController) Success(data interface{}, format string, v ...interface{}) {
	msg := ps(format, v...)
	logs.Info("用户[%s]:%s", this.User.Account, msg)
	if data == nil {
		this.Res = &Response{0, msg, ""}
	} else {
		this.Res = &Response{0, msg, data}
	}
	return
}

func (this *OnlineController) Debug(data interface{}, format string, v ...interface{}) {
	msg := ps(format, v...)
	logs.Debug("用户[%s]:%s", this.User.Account, msg)
	logs.Debug("用户[%s]数据:%v", this.User.Account, data)
	if data == nil {
		this.Res = &Response{0, msg, ""}
	} else {
		this.Res = &Response{0, msg, data}
	}
	return
}

func (this *OnlineController) Error(err error, format string, v ...interface{}) {
	msg := ps(format, v...)
	logs.Error("用户[%s]:%s", this.User.Account, msg)
	logs.Error("用户[%s]错误:%v", this.User.Account, err)
	this.Res = &Response{1, msg, ""}
	return
}

// 权限验证，参数解析
func (this *OnlineController) Prepare() {
	var req Request
	JsonCheck(this.Ctx.Input.RequestBody, &req)
	if req.Msg == "" {
		logs.Error("请求失败，空令牌")
		this.Res = &Response{1, "请求失败", ""}
		return
	}
	this.Req = &req
	logs.Debug("%d_%s_%s", this.Req.Code, this.Req.Msg, this.Req.Data)
	this.User = SidGetUser(req.Msg)
	if this.User == nil {
		logs.Error("登录状态已过期，请重新登录")
		this.Res = &Response{3, "登录状态已过期，请重新登录", ""}
		return
	}

	// 请求频率校验
	val, ok := maprouter.Bucket[this.Ctx.Input.URL()]
	if ok {
		if val.LimitTime > 0 {
			pinlv, okk := optionPinLv.Bucket[ps("%s_%s", this.User.Account, this.Ctx.Input.URL())]
			if okk {
				if TimeUnix-pinlv < val.LimitTime {
					logs.Error("[%s]请求频率频繁，剩余[%d]秒", this.User.Account, TimeUnix-pinlv)
					this.Res = &Response{1, ps("请求频率频繁，还需等待[%d]秒，请稍后操作", TimeUnix-pinlv), ""}
					return
				}
			}
			optionPinLv.Lock.Lock()
			optionPinLv.Bucket[ps("%s_%s", this.User.Account, this.Ctx.Input.URL())] = TimeUnix
			optionPinLv.Lock.Unlock()
		}
	}
}

/* =================================移动前端form表单上传图像有权限校验请求接口=========================== */
type FormUserController struct {
	InitController
	User *models.SysUser
}

func (this *FormUserController) Success(data interface{}, format string, v ...interface{}) {
	msg := ps(format, v...)
	logs.Info("用户[%s]:%s", this.User.Account, msg)
	if data == nil {
		this.Res = &Response{0, msg, ""}
	} else {
		this.Res = &Response{0, msg, data}
	}
	return
}

func (this *FormUserController) Debug(data interface{}, format string, v ...interface{}) {
	msg := ps(format, v...)
	logs.Debug("用户[%s]:%s", this.User.Account, msg)
	logs.Debug("用户[%s]数据:%v", this.User.Account, data)
	if data == nil {
		this.Res = &Response{0, msg, ""}
	} else {
		this.Res = &Response{0, msg, data}
	}
	return
}

func (this *FormUserController) Error(err error, format string, v ...interface{}) {
	msg := ps(format, v...)
	logs.Error("用户[%s]:%s", this.User.Account, msg)
	logs.Error("用户[%s]错误:%v", this.User.Account, err)
	this.Res = &Response{1, msg, ""}
	return
}

func (this *FormUserController) Prepare() {
	this.User = SidGetUser(this.GetString("sid"))
	if this.User == nil {
		logs.Error("登录状态已过期，请重新登录")
		this.Res = &Response{3, "登录状态已过期，请重新登录", ""}
		return
	}
}

/* =================================管理平台登录授权=========================== */
type SysOnlineController struct {
	beego.Controller
	User      *models.SysUser
	Req       *Request
	Res       *Response
	OptionLog *models.SysOptionLog
}

func (this *SysOnlineController) Success(data interface{}, format string, v ...interface{}) {
	msg := ps(format, v...)
	logs.Info("用户[%s]:%s", this.User.Account, msg)
	if data == nil {
		this.Res = &Response{0, msg, ""}
	} else {
		this.Res = &Response{0, msg, data}
	}
	return
}

func (this *SysOnlineController) Debug(data interface{}, format string, v ...interface{}) {
	msg := ps(format, v...)
	logs.Debug("用户[%s]:%s", this.User.Account, msg)
	logs.Debug("用户[%s]数据:%v", this.User.Account, data)
	if data == nil {
		this.Res = &Response{0, msg, ""}
	} else {
		this.Res = &Response{0, msg, data}
	}
	return
}

func (this *SysOnlineController) Error(err error, format string, v ...interface{}) {
	msg := ps(format, v...)
	logs.Error("用户[%s]:%s", this.User.Account, msg)
	logs.Error("用户[%s]错误:%v", this.User.Account, err)
	this.Res = &Response{1, msg, ""}
	return
}

// 权限验证，参数解析
func (this *SysOnlineController) Prepare() {
	var req Request
	JsonCheck(this.Ctx.Input.RequestBody, &req)

	if req.Msg == "" {
		logs.Error("请求失败，空令牌")
		this.Res = &Response{1, "请求失败", ""}
		return
	}
	this.Req = &req
	logs.Debug("%d_%s_%s", this.Req.Code, this.Req.Msg, this.Req.Data)
	this.User = SidGetUser(this.Req.Msg)
	if this.User == nil {
		logs.Error("登录状态已过期，请重新登录")
		this.Res = &Response{3, "登录状态已过期，请重新登录", ""}
		return
	}

	// 请求频率校验
	val, ok := maprouter.Bucket[this.Ctx.Input.URL()]
	if ok {
		if val.LimitTime > 0 {
			pinlv, okk := optionPinLv.Bucket[ps("%s_%s", this.User.Account, this.Ctx.Input.URL())]
			if okk {
				if TimeUnix-pinlv < val.LimitTime {
					logs.Error("[%s]请求频率频繁，剩余[%d]秒", this.User.Account, TimeUnix-pinlv)
					this.Res = &Response{1, ps("请求频率频繁，还需等待[%d]秒，请稍后操作", TimeUnix-pinlv), ""}
					return
				}
			}
			optionPinLv.Lock.Lock()
			optionPinLv.Bucket[ps("%s_%s", this.User.Account, this.Ctx.Input.URL())] = TimeUnix
			optionPinLv.Lock.Unlock()
		}
	} else {
		logs.Error("后台用户[%s]请求数据路径不存在[%s]", this.User.Account, this.Ctx.Input.URL())
		this.Res = &Response{4, "请求地址不存在", ""}
		return
	}

	if val.OpLog == 1 {
		this.OptionLog = &models.SysOptionLog{}
		this.OptionLog.Ip = this.Ctx.Input.IP()
		this.OptionLog.DateTime = TimeStr
		this.OptionLog.OptionName = val.Describe
		this.OptionLog.Account = this.User.Account
		if this.User.Role > 6 {
			this.OptionLog.UserType = "管理员"
		} else {
			this.OptionLog.UserType = "会员"
		}
	}
	value, k := maprole.Bucket[ps("%d", this.User.Role)]
	if !k || !strings.Contains(value.Power, ps(",%d,", val.Id)) {
		logs.Error("后台用户[%s]无权限操作[%s]", this.User.Account, this.Ctx.Input.URL())
		this.Res = &Response{4, "无权限操作", ""}
		return
	}
}

func (this *SysOnlineController) Finish() {
	if this.OptionLog != nil {
		this.OptionLog.Desc = this.Res.Msg
		this.OptionLog.Result = this.Res.Code
		go func(option *models.SysOptionLog) {
			resp, err := lib.HttpGet(ps("http://api.map.baidu.com/location/ip?ak=3zSeVkYvnPBrCuifkGuKDzg38cfkS8Vg&ip=%s", option.Ip))
			if err == nil {
				defer resp.Body.Close()
				body, err := ioutil.ReadAll(resp.Body)
				if err == nil {
					var req LoginReq
					err = json.Unmarshal(body, &req)
					if err == nil {
						if req.Status == 0 {
							option.IpAddr = req.Content.Address
						}
					}
				}
			}
			models.AddSysOptionLog(option)
		}(this.OptionLog)
	}

	if this.Res == nil {
		logs.Error("请求失败，无标准返回结构体")
		this.Res = &Response{1, "请求失败", ""}
	}
	this.Ctx.Output.JSON(this.Res, false, false)
	return
}

/**********************************管理平台登录授权************************************/

/**********************************form表单接口************************************/
type FormSysOnlineController struct {
	beego.Controller
	User      *models.SysUser
	Res       *Response
	OptionLog *models.SysOptionLog
}

func (this *FormSysOnlineController) Success(data interface{}, format string, v ...interface{}) {
	msg := ps(format, v...)
	logs.Info("用户[%s]:%s", this.User.Account, msg)
	if data == nil {
		this.Res = &Response{0, msg, ""}
	} else {
		this.Res = &Response{0, msg, data}
	}
	return
}

func (this *FormSysOnlineController) Debug(data interface{}, format string, v ...interface{}) {
	msg := ps(format, v...)
	logs.Debug("用户[%s]:%s", this.User.Account, msg)
	logs.Debug("用户[%s]数据:%v", this.User.Account, data)
	if data == nil {
		this.Res = &Response{0, msg, ""}
	} else {
		this.Res = &Response{0, msg, data}
	}
	return
}

func (this *FormSysOnlineController) Error(err error, format string, v ...interface{}) {
	msg := ps(format, v...)
	logs.Error("用户[%s]:%s", this.User.Account, msg)
	logs.Error("用户[%s]错误:%v", this.User.Account, err)
	this.Res = &Response{1, msg, ""}
	return
}

// 权限验证，参数解析
func (this *FormSysOnlineController) Prepare() {
	sid := this.GetString("Msg")
	if sid == "" {
		logs.Error("请求失败，空令牌")
		this.Res = &Response{1, "请求失败", ""}
		return
	}
	this.User = SidGetUser(sid)
	if this.User == nil {
		logs.Error("登录状态已过期，请重新登录")
		this.Res = &Response{3, "登录状态已过期，请重新登录", ""}
		return
	}

	// 请求频率校验
	val, ok := maprouter.Bucket[this.Ctx.Input.URL()]
	if ok {
		if val.LimitTime > 0 {
			pinlv, okk := optionPinLv.Bucket[ps("%s_%s", this.User.Account, this.Ctx.Input.URL())]
			if okk {
				if TimeUnix-pinlv < val.LimitTime {
					logs.Error("[%s]请求频率频繁，剩余[%d]秒", this.User.Account, TimeUnix-pinlv)
					this.Res = &Response{1, ps("请求频率频繁，还需等待[%d]秒，请稍后操作", TimeUnix-pinlv), ""}
					return
				}
			}
			optionPinLv.Lock.Lock()
			optionPinLv.Bucket[ps("%s_%s", this.User.Account, this.Ctx.Input.URL())] = TimeUnix
			optionPinLv.Lock.Unlock()
		}
	} else {
		logs.Error("后台用户[%s]请求数据路径不存在[%s]", this.User.Account, this.Ctx.Input.URL())
		this.Res = &Response{4, "请求地址不存在", ""}
		return
	}

	if val.OpLog == 1 {
		this.OptionLog = &models.SysOptionLog{}
		this.OptionLog.Ip = this.Ctx.Input.IP()
		this.OptionLog.DateTime = TimeStr
		this.OptionLog.OptionName = val.Describe
		this.OptionLog.Account = this.User.Account
		if this.User.Role > 6 {
			this.OptionLog.UserType = "管理员"
		} else {
			this.OptionLog.UserType = "会员"
		}
	}
	value, k := maprole.Bucket[ps("%d", this.User.Role)]
	if !k || !strings.Contains(value.Power, ps(",%d,", val.Id)) {
		logs.Error("后台用户[%s]无权限操作[%s]", this.User.Account, this.Ctx.Input.URL())
		this.Res = &Response{4, "无权限操作", ""}
		return
	}
}

func (this *FormSysOnlineController) Finish() {
	if this.OptionLog != nil {
		this.OptionLog.Desc = this.Res.Msg
		this.OptionLog.Result = this.Res.Code
		go func(option *models.SysOptionLog) {
			resp, err := lib.HttpGet(ps("http://api.map.baidu.com/location/ip?ak=3zSeVkYvnPBrCuifkGuKDzg38cfkS8Vg&ip=%s", option.Ip))
			if err == nil {
				defer resp.Body.Close()
				body, err := ioutil.ReadAll(resp.Body)
				if err == nil {
					var req LoginReq
					err = json.Unmarshal(body, &req)
					if err == nil {
						if req.Status == 0 {
							option.IpAddr = req.Content.Address
						}
					}
				}
			}
			models.AddSysOptionLog(option)
		}(this.OptionLog)
	}

	if this.Res == nil {
		logs.Error("请求失败，无标准返回结构体")
		this.Res = &Response{1, "请求失败", ""}
	}
	this.Ctx.Output.JSON(this.Res, false, false)
	return
}
`
var api_base_batch = `package controllers

import (
	"github.com/astaxie/beego/logs"
	"github.com/astaxie/beego/toolbox"
)

// 夜间清理系统临时缓存，包括map和redis
func InitSystemParam() error {
	// 下单频率每天清理
	// InitOrderPinLvMap()
	// 出入金频率每天清理
	// InitOrderOutMoneyMap()
	return nil
}

// 夜间清理系统临时缓存，包括map和redis
func BatchInitSystemParam() {
	task := toolbox.NewTask("initsystemparam", "0 0 05 * * 2-6", InitSystemParam)

	// 加入到全局批量列表
	toolbox.AddTask("initsystemparam", task)
	logs.Info("定时任务：夜间清理系统临时缓存开启...")
}

//前6个字段分别表示：
//       秒钟：0-59
//       分钟：0-59
//       小时：1-23
//       日期：1-31
//       月份：1-12
//       星期：0-6（0 表示周日）

//还可以用一些特殊符号：
//       *： 表示任何时刻
//       ,：　表示分割，如第三段里：2,4，表示 2 点和 4 点执行
//　　    －：表示一个段，如第三端里： 1-5，就表示 1 到 5 点
//       /n : 表示每个n的单位执行一次，如第三段里，*/1, 就表示每隔 1 个小时执行一次命令。也可以写成1-23/1.
/////////////////////////////////////////////////////////
//  0/30 * * * * *                        每 30 秒 执行
//  0 43 21 * * *                         21:43 执行
//  0 15 05 * * * 　　                     05:15 执行
//  0 0 17 * * *                          17:00 执行
//  0 0 17 * * 1                          每周一的 17:00 执行
//  0 0,10 17 * * 0,2,3                   每周日,周二,周三的 17:00和 17:10 执行
//  0 0-10 17 1 * *                       毎月1日从 17:00 到 7:10 毎隔 1 分钟 执行
//  0 0 0 1,15 * 1                        毎月1日和 15 日和 一日的 0:00 执行
//  0 42 4 1 * * 　 　                     毎月1日的 4:42 分 执行
//  0 0 21 * * 1-6　　                     周一到周六 21:00 执行
//  0 0,10,20,30,40,50 * * * *　           每隔 10 分 执行
//  0 */10 * * * * 　　　　　　              每隔 10 分 执行
//  0 * 1 * * *　　　　　　　　               从 1:0 到 1:59 每隔 1 分钟 执行
//  0 0 1 * * *　　　　　　　　               1:00 执行
//  0 0 */1 * * *　　　　　　　               毎时 0 分 每隔 1 小时 执行
//  0 0 * * * *　　　　　　　　               毎时 0 分 每隔 1 小时 执行
//  0 2 8-20/3 * * *　　　　　　             8:02,11:02,14:02,17:02,20:02 执行
//  0 30 5 1,15 * *　　　　　　              1 日 和 15 日的 5:30 执行
`
var api_base_define = `package controllers

import (
	"fmt"

	"github.com/astaxie/beego"
)

var ps = fmt.Sprintf
var pe = fmt.Errorf
var runmode string
var whituser string
var OrderNum int

func init() {
	runmode = beego.AppConfig.DefaultString("runmode", "dev")
	whituser = beego.AppConfig.String("whituser")
}

// 根据ip去百度接口查询归属地
type LoginAddr struct {
	Address string
}

// 根据ip去百度接口查询归属地
type LoginReq struct {
	Content LoginAddr
	Status  int
	Message int
}

// 平台代号
const (
	Android   int = 1
	IOS       int = 2
	PC        int = 3
	MobileWeb int = 4
	PCWeb     int = 5
)

// 请求结构体
type Request struct {
	Code int
	Msg  string
	Data []byte
}

// 返回结构体
type Response struct {
	Code int
	Msg  string
	Data interface{}
}

// 返回结构体
type DocResponse struct {
	Code int
	Msg  string
	Data string
}

// 错误代号
const (
	ErrorNil        int = 0 // 成功
	ErrorFail       int = 1 // 一般性错误
	ErrorSidNil     int = 2 // 空令牌
	ErrorSidTimeOut int = 3 // 令牌超时
	ErrorNoAuth     int = 4 // 无访问权限
)
`
var api_base_session = `package controllers

import (
	"fmt"
	"time"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
	"github.com/chenlongwill/lib"

	"{{.Appname}}/models"
)

// 根据sid获取app在线用户信息，没有返回nil
func SidGetUser(sid string) *models.SysUser {
	redis := lib.NewRedis("session")
	var user models.SysUser
	err := redis.GetStruct(sid, &user)
	if err != nil {
		logs.Debug("用户不在线[%s]err[%v]", sid, err)
		return nil
	}
	return &user
}

// 根据account获取app在线用户信息，没有返回nil
func AccountGetUser(account string) *models.SysUser {
	redis := lib.NewRedis("session")
	var user models.SysUser
	err := redis.GetStruct(redis.GetDefaultString(account), &user)
	if err != nil {
		logs.Debug("用户不在线[%s]err[%v]", account, err)
		return nil
	}
	return &user
}

// 用户信息变更，更新session，如果sid存在，只更新内容，不存在则不更新session
func SessionPutUserNoCoverSid(account string) (user *models.SysUser, err error) {
	user, err = models.GetUserByAccount(account)
	if err != nil {
		return
	}
	user.Pwd = ""
	if user.Zfpwd == "" {
		user.Zfpwd = "n"
	} else {
		user.Zfpwd = "y"
	}
	// user.Openid = ""
	idcard := []byte(user.Idcard)
	num := len(user.Idcard)
	if num == 18 {
		user.Idcard = ps("%s******%s", idcard[0:5], idcard[num-6:num])
	} else {
		user.Idcard = ""
	}
	redis := lib.NewRedis("session")
	tuser := AccountGetUser(account)
	if tuser != nil {
		user.Platform = tuser.Platform
		user.LoginIp = tuser.LoginIp
		user.LoginAddr = tuser.LoginAddr
		user.LoginTime = tuser.LoginTime
		err = redis.PutStructEx(user.Sid, tuser, time.Second*time.Duration(beego.AppConfig.DefaultInt("session_timeout", 43200)))
		if err != nil {
			return
		}
		err = redis.PutEX(user.Account, user.Sid, time.Second*time.Duration(beego.AppConfig.DefaultInt("session_timeout", 43200)))
		if err != nil {
			return
		}
	} else {
		err = fmt.Errorf("[%s]登录状态已过期", user.Account)
	}
	return
}

// 用户登录校验成功之后，将用户信息存储到session，重新生成sid
func SessionPutUser(user *models.SysUser) (err error) {
	user.Sid = lib.GetSid()
	user.Pwd = ""
	if user.Zfpwd == "" {
		user.Zfpwd = "n"
	} else {
		user.Zfpwd = "y"
	}
	// user.Openid = ""
	idcard := []byte(user.Idcard)
	num := len(user.Idcard)
	if num == 18 {
		user.Idcard = ps("%s******%s", idcard[0:5], idcard[num-6:num])
	} else {
		user.Idcard = ""
	}
	redis := lib.NewRedis("session")
	if redis.IsExist(user.Account) {
		logs.Debug("更新用户session信息[%s]", user.Account)
		redis.Delete(redis.GetDefaultString(user.Account))
		redis.Delete(user.Account)
	}
	var tmpuser *models.SysUser
	tmpuser = user
	err = redis.PutStructEx(user.Sid, tmpuser, time.Second*time.Duration(beego.AppConfig.DefaultInt("session_timeout", 43200)))
	if err != nil {
		return
	}
	err = redis.PutEX(user.Account, user.Sid, time.Second*time.Duration(beego.AppConfig.DefaultInt("session_timeout", 43200)))
	if err != nil {
		return
	}
	return
}

// 根据用户账号，删除用户session信息
func SessionDelUser(acc string) bool {
	redis := lib.NewRedis("session")
	if redis.IsExist(acc) {
		logs.Debug("删除用户session信息[%s]", acc)
		redis.Delete(redis.GetDefaultString(acc))
		redis.Delete(acc)
		return true
	} else {
		return false
	}
}

// 根据用户sid，获取用户session信息
func GetSession(sid string) (string, bool) {
	redis := lib.NewRedis("session")
	session, err := redis.GetString(sid)
	if err != nil {
		logs.Error("根据sid获取session失败[%s]err[%v]", sid, err)

		return "", false
	} else {
		return session, true
	}
}
`
var api_base_time = `package controllers

import (
	"time"

	"github.com/astaxie/beego/logs"
)

var TimeUnix int64
var TimeStr string
var TimeTen string
var TimeBase time.Time

func TimeInit() {
	block := make(chan bool)
	go func() {
		for {
			if TimeUnix == time.Now().Unix() {
				time.Sleep(time.Millisecond * 5)
				continue
			}
			TimeUnix = time.Now().Unix()
			TimeBase = time.Now()
			TimeStr = time.Now().Format("2006-01-02 15:04:05")
			TimeTen = time.Now().Format("20060102150405") // 14位
			block <- true
		}
	}()
	go func() {
		logs.Debug("并行定时器开启(秒)")
		for {
			<-block
			if runmode == "pro" {
			} else {
				// go KlineCreateInit()
			}
		}
	}()
}
`
