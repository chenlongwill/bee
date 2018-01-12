package apiapp

var api_base_controller = `package controllers

import (
	"encoding/json"
	"io/ioutil"
	"strings"
	"sync"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"

	"{{.Appname}}/lib"
	"{{.Appname}}/models"
)

type BaseController struct {
	beego.Controller
	Req *Request
	Res *Response
}

type Tmp struct {
	Code ErrCode
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

func (this *BaseController) Prepare() {
	var req Request
	JsonCheck(this.Ctx.Input.RequestBody, &req)
	this.Req = &req
}

// 统一返回格式
func (this *BaseController) Finish() {
	if this.Res == nil {
		this.Res = &Response{ErrorFail, ErrorFail.String(), NilString}
	}
	if this.Res.Data == nil {
		this.Res.Data = NilString
	}
	if this.Res.Code == ErrorSidQueNil {
		return
	} else {
		this.Ctx.Output.JSON(this.Res, false, false)
		return
	}
}

type OnlineController struct {
	BaseController
	User *models.SysUser
}

// 权限验证，参数解析
func (this *OnlineController) Prepare() {
	var req Request
	JsonCheck(this.Ctx.Input.RequestBody, &req)
	if req.Msg == "" {
		this.Res = &Response{ErrorSidQueNil, "空令牌", NilString}
		this.Ctx.Output.JSON(this.Res, false, false)
		return
	}
	this.Req = &req
	logs.Debug("%d_%s_%s", this.Req.Code, this.Req.Msg, this.Req.Data)
	this.User = SidGetUser(req.Msg)
	if this.User == nil {
		this.Res = &Response{ErrorSidQueNil, ErrorSidQueNil.String(), NilString}
		this.Ctx.Output.JSON(this.Res, false, false)
		return
	}
}

// app用户信息服务接口
type FormUserController struct {
	beego.Controller
	User *models.SysUser
	Res  *Response
}

func (this *FormUserController) Prepare() {
	sid := this.GetString("sid")
	this.User = SidGetUser(sid)
	if this.User == nil {
		this.Res = &Response{ErrorSidQueNil, ErrorSidQueNil.String(), NilString}
		this.Ctx.Output.JSON(this.Res, false, false)
		return
	}
}

// 统一返回格式
func (this *FormUserController) Finish() {
	if this.Res == nil {
		this.Res = &Response{ErrorFail, ErrorFail.String(), NilString}
	}
	if this.Res.Data == nil {
		this.Res.Data = NilString
	}
	if this.Res.Code == ErrorSidQueNil {
		return
	} else {
		this.Ctx.Output.JSON(this.Res, false, false)
		return
	}
}

/**********************************管理平台登录授权************************************/
type SysOnlineController struct {
	beego.Controller
	User      *models.SysUser
	Req       *Request
	Res       *Response
	OptionLog *models.SysOptionLog
}

// 控制下单频率
type OptionPinLvMap struct {
	Lock   sync.RWMutex
	Bucket map[string]int64
}

var optionPinLv OptionPinLvMap

func InitOptionPinLvMap() {
	optionPinLv.Lock.Lock()
	optionPinLv.Bucket = make(map[string]int64, 1024)
	optionPinLv.Lock.Unlock()
}

// 权限验证，参数解析
func (this *SysOnlineController) Prepare() {
	var req Request
	this.OptionLog = &models.SysOptionLog{}
	this.OptionLog.Ip = this.Ctx.Input.IP()
	this.OptionLog.DateTime = TimeStr
	logs.Debug("=============%s", this.Ctx.Input.RequestBody)

	JsonCheck(this.Ctx.Input.RequestBody, &req)
	this.Req = &req
	if req.Msg == "" {
		this.Res = &Response{ErrorSidQueNil, "空令牌", NilString}
		this.Ctx.Output.JSON(this.Res, false, false)
		return
	}
	logs.Debug("%d_%s_%s", this.Req.Code, this.Req.Msg, this.Req.Data)
	this.User = SidGetUser(req.Msg)
	if this.User == nil {
		this.Res = &Response{ErrorSidQueNil, ErrorSidQueNil.String(), NilString}
		this.Ctx.Output.JSON(this.Res, false, false)
		return
	}
	logs.Error("后台操作[%s]", this.User.Account)
	if runmode == "super" {
		// 限流
		var n int64 = 0
		for _, v := range optionPinLv.Bucket {
			if int(TimeUnix-v) < 60 {
				n++
			}
		}
		logs.Error("后台人数[%d]", n)
		optionPinLv.Lock.Lock()
		pinlv, okk := optionPinLv.Bucket[this.User.Account]
		if okk {
			if TimeUnix-pinlv < n {
				logs.Error("[%s]后台操作失败频率[%d]秒", this.User.Account, TimeUnix-pinlv)
				this.Res = &Response{ErrorNoAuth, ps("高峰期限流，操作失败，还需等待[%d]秒，请稍操作", pinlv+n-TimeUnix), "频率限制"}
				optionPinLv.Lock.Unlock()
				this.Data["json"] = this.Res
				this.ServeJSON()
				return
			}
		}
		optionPinLv.Bucket[this.User.Account] = TimeUnix
		optionPinLv.Lock.Unlock()
	}

	this.OptionLog.Account = this.User.Account
	if this.User.Role > 6 {
		this.OptionLog.UserType = "管理员"
	} else {
		this.OptionLog.UserType = "会员"
	}
	val, ok := mapauth.Bucket[this.Ctx.Input.URL()]
	if !ok {
		logs.Debug("后台用户[%s]请求数据路径非法[%s]", this.User.Account, this.Ctx.Input.URL())
		this.Res = &Response{ErrorNoAuth, "请求数据路径非法", NilString}
		this.Ctx.Output.JSON(this.Res, false, false)
		return
	}
	this.OptionLog.OptionName = val.Describe
	value, k := maprole.Bucket[ps("%d", this.User.Role)]
	if !k || !strings.Contains(value.Power, ps(",%d,", val.Id)) {
		logs.Debug("后台用户[%s]无权限[%s]", this.User.Account, this.Ctx.Input.URL())
		this.Res = &Response{ErrorNoAuth, ErrorNoAuth.String(), NilString}
		this.Ctx.Output.JSON(this.Res, false, false)
		return
	}
}

func (this *SysOnlineController) Finish() {
	this.OptionLog.Desc = this.Res.Msg
	this.OptionLog.Result = int(this.Res.Code)
	if this.Res.Data != "频率限制" {
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
							logs.Debug(req, req.Content.Address)
							option.IpAddr = req.Content.Address
						} else {
							logs.Debug(req)
						}
					}
				}
			}
			models.AddSysOptionLog(option)
		}(this.OptionLog)
	}

	if this.Res == nil {
		this.Res = &Response{ErrorFail, ErrorFail.String(), NilString}
	}
	if this.Res.Data == nil {
		this.Res.Data = NilString
	}
	if this.Res.Code == ErrorSidQueNil || this.Res.Code == ErrorNoAuth {
		return
	} else {
		this.Ctx.Output.JSON(this.Res, false, false)
		return
	}
}

/**********************************管理平台登录授权************************************/

/**********************************form表单接口************************************/
type FormSysOnlineController struct {
	beego.Controller
	User      *models.SysUser
	Res       *Response
	OptionLog *models.SysOptionLog
}

// 权限验证，参数解析
func (this *FormSysOnlineController) Prepare() {
	this.OptionLog = &models.SysOptionLog{}
	this.OptionLog.Ip = this.Ctx.Input.IP()
	this.OptionLog.DateTime = TimeStr
	sid := this.GetString("Msg")
	if sid == "" {
		this.Res = &Response{ErrorSidQueNil, "空令牌", NilString}
		this.Ctx.Output.JSON(this.Res, false, false)
		return
	}
	this.User = SidGetUser(sid)
	if this.User == nil {
		this.Res = &Response{ErrorSidQueNil, ErrorSidQueNil.String(), NilString}
		this.Ctx.Output.JSON(this.Res, false, false)
		return
	}
	this.OptionLog.Account = this.User.Account
	if this.User.Role > 6 {
		this.OptionLog.UserType = "管理员"
	} else {
		this.OptionLog.UserType = "会员"
	}
	val, ok := mapauth.Bucket[this.Ctx.Input.URL()]
	if !ok {
		logs.Debug("后台用户[%s]请求数据路径非法[%s]", this.User.Account, this.Ctx.Input.URL())
		this.Res = &Response{ErrorNoAuth, "请求数据路径非法", NilString}
		this.Ctx.Output.JSON(this.Res, false, false)
		return
	}
	this.OptionLog.OptionName = val.Describe
	value, k := maprole.Bucket[ps("%d", this.User.Role)]
	if !k || !strings.Contains(value.Power, ps(",%d,", val.Id)) {
		logs.Debug("后台用户[%s]无权限[%s]", this.User.Account, this.Ctx.Input.URL())
		this.Res = &Response{ErrorNoAuth, ErrorNoAuth.String(), NilString}
		this.Ctx.Output.JSON(this.Res, false, false)
		return
	}
}

func (this *FormSysOnlineController) Finish() {
	this.OptionLog.Desc = this.Res.Msg
	this.OptionLog.Result = int(this.Res.Code)

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
						logs.Debug(req, req.Content.Address)
						option.IpAddr = req.Content.Address
					} else {
						logs.Debug(req)
					}
				}
			}
		}
		models.AddSysOptionLog(option)
	}(this.OptionLog)

	if this.Res == nil {
		this.Res = &Response{ErrorFail, ErrorFail.String(), NilString}
	}
	if this.Res.Data == nil {
		this.Res.Data = NilString
	}
	if this.Res.Code == ErrorSidQueNil || this.Res.Code == ErrorNoAuth {
		return
	} else {
		this.Ctx.Output.JSON(this.Res, false, false)
		return
	}
}

`
