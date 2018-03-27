package apiapp

var api_base_user = `package controllers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/astaxie/beego/logs"
	"github.com/astaxie/beego/toolbox"
	"github.com/chenlongwill/lib"

	"{{.Appname}}/models"
)

var authList []models.SysAuth

// app用户信息服务接口
type AppUserController struct {
	BaseController
}

// app用户信息服务接口
type AppUserOnlineController struct {
	OnlineController
}

// UrlLook ...
// @Title UrlLook
// @Description 访问流量统计
// @Param	body		body 	controllers.Request	true		"json格式登录请求参数"
// @Success 200 {object} controllers.DocResponse
// @router /reqest/count [post]
func (this *AppUserOnlineController) UrlLook() {
	if this.User.Account == "18117493299" {
		data := toolbox.StatisticsMap.GetMap()
		this.Success(data, "查询访问流量统计成功")
	} else {
		this.Error(nil, "查询访问流量统计失败")
	}
	return
}

type LoginRequest struct {
	Account  string "description:\"账号\""
	Pwd      string "description:\"密码\""
	Platform int    "description:\"客户端代号\""
}

type DocLoginRequest struct {
	Code int          "description:\"请求代号\""
	Msg  string       "description:\"token令牌\""
	Data LoginRequest "description:\"请求数据\""
}

// Login ...
// @Title Login
// @Description 用户登录验证
// @Param	body		body 	controllers.DocLoginRequest	true		"json格式登录请求参数"
// @Success 200 {object} models.SysUser
// @router /login [post]
func (this *AppUserController) Login() {
	var v LoginRequest
	if err := json.Unmarshal(this.Req.Data, &v); err == nil {
		// 非空校验，任意类型
		if lib.CheckStructArgNotNull(v, "Account", "Pwd") != "" {
			this.Error(pe("[%s]", v.Account), "请求失败，请输入%s", lib.CheckStructArgNotNull(v, "Account", "Pwd"))
			return
		}

		var user *models.SysUser
		user, err = models.GetUserByAccount(v.Account)
		if err != nil {
			this.Error(pe("[%s][%v]", v.Account, err), "登录失败，此账号还未注册")
			return
		}

		// 判断管理员账户是否到期
		if user.Role > 5 {
			t1, err := time.Parse("2006-01-02 15:04:05", user.RegisterTime)
			if err != nil || t1.Before(TimeBase) {
				this.Error(pe("[%s][%v]", v.Account, err), "登录失败，管理账号已到期")
				return
			}
		}

		// 用户状态:1-待完善资料，2-完善资料中，3-驳回，4-正常，6-禁止登陆，7-销户
		if user.Status != 1 && user.Status != 2 && user.Status != 3 && user.Status != 4 {
			if user.Status == 6 {
				this.Error(pe("[%s]", v.Account), "您账户已冻结，禁止登陆")
			} else {
				this.Error(pe("[%s]", v.Account), "此已销户，不能登录")
			}
			return
		}

		// 查询用户信息成功，开始密码校验
		if user.Pwd != lib.StrToMD5(fmt.Sprintf("@China_%s", v.Pwd)) {
			this.Error(pe("[%s]", v.Account), "登录失败，登录密码不正确")
			return
		}

		// 密码校验成功，加入session
		user.Platform = v.Platform
		user.LoginIp = this.Ctx.Input.IP()
		user.LoginTime = TimeStr

		// 查询寻ip归属地，更新到数据库
		resp, err := lib.HttpGet(ps("http://api.map.baidu.com/location/ip?ak=3zSeVkYvnPBrCuifkGuKDzg38cfkS8Vg&ip=%s", user.LoginIp))
		if err == nil {
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				var req LoginReq
				err = json.Unmarshal(body, &req)
				if err == nil {
					if req.Status == 0 {
						user.LoginAddr = req.Content.Address
					} else {
						logs.Error("获取ip归属地失败", req)
					}
				}
			}
		}

		go models.UpdateUserIp(user)

		// PC管理平台登录，非普通用户和经纪人，则导出用户权限
		if v.Platform == int(PC) {
			if user.Role == 1 {
				this.Error(pe("用户[%v]无权登录后台", user.Account), "登录失败，无权登录管理后台")
				return
			}
			val, k := maprole.Bucket[ps("%d", user.Role)]
			if k {
				var result []models.SysAuth
				for _, value := range authList {
					if strings.Contains(val.Power, ps(",%d,", value.Id)) {
						result = append(result, value)
					}
				}
				user.Auth = result
			}
		} else {
			if user.Role > 5 {
				this.Error(pe("管理员[%v]无权登录前端", user.Account), "登录失败，无权登录前端")
				return
			}
		}

		err = SessionPutUser(user)
		if err != nil {
			this.Error(pe("[%v]加入session失败[%v]", user.Account, err), "[%s]登录失败，请重新尝试", user.Account)
			return
		}

		this.Success(user, "[%s]登录成功", user.Account)
	} else {
		this.Error(pe("[%v]参数解析失败[%v]", v, err), "输入信息解析失败，请稍后重试")
	}
	return
}

// Logout ...
// @Title Logout
// @Description 用户退出登录
// @Param	body		body 	controllers.DocRequest	true		"json格式登录请求参数"
// @Success 200 {object} controllers.DocResponse
// @router /logout [post]
func (this *AppUserOnlineController) Logout() {
	if !SessionDelUser(this.User.Account) {
		this.Error(nil, "退出失败，请重新尝试")
		return
	}
	this.Success(nil, "退出成功")
	return
}

type RegisterRequest struct {
	Phone      string "description:\"手机号\""
	Code       string "description:\"验证码\""
	Pwd        string "description:\"密码\""
	Brokercode int    "description:\"经纪人编码\""
}

type DocRegisterRequest struct {
	Code int             "description:\"请求代号\""
	Msg  string          "description:\"token令牌\""
	Data RegisterRequest "description:\"请求数据\""
}

// GetVcodeBytImg ...
// @Title GetVcodeBytImg
// @Description 获取图形验证码
// @Success 200 {object} controllers.DocResponse
// @router /img [post]
func (this *AppUserController) GetVcodeBytImg() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	vcode := ps("%04v", r.Int31n(9999))
	digits := []byte(vcode)
	codestr := ""

	for v := range digits {
		digits[v] %= 10
		codestr += strconv.FormatInt(int64(digits[v]), 32)
	}
	ip := this.Ctx.Input.IP()
	redis := lib.NewRedis("vcodeimg")

	err := redis.PutEX(ps("%s.%s", ip, codestr), codestr, time.Second*300)
	if err != nil {
		this.Error(pe("[%s][%v]", ip, err), "验证码发送失败，请重新获取验证码")
		return
	}

	data, err := lib.Newimage(digits, 100, 40)
	if err != nil {
		this.Error(pe("[%s][%v]", ip, err), "验证码发送失败，请重新获取验证码")
		return
	}
	this.Success(data, "图形验证码获取成功")
	return
}

type GetVcodeByPhoneRequest struct {
	Codeimg string
	Phone   string
}

type DocGetVcodeByPhoneRequest struct {
	Code int                    "description:\"请求代号\""
	Msg  string                 "description:\"token令牌\""
	Data GetVcodeByPhoneRequest "description:\"请求数据\""
}

// GetVcodeBytPhone ...
// @Title GetVcodeBytPhone
// @Description 根据手机号发送验证码
// @Param	body		body 	controllers.DocGetVcodeByPhoneRequest	true		"json格式登录请求参数"
// @Success 200 {object} controllers.DocResponse
// @router /phone [post]
func (this *AppUserController) GetVcodeBytPhone() {
	var v GetVcodeByPhoneRequest
	if err := json.Unmarshal(this.Req.Data, &v); err == nil {
		// 非空校验，任意类型
		if lib.CheckStructArgNotNull(v, "Codeimg", "Phone") != "" {
			this.Error(nil, "请求失败，请输入%s", lib.CheckStructArgNotNull(v, "Codeimg", "Phone"))
			return
		}
		if !lib.CheckArgPhone(v.Phone) {
			this.Error(pe("[%s]", v.Phone), "操作失败，手机号格式错误")
			return
		}

		ip := this.Ctx.Input.IP()

		redis := lib.NewRedis("vcodeimg")

		vcodeimg, err := redis.GetString(fmt.Sprintf("%s.%s", ip, v.Codeimg))
		if err != nil {
			this.Error(pe("[%s][%v]", v.Phone, err), "图形验证码校验失败")
			return
		}
		if vcodeimg != v.Codeimg {
			this.Error(pe("[%s]", v.Phone), "图形验证码校验失败")
			return
		}
		err = redis.Delete(ps("%s.%s", ip, v.Codeimg))
		if err != nil {
			logs.Error("[%s]图形验证码删除失败:[%v]", ps("%s.%s", ip, v.Codeimg), err)
		}
		if !lib.SendVcode(v.Phone) {
			this.Error(pe("[%s]", v.Phone), "获取手机验证码失败，请重新尝试")
			return
		}
		this.Success(nil, "发送手机验证码成功")
	} else {
		this.Error(pe("[%v]参数解析失败[%v]", v, err), "输入信息解析失败，请稍后重试")
	}
	return
}

// Register ...
// @Title Register
// @Description 用户注册
// @Param	body		body 	controllers.DocRegisterRequest	true		"json格式登录请求参数"
// @Success 200 {object} controllers.DocResponse
// @router /register [post]
func (this *AppUserController) Register() {
	var v RegisterRequest
	if err := json.Unmarshal(this.Req.Data, &v); err == nil {
		// 注册参数校验
		// 非空校验，任意类型
		if lib.CheckStructArgNotNull(v, "Phone", "Code", "Pwd", "Brokercode") != "" {
			this.Error(nil, "请求失败，请输入%s", lib.CheckStructArgNotNull(v, "Phone", "Code", "Pwd", "Brokercode"))
			return
		}

		err = lib.CheckVcode(v.Phone, v.Code)
		if err != nil {
			this.Error(pe("%s%v", v.Phone, err), "%v", err)
			return
		}

		var ruser *models.SysUser
		ruser, err = models.GetSysUserById(v.Brokercode)
		if err != nil {
			this.Error(pe("%s该经纪人不存在%v", v.Phone, err), "该经纪人不存在")
			return
		}

		if ruser.Role != 2 {
			this.Error(pe("[%s][%s]该用户不是经纪人", v.Phone, ruser.Account), ps("[%d]该用户不是经纪人", v.Brokercode))
			return
		}

		if ruser.BrokerStatus != 2 && ruser.BrokerStatus != 4 {
			this.Error(pe("[%s][%s]该经纪人禁止开户", v.Phone, ruser.Account), ps("[%d]该经纪人禁止开户", v.Brokercode))
			return
		}

		// 插入一条数据获取唯一id
		var user models.SysUser
		user.Account = v.Phone
		user.Phone = v.Phone
		user.Idcard = v.Phone
		user.Name = "临时用户"
		user.Broker = ruser.Id
		user.Xiaoshou = ruser.Account
		user.Huiyuan = ruser.Huiyuan
		user.Yunying = ruser.Yunying
		user.Status = 1
		user.IoAble = 2
		user.Platform = MobileWeb
		user.LoginIp = this.Ctx.Input.IP()
		user.LoginTime = TimeStr
		user.RegisterTime = TimeStr
		user.Role = 1
		user.Pwd = lib.StrToMD5(fmt.Sprintf("@China_%s", v.Pwd))
		// 查询寻ip归属地，更新到数据库
		resp, err := lib.HttpGet(ps("http://api.map.baidu.com/location/ip?ak=3zSeVkYvnPBrCuifkGuKDzg38cfkS8Vg&ip=%s", user.LoginIp))
		if err == nil {
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				var req LoginReq
				err = json.Unmarshal(body, &req)
				if err == nil {
					if req.Status == 0 {
						user.LoginAddr = req.Content.Address
					} else {
						logs.Error("获取ip归属地失败", req)
					}
				}
			}
		}

		_, err = models.AddSysUser(&user)
		if err != nil {
			this.Error(err, ps("注册失败，手机号[%s]已经注册，请尝试或联系客服", v.Phone))
			return
		}

		err = SessionPutUser(&user)
		if err != nil {
			this.Error(pe("[%v]加入session失败[%v]", user.Account, err), "[%s]登录失败，请重新尝试登录", user.Account)
			return
		}

		this.Success(user, "[%s]注册成功", user.Account)
	} else {
		this.Error(pe("[%v]参数解析失败[%v]", v, err), "输入信息解析失败，请稍后重试")
	}
	return
}
`
