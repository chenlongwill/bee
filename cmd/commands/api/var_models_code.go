package apiapp

var api_var_sys_user = `package models

import (
	// syssql "database/sql"
	"fmt"

	"github.com/astaxie/beego/orm"
)
	
// Auth         []SysAuth "orm:\"-\"" // 权限

var ps = fmt.Sprintf

// 通过账号获取用户信息
func GetUserByAccount(account string) (v *SysUser, err error) {
	o := orm.NewOrm()
	v = &SysUser{Account: account}
	if err = o.Read(v, "Account"); err == nil {
		return v, nil
	}
	return nil, err
}

// 更新用户登陆归属地和ip地址和登陆时间
func UpdateUserIp(v *SysUser) (err error) {
	o := orm.NewOrm()
	if _, err = o.Update(v, "LoginIp", "LoginTime", "Platform", "LoginAddr"); err == nil {
		return nil
	}
	return err
}
`
