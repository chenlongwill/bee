package apiapp

var api_read_me = `
# bee工具根据数据库结构反向生成基础代码
bee api qq_5 -tables="sys_option_log,sys_auth,sys_price,sys_role,sys_settle,sys_user,sys_xun" -driver="mysql" -conn="{{.conn}}"
bee generate appcode -tables="sys_user" -driver=mysql -conn="{{.conn}}" -level=2

# bee工具自动生成API文档
bee run -gendoc=true -downdoc=true

Mac  编译go 报错 kill 9  ，解决方案：添加编译参数
go install -ldflags -s
mac 下redis默认守护进程启动，daemonize yes;
redis-server /usr/local/etc/redis.conf 

nohup ./comet 2>&1 > ~/logs/im_core.log &

# 时间和时间戳转换
toBeCharge := "2015-01-01 00:00:00"                             //待转化为时间戳的字符串 注意 这里的小时和分钟还要秒必须写 因为是跟着模板走的 修改模板的话也可以不写  
timeLayout := "2006-01-02 15:04:05"                             //转化所需模板  
loc, _ := time.LoadLocation("Local")                            //重要：获取时区  
theTime, _ := time.ParseInLocation(timeLayout, toBeCharge, loc) //使用模板在对应时区转化为time.time类型  
sr := theTime.Unix()                                            //转化为时间戳 类型是int64  
fmt.Println(theTime)                                            //打印输出theTime 2015-01-01 15:15:00 +0800 CST  
fmt.Println(sr)                                                 //打印输出时间戳 1420041600  
# 时间戳转日期  
dataTimeStr := time.Unix(sr, 0).Format(timeLayout) // 设置时间戳 使用模板格式化为日期字符串 

# 仪表盘生成在beego router框架里
# beego-router.go-865-+
toolbox.StatisticsMap.AddStatistics(r.Method, r.URL.Path, "&admin.user", time.Duration(timeDur.Nanoseconds()))
`
