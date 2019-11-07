---
--- Generated by EmmyLua(https://github.com/EmmyLua)
--- Created by linjw.
--- DateTime: 2019/11/1 11:09
---

mysql = require("nginx.lualib.resty.mysql")
props = {
    host="172.16.10.39",
    port=3306,
    database="dbtoken",
    user="dbtoken_rw",
    password="szy123"
}
db, err = mysql.new()
if not db then
    print("连接mysql失败", err)
    return
end
db:set_timeout(1000)
res, err, errno, sqlstate = db:connect(props)
if not res then
    print("failed to connect:", err)
    return
end
t = os.date("%Y-%m-%d %H:%M:%S", os.time())
select_sql = "select id, token_id, expire_time from t_kick_token where id >= 13578 limit 2000";
res, err, errno, sqlstate = db:query(select_sql)
if not res then
    print("bad result:", err)
    return
end
cjson = require "cjson"
for i, v in ipairs(res) do
    print(cjson.encode(v))

    if v.expire_time>=t then
        print("设置"..v.token_id)
    end
end