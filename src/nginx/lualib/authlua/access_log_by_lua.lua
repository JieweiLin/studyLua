local json = require(require("ffi").os == "Windows" and "dkjson" or "cjson.safe")
local retTable = {};    --最终产生json的表
local sessionId  = tostring(ngx.var.cookie_JSESSIONID);
retTable["remote_addr"] = ngx.var.remote_addr;
retTable["remote_user"] = ngx.var.remote_user;
retTable["time_local"] = ngx.var.time_local;
retTable["request_uri"] = ngx.var.request_uri;
retTable["cost_time"] = ngx.var.request_time;
retTable["status"] = ngx.var.status;
retTable["http_referer"] = ngx.var.http_referer;
retTable["http_user_agent"] = ngx.var.http_user_agent;
retTable["http_x_forwarded_for"] = ngx.var.http_x_forwarded_for;
retTable["sessionId"] = sessionId;
retTable["request_body"] = ngx.var.request_body;
retTable["resp_body"] = ngx.var.resp_body;
 ngx.log(ngx.ALERT,json.encode(retTable))