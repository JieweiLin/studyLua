
require("authlua.redis_config")
local redis = require("authlua.redis_iresty")


ngx.log(ngx.ERR,"哇擦:"..ngx.var.ppass);

ngx.req.read_body() -- 解析 body 参数之前一定要先读取 body
local arg = ngx.req.get_post_args()

local json = require("resty.dkjson");


for k,v in pairs(arg) do
  ngx.log(ngx.ERR,"收到key:".. k.. " 值是:".. v);
  
  if k == 'reqcode' then 
    ngx.log(ngx.ERR,"协议编号:"..v);
    
  end
  
  if k == 'body' then 
    ngx.log(ngx.ERR,"协议内容:"..v);
  end
  
end



local black_ips = {["192.168.1.224"]=true}

local ip = ngx.var.remote_addr
ngx.log(ngx.ERR,"用户IP:"..ip);
if true == black_ips[ip] then
          --ngx.print("deny")
          ngx.var.ppass = ngx.var.ppass..'BackUp';
else
  -- ngx.print("{\"returncode\":\"0\",\"message\":\"请求已经接收\",\"body\":\"\"}");
end

