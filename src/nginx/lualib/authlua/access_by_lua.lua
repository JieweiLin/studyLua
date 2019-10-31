local token = ngx.var.cookie_token;
local redisConfig = require "authlua.redis_config"
local redis = require("authlua.redis_iresty")

local opts = {timeout=redisConfig.getTimeOut(),ip=redisConfig.getIp(),port=redisConfig.getPort(),pwd=redisConfig.getPwd()};
local red = redis:new(opts);

 ngx.log(ngx.INFO,"token=",token);
 
 if not token then
      ngx.redirect("/nginx");
      
 else  --У��session�Ƿ���ȷ
 
    local res, err = red:sismember("tokenlist",token);
    
    ngx.log(ngx.INFO,"user token is : "..res);
    if not res then
     ngx.log(ngx.INFO,"token没有找到 ");
         ngx.redirect("/nginx");
    elseif res == 0 then
        ngx.log(ngx.INFO,"token不存在 ");
        ngx.redirect("/nginx");
    end
 
      
 end