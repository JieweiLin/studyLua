local token = ngx.var.cookie_token;
local redisConfig = require "authlua.redis_config"
local redis = require("authlua.redis_iresty")

local opts = {timeout=redisConfig.getTimeOut(),ip=redisConfig.getIp(),port=redisConfig.getPort(),pwd=redisConfig.getPwd()};
local red = redis:new(opts);

 ngx.log(ngx.INFO,"token"..token);
 
 if not token then
      ngx.print("请重新登陆");
 else 
    local res, err = red:sismember("tokenlist",token);
    
    if not res then
         ngx.print("请重新登陆");
    elseif res == 0 then
         ngx.print("请重新登陆");
    end
 
      
 end