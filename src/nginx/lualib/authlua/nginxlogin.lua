local username = nil;
local password = nil;

local redisConfig = require "authlua.redis_config"
local redis = require("authlua.redis_iresty")

local opts = {timeout=redisConfig.getTimeOut(),ip=redisConfig.getIp(),port=redisConfig.getPort(),pwd=redisConfig.getPwd()};
local red = redis:new(opts);

local arg = ngx.req.get_uri_args()
           for k,v in pairs(arg) do
             
               if k == 'username' then
                   username = v;
               end
               
               if k == 'password' then
                   password = v;
               end
               
               
           end
           
 if username and password then
    ngx.log(ngx.INFO,"username="..username.."password="..password);
    
    
    local res, err = red:sismember("accountlist",username.."*"..password);
    
    
    if res ~= 1 then
      
         ngx.log(ngx.INFO,"login fail:"..res);
         ngx.redirect("/nginx");
         
    else   
       
         local token = ngx.var.cookie_token; --  ��ȡcookie�����浽����ȥ..
          ngx.log(ngx.ERR,"保存用户的token:",token);
         local res, err = red:sadd('tokenlist',token);
         if not res then
               ngx.log(ngx.ERR,"add token to cache fail:",err);
          end
         
         ngx.redirect("/nginxindex");
    
    end
    
    
    
 else
    
 end
           
           