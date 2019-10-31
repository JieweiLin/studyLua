local redisConfig = require "authlua.redis_config"
local redis = require("authlua.redis_iresty")
local shared_data  = ngx.shared.shared_data;
local opts = {timeout=redisConfig.getTimeOut(),ip=redisConfig.getIp(),port=redisConfig.getPort(),pwd=redisConfig.getPwd()};
local red = redis:new(opts);
function decodeURI(s)
    s = string.gsub(s, '%%(%x%x)', function(h) return string.char(tonumber(h, 16)) end)
    return s
end

local cmd = ngx.var.arg_cmd;

if cmd == 'set' then

  local reqcode = ngx.var.arg_reqcode;
  local reqdata = decodeURI(ngx.var.arg_reqdata); 
  
  if reqcode == '' or reqdata == '' then
    ngx.print("协议号或返回内容不能为空");
    return;
  end
  
   ngx.log(ngx.INFO,'协议号:'..reqcode.."返回内容:"..reqdata);
 --  ngx.print('协议号:'..reqcode.."返回内容:"..reqdata);

  red:sadd("reqcodeblacklist",reqcode);
  
  local res,err = red:set("reqcodeblack:"..reqcode,reqdata);
  if  res then
  
      shared_data :set("hasinit", false); --让内存重新初始化
      ngx.print("ok");
    
  else
       ngx.print("fail");
  end

elseif cmd == 'del' then

  local reqcode = ngx.var.arg_reqcode;
  red:srem("reqcodeblacklist",reqcode);
  local res,err = red:del("reqcodeblack:"..reqcode);
  if  res then
      shared_data :set("hasinit", false); --让内存重新初始化
      ngx.print("ok");
  else
      ngx.print("fail");
  end
  
elseif cmd == 'get' then

     local reqcodeblacklist = "";
    local res,err = red:smembers("reqcodeblacklist");
    
   if not res then
   
   else
     for k2,word in pairs(res) do
        reqcodeblacklist = reqcodeblacklist .. word .. ","
    end
     ngx.print(reqcodeblacklist);
   end
    
elseif cmd == 'detail' then   

  local reqcode = ngx.var.arg_reqcode;
  local res,err = red:get("reqcodeblack:"..reqcode);
  if  res then
      ngx.print(res);
  else
      ngx.print("fail");
  end
  
  elseif cmd == 'getlk' then   
   
    local res,err = red:get("fluidcontrol");
     if  res then
        ngx.print(res);
    end
   
   elseif cmd == 'setlk' then   
   
    local lk = decodeURI(ngx.var.arg_lk);
    local res,err = red:set("fluidcontrol",lk);
    if  res then
      shared_data :set("hasinit", false); --让内存重新初始化
      ngx.print("ok");
  else
      ngx.print("fail");
  end
   
end