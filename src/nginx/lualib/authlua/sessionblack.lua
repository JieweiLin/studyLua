local redisConfig = require "authlua.redis_config"
local redis = require("authlua.redis_iresty")
local shared_data  = ngx.shared.shared_data;

local function lua_string_split(str, split_char)      
 local sub_str_tab = {};  
   
 while (true) do          
 local pos = string.find(str, split_char);    
 if (not pos) then              
  local size_t = table.getn(sub_str_tab)  
  table.insert(sub_str_tab,size_t+1,str);  
  break;    
 end  
   
 local sub_str = string.sub(str, 1, pos - 1);                
 local size_t = table.getn(sub_str_tab)  
 table.insert(sub_str_tab,size_t+1,sub_str);  
 local t = string.len(str);  
 str = string.sub(str, pos + 1, t);     
 end      
 return sub_str_tab;  
end 

local opts = {timeout=redisConfig.getTimeOut(),ip=redisConfig.getIp(),port=redisConfig.getPort(),pwd=redisConfig.getPwd()};
local red = redis:new(opts);

local cmd = ngx.var.arg_cmd;
local sessionlist = "";
if cmd == 'opencontrol' then
    local controlElements = ngx.var.arg_controlElements;
    red:set("opensessioncontrol",controlElements);
    shared_data :set("hasinit", false); --让内存重新初始化
    ngx.print("ok");

elseif cmd == 'closecontrol' then

red:del("opensessioncontrol");
shared_data :set("hasinit", false); --让内存重新初始化
ngx.print("ok");
  
elseif cmd == 'getcontrol' then
   local res,err = red:get("opensessioncontrol");
   if err then
     ngx.log(ngx.ERR,"获取会话控制失败",err);
     ngx.print("-1");
   elseif not res then
     ngx.print("");
  else 
    ngx.print(res);
  end

elseif cmd == 'get' then
  local res,err = red:smembers("sessionblacklist");
  if err then
    ngx.log(ngx.ERR,"获取会话黑名单失败",err);
    -- ngx.print("获取IP黑名单失败");
   elseif not res then
      ngx.print("");
  else   
    for k2,word in pairs(res) do
        sessionlist = sessionlist .. word .. ","
    end
    
    
    
     ngx.print(sessionlist);
  end

end
