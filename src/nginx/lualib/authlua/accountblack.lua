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
local accountlist = "";
if cmd == 'set' then
    accountlist = ngx.var.arg_accountlist;
    red:del("accountblacklist");
    
    local ta  = lua_string_split(accountlist,",")  
  
    local size = table.getn(ta)  
    for i = 1,size ,1 do  
       if ta[i] ~= '' then
       red:sadd("accountblacklist",ta[i]);
       end
    end 
   
   shared_data :set("hasinit", false); --让内存重新初始化
       ngx.print("ok");
    

elseif cmd == 'get' then

  
  local res,err = red:smembers("accountblacklist");
  if err then
    ngx.log(ngx.ERR,"获取账号黑名单失败",err);
    ngx.print("-1");
  elseif not res then
    ngx.print("");
  else   
    
    for k2,word in pairs(res) do
        accountlist = accountlist .. word .. ","
    end
    
    
    
     ngx.print(accountlist);
  end

end
