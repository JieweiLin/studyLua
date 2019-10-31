local redisConfig = require "authlua.redis_config"
local redis = require("authlua.redis_iresty")
local json = require(require("ffi").os == "Windows" and "dkjson" or "cjson.safe")
local shared_data  = ngx.shared.shared_data;
local opts = {timeout=redisConfig.getTimeOut(),ip=redisConfig.getIp(),port=redisConfig.getPort(),pwd=redisConfig.getPwd()};
local red = redis:new(opts);




local rule={}
-- 从redis初始化规则到内存
function rule.init()
    
    local hasinit = shared_data :get("hasinit");
    ngx.log(ngx.INFO,"是否已经初始化规则到内存?",hasinit);
    
    local rule_status = shared_data :get("rule_status");
    
    if not hasinit then
    
      shared_data:flush_all(); --清空内存数据
      -- 初始化一下IP
      shared_data:set("ip_conn_num", 200);
      shared_data:set("ip_req_rate", 200);
  

    
    if rule_status ~= nil then -- 把规则状态设置回去
      shared_data :set("rule_status", rule_status);
    end

     local opts = {timeout=redisConfig.getTimeOut(),ip=redisConfig.getIp(),port=redisConfig.getPort(),pwd=redisConfig.getPwd()};
     local red = redis:new(opts);

     -- 加载IP黑名单
     
     local res,err = red:smembers("ipblacklist");
     if err then
        ngx.log(ngx.ERR,"加载IP黑名单失败", err)
     elseif not res then
        -- ngx.log(ngx.info,"IP黑名单未设置")
     else
      shared_data :set("ipblacklist",json.encode(res)); 
      for k2,word in pairs(res) do
        
        shared_data :set("ipblack"..word, true);
            
      end
      
        ngx.log(ngx.INFO,"加载IP黑名单成功");
    
      end

      -- 加载IP白名单 
       local res,err = red:smembers("ipwhitelist");
     if err then
        ngx.log(ngx.ERR,"加载IP白名单失败", err)
     elseif not res then
        -- ngx.log(ngx.info,"IP白名单未设置")
     else
      shared_data :set("ipwhitelist",json.encode(res)); 
      for k2,word in pairs(res) do
        
        shared_data :set("ipwhite"..word, true);
            
      end
      
        ngx.log(ngx.INFO,"加载IP白名单成功");
    
      end
    
      local ip_conn_num = 200;
      local ip_req_rate = 200;
      -- 加载IP连接数上限及请求频率上限
      local res,err = red:get("ipconnnum");
      if err then
        ngx.log(ngx.ERR,"加载IP连接数上限失败", err)
      elseif not res then
        -- ngx.log(ngx.info,"IP黑名单未设置")
      else
        ip_conn_num = tonumber(res);
      end
      -- 加载请求频率上限
      local res,err = red:get("ipreqrate");
      if err then
        ngx.log(ngx.ERR,"加载IP请求频率上限失败", err)
      elseif not res then
        -- ngx.log(ngx.info,"IP黑名单未设置")
      else
        ip_req_rate = tonumber(res);
      end
    
      shared_data:set("ip_conn_num", ip_conn_num);
      shared_data:set("ip_req_rate", ip_req_rate);
      
      ngx.log(ngx.WARN,"IP并发连接数上限设置为:",ip_conn_num);
      ngx.log(ngx.WARN,"IP每秒处理请求数上限为:",ip_req_rate);
      
      -- 加载降级规则
      local res,err = red:smembers("offline_req_list");
      if err then
         ngx.log(ngx.ERR,"加载降级规则失败",err);
       elseif not res then
         -- ngx.log(ngx.ERR,"协议黑名单未设置");
      else
        shared_data :set("offline_req_list",json.encode(res));
        for k2,word in pairs(res) do
          
          local res, err = red:get("offline_req_alertmsg:"..word)
          shared_data :set("offline_req_alertmsg_"..word, res);
              
        end
        
         ngx.log(ngx.INFO,"加载降级规则成功");
      
      end
      
      
      -- 加载限流规则
      local res,err = red:smembers("limit_req_list");
      if err then
         ngx.log(ngx.ERR,"加载限流规则失败",err);
       elseif not res then
         -- ngx.log(ngx.ERR,"协议黑名单未设置");
      else
        shared_data :set("limit_req_list",json.encode(res));
        for k2,word in pairs(res) do
          
          local res, err = red:get("limit_req_rate:"..word)
          shared_data :set("limit_req_rate_"..word, tonumber(res));
          
          local res, err = red:get("limit_req_alertmsg:"..word)
          shared_data :set("limit_req_alertmsg_"..word, res);
              
        end
         ngx.log(ngx.INFO,"加载限流规则成功");
      end
      
      -- 加载当前规则版本号
      local ruleVersion = "0";
      local res,err = red:get("ruleVersion");
      if err then
        ngx.log(ngx.ERR,"加载规则当前版本号失败", err)
      elseif not res then
      else
        ruleVersion = res;
        shared_data :set("ruleVersion",ruleVersion);
      end
      
      -- 降级用户取模值。0代表不降级用户。 1代表百分百降级。 2降级1/2
      local failUserNum = 0; 
      local res,err = red:get("failUserNum");
      if err then
        ngx.log(ngx.ERR,"加载降级用户取模值失败", err)
      elseif not res then
      else
        failUserNum = tonumber(res);
        shared_data :set("failUserNum",failUserNum);
      end
      
      -- 加载URL按用户降级规则
      local res,err = red:smembers("offline_url_list");
      if err then
         ngx.log(ngx.ERR,"加载用户降级规则失败",err);
       elseif not res then
         -- ngx.log(ngx.ERR,"协议黑名单未设置");
      else
        shared_data :set("offline_url_list",json.encode(res));
        for k2,word in pairs(res) do
          
          local res, err = red:get("offline_url_msg:"..word)
          shared_data :set("offline_url_msg_"..word, res);
              
        end
         ngx.log(ngx.INFO,"加载URL按用户降级规则成功");
      end
      
      
    
      shared_data :set("hasinit", true);
 
   
      ngx.log(ngx.WARN,"初始化规则到内存完成");
   
   
   end
    
end

return rule





