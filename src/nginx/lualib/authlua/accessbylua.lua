require("authlua.redis_config")
local redisConfig = require "authlua.redis_config"
local redis = require("authlua.redis_iresty")
local shared_data  = ngx.shared.shared_data;

local hasinit = shared_data :get("hasinit");
ngx.log(ngx.INFO,"是否初始化过呢",hasinit);

local function explode ( _str,seperator )
  local pos,arr= 0, {}
  for st, sp in function() return string.find( _str, seperator, pos, true ) end do
  table.insert( arr, string.sub( _str, pos, st-1 ) )
  pos = sp + 1
  end
  table.insert( arr, string.sub( _str, pos ) )
  return arr
end

-- 字符串切割函数开始
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
-- 字符串切割函数结束

if not hasinit then

   shared_data:flush_all(); --清空内存数据
   
   -- ngx.log(ngx.INFO,"初始化权限策略...");
   
   -- 加载IP黑名单
   local opts = {timeout=redisConfig.getTimeOut(),ip=redisConfig.getIp(),port=redisConfig.getPort(),pwd=redisConfig.getPwd()};
   local red = redis:new(opts);
   
   local res,err = red:smembers("ipblacklist");
   if err then
      ngx.log(ngx.ERR,"加载IP黑名单失败", err)
   elseif not res then
      ngx.log(ngx.ERR,"IP黑名单未设置")
  else
  
    for k2,word in pairs(res) do
      
      shared_data :set("ipblack"..word, true);
          
    end
    
     ngx.log(ngx.INFO,"加载IP黑名单成功");
  
  end
  
  
  -- 加载url黑名单
   local res,err = red:smembers("urlblacklist");
   if err then 
       ngx.log(ngx.ERR,"加载url黑名单失败", err)
   elseif not res then
      ngx.log(ngx.ERR,"url黑名单未设置")
  else
  
    for k2,word in pairs(res) do
      
      shared_data :set("urlblack"..word, true);
          
    end
    
     ngx.log(ngx.INFO,"加载url黑名单成功");
  
  end
  
    -- 加载账号黑名单
   local res,err = red:smembers("accountblacklist");
   if err then
     ngx.log(ngx.ERR,"加载账号黑名单失败", err)
   elseif not res then
      ngx.log(ngx.ERR,"账号黑名单未设置")
  else
  
    for k2,word in pairs(res) do
      
      shared_data :set("accountblack"..word, true);
          
    end
    
     ngx.log(ngx.INFO,"加载账号黑名单成功");
  
  end
  
  
  -- 加载会话黑名单
   local res,err = red:smembers("sessionblacklist");
   if err then
    ngx.log(ngx.ERR,"加载会话黑名单失败", err)
   elseif not res then
      ngx.log(ngx.ERR,"会话黑名单为空")
  else
  
    for k2,word in pairs(res) do
      
      shared_data :set("sessionblack"..word, true);
          
    end
    
     ngx.log(ngx.INFO,"加载会话黑名单成功");
  
  end
  
  -- 加载协议黑名单
  local res,err = red:smembers("reqcodeblacklist");
  if err then
     ngx.log(ngx.ERR,"加载协议黑名单失败",err);
   elseif not res then
      ngx.log(ngx.ERR,"协议黑名单未设置");
  else
  
    for k2,word in pairs(res) do
      
      local res, err = red:get("reqcodeblack:"..word)
      shared_data :set("reqcodeblack"..word, res);
          
    end
    
     ngx.log(ngx.INFO,"加载协议黑名单成功");
  
  end
  
  -- 加载流控信息   协议编号|倒霉数|返回内容, 协议编号|倒霉数|返回内容
  local res,err = red:get("fluidcontrol");
  if err then
  ngx.log(ngx.ERR,"加载流控信息失败",err);
  elseif not res then
      ngx.log(ngx.ERR,"流控信息未设置");
  else
    
         local fluidinfos  = lua_string_split(res,"*")  ;
         local size1 = table.getn(fluidinfos)  ;
        for i = 1,size1,1 do  
           if fluidinfos[i] ~= '' then
           
                local fluidinfo = fluidinfos[i];
               -- ngx.log(ngx.ERR,"单条流内容"..fluidinfo);
                
               local fluidinfoElements = lua_string_split(fluidinfo,"|")  ;
              --  ngx.log(ngx.ERR,"协议编号",fluidinfoElements[1]);
               -- ngx.log(ngx.ERR,"倒霉数",fluidinfoElements[2]);
               -- ngx.log(ngx.ERR,"返回内容",fluidinfoElements[3]);
               
               local s1 = "fluidinfo_dms_"..fluidinfoElements[1];
             -- ngx.log(ngx.ERR,"设置倒霉数的串",s1);
               
               shared_data :set("fluidinfo_dms_"..fluidinfoElements[1],fluidinfoElements[2]);
               shared_data :set("fluidinfo_fhnr_"..fluidinfoElements[1],fluidinfoElements[3]);
               
           end
        end 
    
  end
  
  -- 是否开启会话频率控制
  local res, err = red:get("opensessioncontrol")
  if res then
    shared_data :set("opensessioncontrol", res);
  end
  
  
  
  shared_data :set("hasinit", true);
   
end

   -- ngx.log(ngx.INFO,"执行策略过滤");
   -- 判断IP黑名单

   local ip = ngx.var.remote_addr;
   ngx.log(ngx.INFO,"用户IP:"..ip);

   local res = shared_data :get("ipblack"..ip);

   if res then
      ngx.log(ngx.ERR,"IP在黑名单，被拒绝".. ip)
      return ngx.exit(ngx.HTTP_FORBIDDEN);
   end

  -- 判断地址黑名单
  local url = ngx.var.document_uri ;
  local res = shared_data :get("urlblack"..url);
 ngx.log(ngx.INFO,"请求地址:".. url);
   if res then
      ngx.log(ngx.INFO,"地址在黑名单，被拒绝".. url)
      ngx.print("{\"returncode\":\"0\",\"message\":\"系统繁忙,请稍候再试\",\"body\":\"\"}");
        return ngx.exit(ngx.HTTP_OK);
   end

    -- 判断协议黑名单
    local request_method = ngx.var.request_method;
    local receive_headers = ngx.req.get_headers();
    local args = nil;
    if "GET" == request_method then
      args = ngx.req.get_uri_args()
    elseif "POST" == request_method then
      ngx.req.read_body();
      if string.sub(receive_headers["content-type"],1,20) == "multipart/form-data;" then
        -- ngx.log(ngx.INFO,"用了form-data"); -- 用了这个解析参数比较麻烦
        args = {};
        local body_data = ngx.req.get_body_data();
        local new_body_data = {};
        local boundary = "--" .. string.sub(receive_headers["content-type"],31)
        local body_data_table = explode(tostring(body_data),boundary)
        local first_string = table.remove(body_data_table,1)
        local last_string = table.remove(body_data_table)
        for i,v in ipairs(body_data_table) do
          local start_pos,end_pos,capture,capture2 = string.find(v,'Content%-Disposition: form%-data; name="(.+)"; filename="(.*)"')     
          if not start_pos then
            local t = explode(v,"\r\n\r\n");
            local temp_param_name = string.sub(t[1],41,-2)
            local temp_param_value = string.sub(t[2],1,-3)
            args[temp_param_name] = temp_param_value
         else
          file_args[capture] = capture2
          table.insert(new_body_data,v)
         end
        table.insert(new_body_data,1,first_string)
        table.insert(new_body_data,last_string)
        body_data = table.concat(new_body_data,boundary);
        
      end
          
      else
        args = ngx.req.get_post_args()
      end
    end
    local json = require(require("ffi").os == "Windows" and "dkjson" or "cjson.safe")
    local reqcode = 0;
    local body = nil;
    -- 防止无参数报错
    if  args then
            if args["reqcode"] then
              reqcode = args["reqcode"];
              body = args["body"];
            end
    end
    ngx.log(ngx.INFO,"当前请求协议",reqcode);
    ngx.log(ngx.INFO,"当前请求body",body);
    local res = shared_data :get("reqcodeblack"..reqcode);

    if  res then
        ngx.log(ngx.INFO,"协议",reqcode,"在黑名单,返回内容是:", res);
        ngx.print(res);
        return ngx.exit(ngx.HTTP_OK);
    end
    
    
    -- 拦截登陆协议，判断账号是否已被封的
    if reqcode == "1000" or reqcode == "1058" then
     -- ngx.log(ngx.INFO,"登陆协议来咯",reqcode,"body是",body);
      
      local t    = json.decode(body);
      if t then
         -- ngx.log(ngx.INFO,"账号是:",t["account"]);
          
           local res = shared_data :get("accountblack"..t["account"]);
          
             if res then
                ngx.log(ngx.ERR,"账号在黑名单，拒绝".. t["account"])
                ngx.print("{\"returncode\":\"0\",\"message\":\"该账号暂时无法登陆,请稍候再试\",\"body\":\"\"}");
                  return ngx.exit(ngx.HTTP_OK);
             end
      end
      
      
    end
    -- HMS的登陆请求拦截
    if url == "/sys/login.action" then
        
        local logno = args["logno"];
        if logno then
            local res = shared_data :get("accountblack"..logno);
             if res then
                ngx.log(ngx.ERR,"HMS账号在黑名单，拒绝访问:".. logno)
                ngx.print("该账号暂时无法登陆,请稍候再试");
                  return ngx.exit(ngx.HTTP_OK);
             end
        end
        
    end
    
    
    local sss = "fluidinfo_dms_"..reqcode;
     -- ngx.log(ngx.ERR,"倒霉数的串",sss);
    -- 进行流控
    local  dms = shared_data :get(sss);
    -- ngx.log(ngx.ERR,"倒霉数",dms);
    
    if dms ~= nil then
    
         local accessnum = shared_data :get("accessnum_"..reqcode);
        
        if accessnum == nil then
           accessnum = 0;
        end
        
        accessnum = accessnum+1;
        
        if  accessnum > 100000 then
        
              accessnum = 0;
          
        end
        
         shared_data :set("accessnum_"..reqcode,accessnum);
        
         ngx.log(ngx.ERR,"访问第X次：",accessnum);
        
        -- 倒霉
        if accessnum%dms == 0 then
                ngx.print(shared_data :get("fluidinfo_fhnr_"..reqcode));
                return ngx.exit(ngx.HTTP_OK);
        end
    
    
    
    end
    
    -- 判断会话黑名单
    local sessionId  = tostring(ngx.var.cookie_JSESSIONID);
    local res = shared_data :get("sessionblack"..sessionId);

   if res then
      ngx.log(ngx.ERR,"会话在黑名单，拒绝访问".. sessionId)
      ngx.print("{\"returncode\":\"0\",\"message\":\"您的访问过于频繁，请稍候再试\",\"body\":\"\"}");
      return ngx.exit(ngx.HTTP_OK);
   end
    
    
    -- 会话控制
    local whoami  = tostring(ngx.var.cookie_WHOAMI);
    ngx.log(ngx.INFO,"whoami:",whoami);
    local res = shared_data :get("opensessioncontrol");
    if whoami ~= "iamztjy" and res ~= nil then   
      local controlElements = lua_string_split(res,"|")  ;
      local controlSeconds = controlElements[1];
      local controlTimes = tonumber(controlElements[2]);
      
      ngx.log(ngx.INFO,"有进行会话控制:",res,"秒数",controlSeconds,"次数",controlTimes);
      
      local sessionId  = tostring(ngx.var.cookie_JSESSIONID);
      -- ngx.log(ngx.ERR,"当前请求的会话ID是:",sessionId);
      
      local ext = url:match(".+%.(%w+)$");
      -- ngx.log(ngx.INFO,"当前地址后缀:",ext);
      
      if sessionId ~= 'null' and (ext == 'jsp' or ext == 'action' or not ext) then
         local opts = {timeout=redisConfig.getTimeOut(),ip=redisConfig.getIp(),port=redisConfig.getPort(),pwd=redisConfig.getPwd()};
         local red = redis:new(opts);
         local res,err = red:incr("sessioncontrol:"..sessionId);
         if not res then
            ngx.log(ngx.ERR,"会话频率控制失败", err)
         else
            ngx.log(ngx.ERR,"会话", sessionId,"当前访问次数:",res);
            -- 首次访问设置有效期
            if res == 1 then
             -- ngx.log(ngx.ERR,"设置有效期",controlSeconds);
              red:expire("sessioncontrol:"..sessionId,controlSeconds);
            elseif controlTimes and res >  controlTimes then
              ngx.log(ngx.ERR,"超出访问次数啦,异常sessionId: ",sessionId);
              shared_data :set("sessionblack"..sessionId,true);
              red:sadd("sessionblacklist",sessionId);
              ngx.print("{\"returncode\":\"0\",\"message\":\"您的访问过于频繁，请稍候再试\",\"body\":\"\"}");
              return ngx.exit(ngx.HTTP_OK);
            else
             -- ngx.log(ngx.ERR,"进入了else");
            end
            
         end
      end
      
      
    end
    
    
-- 打印埋点traceId

local traceId = ngx.var.tid;
ngx.log(ngx.CRIT,"start--traceId:"..traceId);


