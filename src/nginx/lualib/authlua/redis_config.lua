-- reids连接配置
local ip = "r-bp143d381a65f5c4.redis.rds.aliyuncs.com";  --连接IP
local pwd = "Szy123456";    --密码
local port = 6379;
local timeout = 1;    --超时时间，单位秒


local session_ip = "r-bp14ea6d4710e314.redis.rds.aliyuncs.com";
local session_pwd = "r-bp14ea6d4710e314:3QDgKu327YQz";
local session_port = 6379;



local _M = {_VERSION = "0.1"}

function _M.getIp()
  return ip
end


function _M.getPwd()
  return pwd
end

function _M.getPort()
  return port
end

function _M.getTimeOut()
  return timeout
end


function _M.getSessionIp()
  return session_ip
end


function _M.getSessionPwd()
  return session_pwd
end

function _M.getSessionPort()
  return session_port
end



return _M