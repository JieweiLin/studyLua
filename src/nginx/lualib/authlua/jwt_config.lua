local secret = "";

local _M = {_VERSION = "0.1"}

function _M.getSecret()
  return secret
end

local host = "";
local port = 3306;
local database = "";
local user = "";
local password = "";


function _M.getHost()
  return host
end

function _M.getPort()
  return port
end

function _M.getDatabase()
  return database
end

function _M.getUser()
  return user
end

function _M.getPassword()
  return password
end


return _M
