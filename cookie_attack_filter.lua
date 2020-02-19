enable_cookie_attack_filter = "on"
local rule_dir = "./rules"
local log_dir = '/tmp'
-- local ngx = {
--    var = { remote_addr = '192.168.1.1',http_user_agent = 'curl', server_name = '127.0.0.1',http_cookie='attack'},
--    localtime = function() return '2020-02-16 18:24:00' end,
--    today = function() return '2020-02-16' end,
--    var_request_uri = '/index.html',
--    exit = function(num) print(num) end,
--    re = {find = function() return true end,}
-- 
-- }

-- get client ip address
local function get_client_ip()
    local ip = ngx.var.remote_addr
    if not ip then
        ip = 'none'
    end

    return ip
end

-- get rule from rule file
local function get_rule(file)
    local io = require('io')

    local rule_table = {}
    local rule_file = io.open(rule_dir .. '/' .. file,r)
    if rule_file then
        for line in rule_file:lines() do
            table.insert(rule_table,line)
        end
        rule_file:close()
    end
    
    return rule_table
end

-- record log by json format to file
local function log(ip,filter,uri,data,rule)
    local io = require('io')
    local cjson = require('cjson')

    local log_json_obj = {
        client_ip = ip,
        local_time = ngx.localtime(),
        server_name = ngx.var.server_name,
        user_agent = ngx.var.http_user_agent,
        attack_method = filter,
        req_uri = uri,
        req_data = data,
        match_rule = rule,
    }
    local log_line = cjson.encode(log_json_obj)

    local log_name = log_dir .. '/' .. 'waf_' .. ngx.today() .. '.log'
    local file = io.open(log_name,'a')
    if file then
        file:write(log_line..'\n')
        file:flush()
        file:close()
    end
end

local function cookie_attack_filter()
    if enable_cookie_attack_filter == "on" then
        local client_cookie = ngx.var.http_cookie
        if client_cookie then
            local cookie_rule_list = get_rule('cookie.rule')
            if next(cookie_rule_list) then
                local rulematcher = ngx.re.find
                for _,rule_cookie in ipairs(cookie_rule_list) do
                    if rulematcher(client_cookie,rule_cookie,'jo') then
                        log(get_client_ip(),'cookie',ngx.var.uri,'-',rule_cookie)
                        ngx.exit(403)
                        return true
                    end
                end
            end
        end
    end
end

cookie_attack_filter()
