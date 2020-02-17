local enable_white_ip_filter = 'on'
local rule_dir = "./rules"
local log_dir = '/tmp'
-- local ngx = {
--   var = { remote_addr = '192.168.1.1',http_user_agent = 'curl', server_name = '127.0.0.1'},
--   localtime = function() return '2020-02-16 18:24:00' end,
--   today = function() return '2020-02-16' end,
--   var_request_uri = '/index.html',
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
    local rule_file = io.open(rule_dir .. '/'.. file,r)
    if rule_file then
        for line in rule_file:lines() do
            table.insert(rule_table,line)
        end

    end
    rule_file:close()

    return rule_table
end

-- record log by json format to file
local function log(ip,filter,uri,data,ruletag)
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
        rule_tab = rultetag,
    }
    local log_line = cjson.encode(log_json_obj)

    local log_name = log_dir .. '/' .. 'waf_' .. ngx.today() .. '.log'
    local file = io.open(log_name,"a")
    if file then
        file:write(log_line.."\n")
        file:flush()
    end
    file:close()
end

-- filter client ip whether in ip white list
local function white_ip_filter()
    if enable_white_ip_filter == 'on' then
        local client_ip = get_client_ip()
        local ip_white_list = get_rule('whiteip.rule')  -- return a table

        if next(ip_white_list) then
            for _,rule_ip in ipairs(ip_white_list) do
                if client_ip == rule_ip then
                    log(client_ip,'white_ip',ngx.var_request_uri,'-','-')
                    return true
                end
            end
        end
    end
end

white_ip_filter()
