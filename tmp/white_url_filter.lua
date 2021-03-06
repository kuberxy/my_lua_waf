local enable_white_url_filter = 'on'
local rule_dir = "./rules"
local log_dir = '/tmp'

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
    local file = io.open(log_name,"a")
    if file then
        file:write(log_line.."\n")
        file:flush()
        file:close()
    end
end

local function white_url_filter()
    if enable_white_url_filter == "on" then
        local client_request_uri = ngx.var.request_uri
        local url_white_list = get_rule('whiteurl.rule')

        if next(url_white_list) then
            local rulematcher = ngx.re.find
            for _,rule_url = ipairs(url_white_list) do
                if rulematcher(client_request_uri,rule_url,'jo') then
                    log(get_client_ip(),'white_url',ngx.var.request_uri,'-',rule_url)
                    return true
                end
            end
        end
    end
end