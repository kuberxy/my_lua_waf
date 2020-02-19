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

local function get_args_filter()
    if enable_get_args_filter == 'on' then
        local ngxmatch = ngx.re.find
        local client_get_args_table = ngx.req.get_uri_args()
        if next(client_get_args_table) then
            local get_args_table = get_rule('get_args.rule')
            if next(get_args_table) then
                for key,val in pairs(client_get_args_table) do
                    if type(val) == 'table' then
                        client_get_args = table.concat(val, " ")
                    else
                        client_get_args = tostring(val)
                    end
                    if client_get_args and client_get_args ~= "" then
                        for _,rule_get_args in ipairs(get_args_table) do
                            if ngxmatch(unescape(client_get_args),rule,"isjo") then
                                log(get_client_ip(),'get_args',ngx.var.request_uri,'-',rule_get_args)
                                exit(403)
                                return true
                            end
                        end
                    end
                end
            end
        end
    end
end