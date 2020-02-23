require 'config'

local io = require('io')
local finder = ngx.re.find

local _M = {}

-- get client ip address
function _M.get_client_ip()
    local ip = ngx.var.remote_addr
    if not ip then
        ip = 'none'
    end

    return ip
end

-- get rule from rule file
function _M.get_rule(file)
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
function _M.log(ip,filter,uri,data,rule)
    local cjson = require('cjson')
    
    local log_json_obj = {
        client_ip = ip,
        local_time = ngx.localtime(),
        server_name = ngx.var.server_name,
        user_agent = ngx.var.http_user_agent,
        attack_method = filter,
        req_uri = uri,
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

function _M.get_boundary()
    local client_content_type = ngx.req.get_headers()['content-type']
    if client_content_type then
        local match = finder(client_content_type, ";%s*boundary=\"([^\"]+)\"", "isjo")
        if not match then
            match = finder(client_content_type, ";%s*boundary=([^\",;]+)", "isjo")
        end

        return match
    end
end

function _M.filter_request_body(client_post_args)
    local post_args_list = _M.get_rule('post_args.rule')
    if next(post_args_list) then
        for _,rule_post_args in ipairs(post_args_list) then
            if finder(ngx.unescape_uri(client_post_args,rule,'isjo')) then
                if enable_attack_log == 'on' then
                    _M.log(_M.get_client_ip(),'post_args',ngx.var.request_uri,'client_post_args')
                end
                if log_mode ~= "on" then
                    ngx.exit(403)
                    return true
                end
            end
        end
    end
end

function _M.filter_file_suffix(file_suffix)
    if next(balck_file_suffix) then
        for _,rule_suffix in ipairs(balck_file_suffix) do
            if finder(file_suffix,rule_suffix,"jsjo") then
                if enable_attack_log == 'on' then
                    _M.log(_M.get_client_ip(),'post_args',ngx.var.request_uri,file_suffix)
                end
                if log_mode ~= "on" then
                    ngx.exit(403)
                    return true
                end
            end
        end
    end
end

return _M