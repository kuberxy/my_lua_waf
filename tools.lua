require 'config'

local io = require('io')
local finder = ngx.re.find

local _M = {}

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
function _M.log(ip,filter,uri,rule)
    local cjson = require('cjson')
    
    local log_json_obj = {
        client_ip = ip,
        local_time = ngx.localtime(),
        user_agent = ngx.var.http_user_agent,
        match_filter = filter,
        req_uri = uri,
        match_rule = rule,
    }
    local log_line = cjson.encode(log_json_obj)

    local log_name = log_dir .. '/' .. 'waf-' .. ngx.today() .. '.log'
    local file = io.open(log_name,"a")
    if file then
        file:write(log_line.."\n")
        file:flush()
        file:close()
    end
end

function _M.get_boundary()
    local client_content_type = ngx.req.get_headers()['content-type']
    if not client_content_type then
        return
    end

    if type(client_content_type) == "table" then
        client_content_type = client_content_type[1]
    end

    local match = finder(client_content_type, ";%s*boundary=\"([^\"]+)\"", "isjo")
    if not match then
        match = finder(client_content_type, ";%s*boundary=([^\",;]+)", "isjo")
    end
    
    return match
end

function _M.filter_request_body(client_post_args)
    local post_args_rules = _M.get_rule('post_args.rule')
    if not next(post_args_rules) then
        return
    end

    for _,rule_post_args in ipairs(post_args_rules) do
        if finder(ngx.unescape_uri(client_post_args),rule_post_args,'isjo') then
            if enable_attack_log == 'on' then
                _M.log(ngx.var.remote_addr,'post_args',ngx.var.request_uri,rule_post_args)
            end
            if dry_mode ~= "on" then
                ngx.exit(403)
                return true
            end
        end
    end
end

function _M.filter_file_suffix(file_suffix)
    if not next(black_file_suffix) then
        return
    end

    for _,rule_suffix in ipairs(black_file_suffix) do
        if finder(file_suffix,rule_suffix,"jsjo") then
            if enable_attack_log == 'on' then
                _M.log(_M.get_client_ip(),'post_args',ngx.var.request_uri,file_suffix)
            end
            if dry_mode ~= "on" then
                ngx.exit(403)
                return true
            end
        end
    end
end

return _M