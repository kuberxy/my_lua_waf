local enable_cc_attack_filter = "on"
local log_dir = '/tmp'
local cc_rate = "10/60"

-- get client ip address
local function get_client_ip()
    local ip = ngx.var.remote_addr
    if not ip then
        ip = 'none'
    end

    return ip
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

function cc_attack_filter()
    if enable_cc_attack_filter == "on" then
        local client_ip = get_client_ip()
        local cc_key =  client_ip .. ngx.var.uri
        local cc_count = tonumber(string.match(cc_rate,'(.*)/'))
        local cc_seconds = tonumber(string.match(cc_rate,'/(.*)'))

        local cc_counter = ngx.shared.cc_counter_store
        local current_rate,_ = cc_counter:get(cc_key)
        if current_rate then
            if current_rate > cc_count then
                log(client_ip,'cc_attack',ngx.var.uri,'-',cc_rate)
                ngx.exit(403)
                return true
            else
                cc_counter:incr(cc_key,1)
            end
        else
            cc_counter:set(cc_key,1,cc_seconds)
        end
    end
end

cc_attack_filter()