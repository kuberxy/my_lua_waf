local waf = require('init')
local limiter = require('limiter')

local function main()
    if waf.white_ip_filter() then
    elseif waf.white_url_filter() then
    elseif waf.black_ip_filter() then
    elseif waf.black_url_filter() then
    elseif waf.user_agent_filter() then
    elseif waf.cookie_filter() then
    elseif waf.get_args_filter() then
    elseif waf.post_args_filter() then
    else
        return
    end
end

main()
limiter.req_rate_limiter()