-- enable waf and filter rules path. 
-- if log_mode is "on" then only record attack log but not reject request
enable_waf = 'on'
rule_dir = "/usr/local/openresty/nginx/waf/rules"
dry_mode = 'on'

-- record attack log and attack log path
enable_attack_log = 'on'
log_dir = '/usr/local/openresty/nginx/waf/logs'

-- enable white_ip filter
enable_white_ip_filter = 'on'

-- enable white_url filter
enable_white_url_filter = 'on'

-- enable black_ip filter
enable_black_ip_filter = 'on'

-- enable black_url filter
enable_black_url_filter = 'on'

-- enable user_agent filter
enable_user_agent_filter = 'on'

-- enable cookie_attack filter
enable_cookie_attack_filter = "on"

-- enable get_args filter
enable_get_args_filter = 'on'

-- enable post_args filter
enable_post_args_filter = 'on'
balck_file_suffix = {"php","jsp"}

-- enable request rate limiter
enable_req_rate_limiter = "on"