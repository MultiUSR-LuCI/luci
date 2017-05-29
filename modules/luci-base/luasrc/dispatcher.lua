-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Copyright 2008-2015 Jo-Philipp Wich <jow@openwrt.org>
-- Licensed to the public under the Apache License 2.0.

local fs = require "nixio.fs"
local sys = require "luci.sys"
local util = require "luci.util"
local http = require "luci.http"
local nixio = require "nixio", require "nixio.util"

module("luci.dispatcher", package.seeall)
context = util.threadlocal()
uci = require "luci.model.uci"
i18n = require "luci.i18n"
_M.fs = fs

authenticator = {}

-- Index table
local index = nil

-- Fastindex
local fi


function build_url(...)
	local path = {...}
	local url = { http.getenv("SCRIPT_NAME") or "" }

	local p
	for _, p in ipairs(path) do
		if p:match("^[a-zA-Z0-9_%-%.%%/,;]+$") then
			url[#url+1] = "/"
			url[#url+1] = p
		end
	end

	if #path == 0 then
		url[#url+1] = "/"
	end

	return table.concat(url, "")
end

function node_visible(node)
   if node then
	  return not (
		 (not node.title or #node.title == 0) or
		 (not node.target or node.hidden == true) or
		 (type(node.target) == "table" and node.target.type == "firstchild" and
		  (type(node.nodes) ~= "table" or not next(node.nodes)))
	  )
   end
   return false
end

function node_childs(node)
	local rv = { }
	if node then
		local k, v
		for k, v in util.spairs(node.nodes,
			function(a, b)
				return (node.nodes[a].order or 100)
				     < (node.nodes[b].order or 100)
			end)
		do
			if node_visible(v) then
				rv[#rv+1] = k
			end
		end
	end
	return rv
end


function error404(message)
	http.status(404, "Not Found")
	message = message or "Not Found"

	require("luci.template")
	if not util.copcall(luci.template.render, "error404") then
		http.prepare_content("text/plain")
		http.write(message)
	end
	return false
end

function error500(message)
	util.perror(message)
	if not context.template_header_sent then
		http.status(500, "Internal Server Error")
		http.prepare_content("text/plain")
		http.write(message)
	else
		require("luci.template")
		if not util.copcall(luci.template.render, "error500", {message=message}) then
			http.prepare_content("text/plain")
			http.write(message)
		end
	end
	return false
end

function authenticator.htmlauth(validator, accs, default)
	local user = http.formvalue("luci_username")
	local pass = http.formvalue("luci_password")

	if user and validator(user, pass) then
		return user
	end

	require("luci.i18n")
	require("luci.template")
	context.path = {}
	http.status(403, "Forbidden")
	luci.template.render("sysauth", {duser=default, fuser=user})

	return false

end

function httpdispatch(request, prefix)
	http.context.request = request

	local r = {}
	context.request = r

	local pathinfo = http.urldecode(request:getenv("PATH_INFO") or "", true)

	if prefix then
		for _, node in ipairs(prefix) do
			r[#r+1] = node
		end
	end

	for node in pathinfo:gmatch("[^/]+") do
		r[#r+1] = node
	end

	local stat, err = util.coxpcall(function()
		dispatch(context.request)
	end, error500)

	http.close()

	--context._disable_memtrace()
end

local function require_post_security(target)
	if type(target) == "table" then
		if type(target.post) == "table" then
			local param_name, required_val, request_val

			for param_name, required_val in pairs(target.post) do
				request_val = http.formvalue(param_name)

				if (type(required_val) == "string" and
				    request_val ~= required_val) or
				   (required_val == true and
				    (request_val == nil or request_val == ""))
				then
					return false
				end
			end

			return true
		end

		return (target.post == true)
	end

	return false
end

function test_post_security()
	if http.getenv("REQUEST_METHOD") ~= "POST" then
		http.status(405, "Method Not Allowed")
		http.header("Allow", "POST")
		return false
	end

	if http.formvalue("token") ~= context.authtoken then
		http.status(403, "Forbidden")
		luci.template.render("csrftoken")
		return false
	end

	return true
end

function dispatch(request)
	--context._disable_memtrace = require "luci.debug".trap_memtrace("l")
	local ctx = context
	ctx.path = request

	local conf = require "luci.config"
	assert(conf.main,
		"/etc/config/luci seems to be corrupt, unable to find section 'main'")

	local i18n = require "luci.i18n"
	local lang = conf.main.lang or "auto"
	if lang == "auto" then
		local aclang = http.getenv("HTTP_ACCEPT_LANGUAGE") or ""
		for lpat in aclang:gmatch("[%w-]+") do
			lpat = lpat and lpat:gsub("-", "_")
			if conf.languages[lpat] then
				lang = lpat
				break
			end
		end
	end
	if lang == "auto" then
		lang = i18n.default
	end
	i18n.setlanguage(lang)

	local c = ctx.tree
	local stat
	if not c then
		c = createtree()
	end

	local track = {}
	local args = {}
	ctx.args = args
	ctx.requestargs = ctx.requestargs or args
	local n
	local preq = {}
	local freq = {}

	for i, s in ipairs(request) do
		preq[#preq+1] = s
		freq[#freq+1] = s
		c = c.nodes[s]
		n = i
		if not c then
			break
		end

		util.update(track, c)

		if c.leaf then
			break
		end
	end

	if c and c.leaf then
		for j=n+1, #request do
			args[#args+1] = request[j]
			freq[#freq+1] = request[j]
		end
	end

	ctx.requestpath = ctx.requestpath or freq
	ctx.path = preq

	if track.i18n then
		i18n.loadc(track.i18n)
	end

	-- Init template engine
	if (c and c.index) or not track.notemplate then
		local tpl = require("luci.template")
		local media = track.mediaurlbase or luci.config.main.mediaurlbase
		if not pcall(tpl.Template, "themes/%s/header" % fs.basename(media)) then
			media = nil
			for name, theme in pairs(luci.config.themes) do
				if name:sub(1,1) ~= "." and pcall(tpl.Template,
				 "themes/%s/header" % fs.basename(theme)) then
					media = theme
				end
			end
			assert(media, "No valid theme found")
		end

		local function _ifattr(cond, key, val)
			if cond then
				local env = getfenv(3)
				local scope = (type(env.self) == "table") and env.self
				if type(val) == "table" then
					if not next(val) then
						return ''
					else
						val = util.serialize_json(val)
					end
				end
				return string.format(
					' %s="%s"', tostring(key),
					util.pcdata(tostring( val
					 or (type(env[key]) ~= "function" and env[key])
					 or (scope and type(scope[key]) ~= "function" and scope[key])
					 or "" ))
				)
			else
				return ''
			end
		end

		tpl.context.viewns = setmetatable({
		   write       = http.write;
		   include     = function(name) tpl.Template(name):render(getfenv(2)) end;
		   translate   = i18n.translate;
		   translatef  = i18n.translatef;
		   export      = function(k, v) if tpl.context.viewns[k] == nil then tpl.context.viewns[k] = v end end;
		   striptags   = util.striptags;
		   pcdata      = util.pcdata;
		   media       = media;
		   theme       = fs.basename(media);
		   resource    = luci.config.main.resourcebase;
		   ifattr      = function(...) return _ifattr(...) end;
		   attr        = function(...) return _ifattr(true, ...) end;
		   url         = build_url;
		}, {__index=function(table, key)
			if key == "controller" then
				return build_url()
			elseif key == "REQUEST_URI" then
				return build_url(unpack(ctx.requestpath))
			elseif key == "token" then
				return ctx.authtoken
			else
				return rawget(table, key) or _G[key]
			end
		end})
	end

	track.dependent = (track.dependent ~= false)
	assert(not track.dependent or not track.auto,
		"Access Violation\nThe page at '" .. table.concat(request, "/") .. "/' " ..
		"has no parent node so the access to this location has been denied.\n" ..
		"This is a software bug, please report this message at " ..
		"https://github.com/openwrt/luci/issues"
	)

	if track.sysauth then
		local authen = type(track.sysauth_authenticator) == "function"
		 and track.sysauth_authenticator
		 or authenticator[track.sysauth_authenticator]

		local def  = (type(track.sysauth) == "string") and track.sysauth
		local accs = def and {track.sysauth} or track.sysauth
		local sess = ctx.authsession
		if not sess then
			sess = http.getcookie("sysauth")
			sess = sess and sess:match("^[a-f0-9]*$")
		end

		local sdat = (util.ubus("session", "get", { ubus_rpc_session = sess }) or { }).values
		local user, token

		if sdat then
			user = sdat.user
			token = sdat.token
		else
			local eu = http.getenv("HTTP_AUTH_USER")
			local ep = http.getenv("HTTP_AUTH_PASS")
			if eu and ep and sys.user.checkpasswd(eu, ep) then
				authen = function() return eu end
			end
		end

		if not util.contains(accs, user) then
			if authen then
				local user, sess = authen(sys.user.checkpasswd, accs, def)
				local token
				if not user or not util.contains(accs, user) then
					return
				else
					if not sess then
						local sdat = util.ubus("session", "create", { timeout = tonumber(luci.config.sauth.sessiontime) })
						if sdat then
							token = sys.uniqueid(16)
							util.ubus("session", "set", {
								ubus_rpc_session = sdat.ubus_rpc_session,
								values = {
									user = user,
									token = token,
									section = sys.uniqueid(16)
								}
							})
							sess = sdat.ubus_rpc_session
						end
					end

					if sess and token then
						http.header("Set-Cookie", 'sysauth=%s; path=%s' %{ sess, build_url() })

						ctx.authsession = sess
						ctx.authtoken = token
						ctx.authuser = user

						http.redirect(build_url(unpack(ctx.requestpath)))
					end
				end
			else
				http.status(403, "Forbidden")
				return
			end
		else
			ctx.authsession = sess
			ctx.authtoken = token
			ctx.authuser = user
		end
	end

	if c and require_post_security(c.target) then
		if not test_post_security(c) then
			return
		end
	end

	if track.setgroup then
		sys.process.setgroup(track.setgroup)
	end

	if track.setuser then
		sys.process.setuser(track.setuser)
	end

	local target = nil
	if c then
		if type(c.target) == "function" then
			target = c.target
		elseif type(c.target) == "table" then
			target = c.target.target
		end
	end

	if c and (c.index or type(target) == "function") then
		ctx.dispatched = c
		ctx.requested = ctx.requested or ctx.dispatched
	end

	if c and c.index then
		local tpl = require "luci.template"

		if util.copcall(tpl.render, "indexer", {}) then
			return true
		end
	end

	if type(target) == "function" then
		util.copcall(function()
			local oldenv = getfenv(target)
			local module = require(c.module)
			local env = setmetatable({}, {__index=

			function(tbl, key)
				return rawget(tbl, key) or module[key] or oldenv[key]
			end})

			setfenv(target, env)
		end)

		local ok, err
		if type(c.target) == "table" then
			ok, err = util.copcall(target, c.target, unpack(args))
		else
			ok, err = util.copcall(target, unpack(args))
		end
		assert(ok,
		       "Failed to execute " .. (type(c.target) == "function" and "function" or c.target.type or "unknown") ..
		       " dispatcher target for entry '/" .. table.concat(request, "/") .. "'.\n" ..
		       "The called action terminated with an exception:\n" .. tostring(err or "(unknown)"))
	else
		local root = node()
		if not root or not root.target then
			error404("No root node was registered, this usually happens if no module was installed.\n" ..
			         "Install luci-mod-admin-full and retry. " ..
			         "If the module is already installed, try removing the /tmp/luci-indexcache file.")
		else
			error404("No page is registered at '/" .. table.concat(request, "/") .. "'.\n" ..
			         "If this url belongs to an extension, make sure it is properly installed.\n" ..
			         "If the extension was recently installed, try removing the /tmp/luci-indexcache file.")
		end
	end
end

function createindex()
	local controllers = { }
	local base = "%s/controller/" % util.libpath()
	local _, path

	for path in (fs.glob("%s*.lua" % base) or function() end) do
		controllers[#controllers+1] = path
	end

	for path in (fs.glob("%s*/*.lua" % base) or function() end) do
		controllers[#controllers+1] = path
	end

	if indexcache then
		local cachedate = fs.stat(indexcache, "mtime")
		if cachedate then
			local realdate = 0
			for _, obj in ipairs(controllers) do
				local omtime = fs.stat(obj, "mtime")
				realdate = (omtime and omtime > realdate) and omtime or realdate
			end

			if cachedate > realdate and sys.process.info("uid") == 0 then
				assert(
					sys.process.info("uid") == fs.stat(indexcache, "uid")
					and fs.stat(indexcache, "modestr") == "rw-------",
					"Fatal: Indexcache is not sane!"
				)

				index = loadfile(indexcache)()
				return index
			end
		end
	end

	index = {}

	for _, path in ipairs(controllers) do
		local modname = "luci.controller." .. path:sub(#base+1, #path-4):gsub("/", ".")
		local mod = require(modname)
		assert(mod ~= true,
		       "Invalid controller file found\n" ..
		       "The file '" .. path .. "' contains an invalid module line.\n" ..
		       "Please verify whether the module name is set to '" .. modname ..
		       "' - It must correspond to the file path!")

		local idx = mod.index
		assert(type(idx) == "function",
		       "Invalid controller file found\n" ..
		       "The file '" .. path .. "' contains no index() function.\n" ..
		       "Please make sure that the controller contains a valid " ..
		       "index function and verify the spelling!")

		index[modname] = idx
	end

	if indexcache then
		local f = nixio.open(indexcache, "w", 600)
		f:writeall(util.get_bytecode(index))
		f:close()
	end
end

-- Build the index before if it does not exist yet.
function createtree()
	if not index then
		createindex()
	end

	local ctx  = context
	local tree = {nodes={}, inreq=true}
	local modi = {}

	ctx.treecache = setmetatable({}, {__mode="v"})
	ctx.tree = tree
	ctx.modifiers = modi

	-- Load default translation
	require "luci.i18n".loadc("base")

	local scope = setmetatable({}, {__index = luci.dispatcher})

	for k, v in pairs(index) do
		scope._NAME = k
		setfenv(v, scope)
		v()
	end

	local function modisort(a,b)
		return modi[a].order < modi[b].order
	end

	for _, v in util.spairs(modi, modisort) do
		scope._NAME = v.module
		setfenv(v.func, scope)
		v.func()
	end

	return tree
end

function modifier(func, order)
	context.modifiers[#context.modifiers+1] = {
		func = func,
		order = order or 0,
		module
			= getfenv(2)._NAME
	}
end

function assign(path, clone, title, order)
	local obj  = node(unpack(path))
	obj.nodes  = nil
	obj.module = nil

	obj.title = title
	obj.order = order

	setmetatable(obj, {__index = _create_node(clone)})

	return obj
end

function entry(path, target, title, order)
	local c = node(unpack(path))

	c.target = target
	c.title  = title
	c.order  = order
	c.module = getfenv(2)._NAME

	return c
end

-- enabling the node.
function get(...)
	return _create_node({...})
end

function node(...)
	local c = _create_node({...})

	c.module = getfenv(2)._NAME
	c.auto = nil

	return c
end

--## Function to chk if the user has acces to the menu entry ##--
local function chk(name)
  	local mu = require ("luci.users")
	local user = get_user()
	local menus = mu.get_menus(user) 
	if user == "root" or user == "nobody" then return false end
	if name == "admin.status" or name == "admin.status.overview" 
	or name == "admin.logout" or name == "admin" 
	or name:match("admin.uci") or name:match("servicectl") 
	or name:match("admin.users") then return false end
	if not util.contains(menus, name) then return true end

	return false
end

function _create_node(path)
        local name = table.concat(path, ".")
	local c

	--## Here is where the magic happens :) ##--
	if #path == 0 then
		return context.tree
	elseif name and chk(name) then
		c = {nodes={}, auto=true}
	else
		c = context.treecache[name]
	end

	if not c then
		local last = table.remove(path)
		local parent = _create_node(path)

		c = {nodes={}, auto=true}
		-- the node is "in request" if the request path matches
		-- at least up to the length of the node path
		if parent.inreq and context.path[#path+1] == last then
		  c.inreq = true
		end
		parent.nodes[last] = c
                
		context.treecache[name] = c
		
        end

	return c
end

-- Subdispatchers --

function _firstchild()
   local path = { unpack(context.path) }
   local name = table.concat(path, ".")
   local node = context.treecache[name]

   local lowest
   if node and node.nodes and next(node.nodes) then
	  local k, v
	  for k, v in pairs(node.nodes) do
		 if not lowest or
			(v.order or 100) < (node.nodes[lowest].order or 100)
		 then
			lowest = k
		 end
	  end
   end

   assert(lowest ~= nil,
		  "The requested node contains no childs, unable to redispatch")

   path[#path+1] = lowest
   dispatch(path)
end

function firstchild()
   return { type = "firstchild", target = _firstchild }
end

--## Function to compare the current index from alias to the user config ##--
--## If the current index is not present then we assign the first available sub menu as index ##--
local function get_alias(user,menu,index,path)
	local conf = "users"
  	local uci  = uci.cursor()
	local tbuf = {}
  	local buf = {}
	
	--## update the users activity file ##--
	if user ~= "root" and user ~= "nobody" then 
		local fname = "/home/"..user.."/activity"
        	local file = io.open(fname, "w+")
        	file:write(os.date() .."\n")
		file:close()
	end

  	local ent = uci:get(conf, user, menu.."_subs")

	if ent then
		for word in string.gmatch(ent, '([^,]+)') do
			tbuf[#tbuf+1] = word
		end
	end

	for i,v in pairs(tbuf) do
		if path == v then
			for word in string.gmatch(path, '([^.]+)') do
				buf[#buf+1] = word
			end
			return buf 
		end
	end
	
	for i,v in pairs(tbuf) do	
		path = path:gsub(index, "")
		local snip = v:sub(0,path:len(),-1)
		if path == snip then
			path = path..v:sub(path:len()+1,-1)
			break
		end
	end

	for word in string.gmatch(path, '([^.]+)') do
		buf[#buf+1] = word
	end

	return buf		
end

--## Function to prep the table from alias so we can process it and compare it with the users config ##-- 
local function prep_alias(user, ...)
	local buf = {...}
	local req = {}
	if #buf < 2 then return {...} end
 
	local index = buf[#buf]
	local menu = buf[2]
	local path
	if index == "overview" then return {...} end
	for i,v in pairs(buf) do
		if not path then
			path = v
		else
			path = path .. "." .. v
		end
	end

	local req = get_alias(user,menu,index,path)

	if #req == 0 then 
		return {...}
	else
		return req
	end
end

function alias(...)
	local user = get_user()
	local req
	--## if user is not root, the index may have changed so ##--
	--## we need to get the first sub-menu and make it the index ##--
	if user ~= "root" and user ~= "nobody" then
		req = prep_alias(user, ...)
	else
		req = {...}
	end

	return function(...)
		for _, r in ipairs({...}) do
			req[#req+1] = r
		end

		dispatch(req)
	end
end

function rewrite(n, ...)
	local req = {...}
	return function(...)
		local dispatched = util.clone(context.dispatched)

		for i=1,n do
			table.remove(dispatched, 1)
		end

		for i, r in ipairs(req) do
			table.insert(dispatched, i, r)
		end

		for _, r in ipairs({...}) do
			dispatched[#dispatched+1] = r
		end

		dispatch(dispatched)
	end
end


local function _call(self, ...)
	local func = getfenv()[self.name]
	assert(func ~= nil,
	       'Cannot resolve function "' .. self.name .. '". Is it misspelled or local?')

	assert(type(func) == "function",
	       'The symbol "' .. self.name .. '" does not refer to a function but data ' ..
	       'of type "' .. type(func) .. '".')

	if #self.argv > 0 then
		return func(unpack(self.argv), ...)
	else
		return func(...)
	end
end

function call(name, ...)
	return {type = "call", argv = {...}, name = name, target = _call}
end

function post_on(params, name, ...)
	return {
		type = "call",
		post = params,
		argv = { ... },
		name = name,
		target = _call
	}
end

function post(...)
	return post_on(true, ...)
end


local _template = function(self, ...)
	require "luci.template".render(self.view)
end

function template(name)
	return {type = "template", view = name, target = _template}
end


local function _cbi(self, ...)
	local cbi = require "luci.cbi"
	local tpl = require "luci.template"
	local http = require "luci.http"

	local config = self.config or {}
	local maps = cbi.load(self.model, ...)

	local state = nil

	for i, res in ipairs(maps) do
		res.flow = config
		local cstate = res:parse()
		if cstate and (not state or cstate < state) then
			state = cstate
		end
	end

	local function _resolve_path(path)
		return type(path) == "table" and build_url(unpack(path)) or path
	end

	if config.on_valid_to and state and state > 0 and state < 2 then
		http.redirect(_resolve_path(config.on_valid_to))
		return
	end

	if config.on_changed_to and state and state > 1 then
		http.redirect(_resolve_path(config.on_changed_to))
		return
	end

	if config.on_success_to and state and state > 0 then
		http.redirect(_resolve_path(config.on_success_to))
		return
	end

	if config.state_handler then
		if not config.state_handler(state, maps) then
			return
		end
	end

	http.header("X-CBI-State", state or 0)

	if not config.noheader then
		tpl.render("cbi/header", {state = state})
	end

	local redirect
	local messages
	local applymap   = false
	local pageaction = true
	local parsechain = { }

	for i, res in ipairs(maps) do
		if res.apply_needed and res.parsechain then
			local c
			for _, c in ipairs(res.parsechain) do
				parsechain[#parsechain+1] = c
			end
			applymap = true
		end

		if res.redirect then
			redirect = redirect or res.redirect
		end

		if res.pageaction == false then
			pageaction = false
		end

		if res.message then
			messages = messages or { }
			messages[#messages+1] = res.message
		end
	end

	for i, res in ipairs(maps) do
		res:render({
			firstmap   = (i == 1),
			applymap   = applymap,
			redirect   = redirect,
			messages   = messages,
			pageaction = pageaction,
			parsechain = parsechain
		})
	end

	if not config.nofooter then
		tpl.render("cbi/footer", {
			flow       = config,
			pageaction = pageaction,
			redirect   = redirect,
			state      = state,
			autoapply  = config.autoapply
		})
	end
end

function cbi(model, config)
	return {
		type = "cbi",
		post = { ["cbi.submit"] = "1" },
		config = config,
		model = model,
		target = _cbi
	}
end


local function _arcombine(self, ...)
	local argv = {...}
	local target = #argv > 0 and self.targets[2] or self.targets[1]
	setfenv(target.target, self.env)
	target:target(unpack(argv))
end

function arcombine(trg1, trg2)
	return {type = "arcombine", env = getfenv(), target = _arcombine, targets = {trg1, trg2}}
end


local function _form(self, ...)
	local cbi = require "luci.cbi"
	local tpl = require "luci.template"
	local http = require "luci.http"

	local maps = luci.cbi.load(self.model, ...)
	local state = nil

	for i, res in ipairs(maps) do
		local cstate = res:parse()
		if cstate and (not state or cstate < state) then
			state = cstate
		end
	end

	http.header("X-CBI-State", state or 0)
	tpl.render("header")
	for i, res in ipairs(maps) do
		res:render()
	end
	tpl.render("footer")
end

function form(model)
	return {
		type = "cbi",
		post = { ["cbi.submit"] = "1" },
		model = model,
		target = _form
	}
end

translate = i18n.translate

-- This function does not actually translate the given argument but
-- is used by build/i18n-scan.pl to find translatable entries.
function _(text)
	return text
end

-- get the current user anyway we can 
-- if no user if found return "nobody"
function get_user()
	local fs = require "nixio.fs"
	local http = require "luci.http"
	local util = require "luci.util"
	local sess = luci.http.getcookie("sysauth")
	local sdat = (util.ubus("session", "get", { ubus_rpc_session = sess }) or { }).values
	local user

	if sdat then 
		user = sdat.user
		return(user)
	elseif http.formvalue("username") then
		user = http.formvalue("username")
		return(user)
	elseif http.getenv("HTTP_AUTH_USER") then
		user = http.getenv("HTTP_AUTH_USER")
		return(user)
	else
		user = "nobody"
		return(user)
	end
end

--## Function to create a file contianing all available menus and sub-menus ##--
local function create_menu(menu,title,path,order)
	local tbuf = {}
	local dir = "/tmp/menu/"
	local fname = dir .. menu

   	-- check if file and dir exists, if not create them
   	if not fs.access(dir) then 
     		fs.mkdir(dir)
   	end
   	if not fs.access(fname) then
     		file = assert(io.open(fname, "w+"))
       		file:write(title.."-"..path.."-"..tostring(order).."\n")
     		file:close()
   	else
   		-- check if file contains val, if not add the val to the file
      		file = assert(io.open(fname, "r"))
     		for line in file:lines() do
       			tbuf[#tbuf+1] = line
     		end
     		file:close()
     		if not util.contains(tbuf, title.."-"..path.."-"..tostring(order)) then
       			file = assert(io.open(fname, "a+"))
       			file:write(title.."-"..path.."-"..tostring(order).."\n")
       			file:close()
     		end
    	end

  	return
end

--## Function to format menus and sub-menus for writing to file ##--
local function parse_path(path,title,order)
	local tbuf = {}
	local dbuf = {}

	for word in string.gmatch(path, '([^.]+)') do
		if (#tbuf < 3) then
			tbuf[#tbuf+1] = word
		end
	end

	for i,v in pairs(tbuf) do
		if tbuf[2] ~= "filebrowser" and tbuf[2] ~= "logout" and tbuf[2] ~= "servicectl" and tbuf[2] ~= "uci" then
            		if tbuf[2] and tbuf[3] then
				dbuf[tbuf[2]] = tbuf[3]
            		end
		end
	end

	for i,v in pairs(dbuf) do
          create_menu(i,title,path,order)
	end
	return
end

--## Function to create the menu tree from the context.treecahce ##--
function create_menu_tree()
	--util.dumptable(context.treecache,2)
	local cnt = 0
	for k,v in pairs(context.treecache) do
		if not k:match("admin.uci.%a+") and v.title then
			parse_path(k, v.title, v.order)
			cnt = cnt + 1
		end
		if cnt >= 50 then return end
	end
	
	return
end

--## Function to sort menus best we can ... the order hierarchy needs work ##--
local function sort_menus(menu)
	local menus = {}
	local tmenus = {}
	local title,path,order
	local menu_keys = {}

	for i,v in pairs(menu) do
		menus[i]= {}
		menu_keys = {}
		for key,val in pairs(v) do
			local tbuf={}
			for word in val:gmatch("[^-]+") do
				tbuf[#tbuf+1] = word
			end

			local tbuf2 = {}
			for word in tbuf[2]:gmatch("[^.]+") do
				tbuf2[#tbuf2+1] = word
			end
			if #tbuf2 > 3 then tbuf[3] = tonumber(tbuf[3]) + 11 end
			title = tbuf[1]
			path = tbuf[2]
			order = tonumber(tbuf[3]) or 99
			--print(title,order,path)
			if util.contains(menu_keys, order) then order = order +1 end
			menu_keys[#menu_keys+1]= order
			tmenus[order] = {title.."-"..path}
			
		end
		table.sort(menu_keys, function(a,b) return a<b end)
		for _,v in pairs(menu_keys) do
				--print(v)
				for a,b in pairs(tmenus[v]) do
					menus[i][#menus[i]+1]=b
				end
			end
		
	end
	return menus
end

--## Function users by add_users and edit_users to display available menus ##--
function load_menu()
	create_menu_tree()
	local menu = {}
	if fs.stat("/tmp/menu") then
		for i,v in fs.dir("/tmp/menu") do
			menu[i]={}
			local file = assert(io.open("/tmp/menu/"..i, "r"))
			
			for line in file:lines() do
				if line ~= nil then
					if not util.contains(menu[i],line) then
						menu[i][#menu[i]+1] = line
					end
				end
			end
			file:close()
		end
	end
	local menus = sort_menus(menu)
	return menus
end
