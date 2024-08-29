require 'sinatra'
require 'json'
require 'pg'
require 'ssh_data'
require 'socket'
require 'openssl'
require 'http_signatures'
require './http_sig_ecdsa'
require './http_sig_utils'
require './utils'

$sockpath = '/run/comp4703-balancer.sock'
$mungekey = Base64.decode64('l3ypcbQpc4ksNdxIl+QehjUR')
$ctrlzone = `zonename`.strip

def rebalance
  sock = UNIXSocket.new($sockpath)
  sock.puts JSON.dump({:operation => :rebalance})
  sock.close
end

def allocate_and_wait(alloc_id)
  sock = UNIXSocket.new($sockpath)
  sock.puts JSON.dump({:operation => :allocate, :allocation => alloc_id})
  line = sock.gets
  if line.nil?
    raise 'failed to contact balancer process'
  end
  res = JSON.parse(line, :symbolize_names => true)
  raise res[:reason] if res[:status] != 'ok'
  sock.close
end

module Control
  class Application < Sinatra::Base
    before do
      if Thread.current[:app_db].nil?
        Thread.current[:app_db] = (db = PG.connect(dbname: 'control'))
        db.type_map_for_results = PG::BasicTypeMapForResults.new db
        db.type_map_for_queries = PG::BasicTypeMapForQueries.new db
        Thread.current[:app_dbssh] = (dbssh = PG.connect(dbname: 'sshportal'))
        dbssh.type_map_for_results = PG::BasicTypeMapForResults.new dbssh
        dbssh.type_map_for_queries = PG::BasicTypeMapForQueries.new dbssh
      end
      @db = Thread.current[:app_db]
      @dbssh = Thread.current[:app_dbssh]

      keys = {}
      @db.exec('select id, auth_key from zones').values.each do |id, auth_key|
        next if auth_key.nil?
        keys["zones/#{id}"] = {public_key: auth_key, :type => :zone, :id => id}
      end
      @db.exec('select hostname, auth_key from workers').values.each do |hostname, auth_key|
        next if auth_key.nil?
        keys["workers/#{hostname}"] = {public_key: auth_key, :type => :worker, :hostname => hostname}
      end
      keystore = FingerprintKeyStore.new(keys)
      msg = RackMessageWrapper.new(request: request)
      @auth = AuthzVerification.new(message: msg, key_store: keystore, required_headers: %w{(request-target) host date})
    end

    post '/worker/ready' do
      halt 403, "access denied\n" unless @auth.valid? and @auth.key_info[:type] == :worker
      hostname = @auth.key_info[:hostname]
      res = @db.exec_params('update workers
        set state = $2, state_change = now()
        where hostname = $1',
        [hostname, 'ready'])
      halt 500, "db error\n" if res.cmd_tuples < 1
      rebalance
      "ok, worker #{hostname} marked ready\n"
    end

    put '/worker/provision/:token' do |token|
      request.body.rewind
      auth_key = request.body.read.strip
      r = @db.exec_params('update workers
        set provision_token = NULL, auth_key = $1
        where provision_token = $2
        returning hostname',
        [auth_key, token])
      halt 403, "invalid provision token\n" if r.ntuples < 1
      "ok, worker auth key saved for #{r[0]['hostname']}\n"
    end

    get '/worker/assignment' do
      halt 403, "access denied\n" unless @auth.valid? and @auth.key_info[:type] == :worker
      hostname = @auth.key_info[:hostname]
      r = @db.exec_params('select * from allocations
        where worker_hostname = $1
        and state in ($2, $3)', [hostname, 'busy', 'allocated'])
      halt 404, "no valid assignment\n" if r.ntuples < 1
      alloc = r[0].symbolize
      r = @db.exec_params('select * from zones
        where id = $1', [alloc[:zone_id]])
      zone = r[0].symbolize
      key = Base64.encode64(
        OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new,
        zone[:id], $mungekey))
      r = @db.exec_params('select * from quotas
        where username = $1', [zone[:owner] ? zone[:owner] : ''])
      quota = r[0].symbolize
      JSON.dump({
        zone_id: zone[:id],
        zone_ip: zone[:vpn_addr],
        owner: zone[:owner],
        munge_key: key,
        quota_mins: quota[:quota_mins],
        used_mins: quota[:used_mins]
      })
    end

    get '/zone/info' do
      unless @auth.valid? and @auth.key_info[:type] == :zone
        rebalance
        halt 403, "access denied\n"
      end

      r = @db.exec_params('select * from zones
        where id = $1', [@auth.key_info[:id]])
      zone = r[0].symbolize
      key = Base64.encode64(
        OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new,
        zone[:id], $mungekey))
      JSON.dump({
        zone_id: zone[:id],
        zone_ip: zone[:vpn_addr],
        owner: zone[:owner],
        munge_key: key
      })
    end

    post '/control/assign-zone/:username' do |username|
      halt 200, "ok: admin user" if %w{sshportal admin}.include?(username)
      halt 403, "access denied\n" unless @auth.valid? and @auth.key_info[:id] == $ctrlzone

      request.body.rewind
      auth_key = request.body.read.strip

      zone = nil
      if username =~ /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
        r = @db.exec_params('select * from zones where id = $1', [username])
        zone = r[0].symbolize if r.ntuples == 1
      end
      if zone.nil?
        r = @db.exec_params('select * from zones where owner = $1', [username])
        zone = r[0].symbolize if r.ntuples == 1
      end
      if zone.nil?
        r = @db.exec_params('select * from zones where auth_key like $1', [auth_key + '%'])
        zone = r[0].symbolize if r.ntuples == 1
      end
      halt 404, "zone not found\n" if zone.nil?

      r = @db.exec_params('select * from quotas
        where username = $1', [zone[:owner] ? zone[:owner] : ''])
      halt 404, "no user quota found for '#{zone[:owner]}'\n" if r.ntuples < 1
      quota = r[0].symbolize
      halt 429, "user '#{zone[:owner]}' is over quota\n" if quota[:used_mins] > quota[:quota_mins]

      @db.exec('begin')
      @db.exec('lock table allocations')
      r = @db.exec_params('select * from allocations where
        zone_id = $1 and state in ($2, $3, $4)',
        [zone[:id], 'waiting', 'allocated', 'busy'])
      alloc_id = nil
      if r.ntuples >= 1
        alloc_id = r[0]['id']
        @db.exec('commit')
        if r[0]['state'] == 'waiting'
          allocate_and_wait(alloc_id)
        end
      else
        r = @db.exec_params('insert into allocations
          (zone_id) values ($1) returning id',
          [zone[:id]])
        alloc_id = r[0]['id']
        @db.exec('commit')
        allocate_and_wait(alloc_id)
      end

      r = @db.exec_params('select * from allocations where id = $1',
        [alloc_id])
      if r[0]['state'] == 'allocated' or r[0]['state'] == 'busy'
        @db.exec_params('update allocations set state = $2 where id = $1',
          [alloc_id, 'busy'])
        @dbssh.exec_params('update users
          set comment = NULL
          where id = $1', [r[0]['ssh_user_id']])
      end
      return "ok: allocation #{alloc_id} is now #{r[0]['state']} on #{r[0]['hostname']}\n"
    end
  end
end
