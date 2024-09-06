require 'sinatra'
require 'json'
require 'pg'
require 'ssh_data'
require 'socket'
require 'openssl'
require 'connection_pool'
require 'http_signatures'
require './http_sig_ecdsa'
require './http_sig_utils'
require './utils'

$sockpath = '/run/comp4703-balancer.sock'
$mungekey = Base64.decode64('l3ypcbQpc4ksNdxIl+QehjUR')
$ctrlzone = `zonename`.strip

def rebalance
  begin
    sock = UNIXSocket.new($sockpath)
    sock.puts JSON.dump({:operation => :rebalance})
    sock.close
  rescue Exception
  end
end

def await_any_allocation
  t0 = Time.now
  sock = nil
  begin
    sock = UNIXSocket.new($sockpath)
    sock.puts JSON.dump({:operation => :wait_any})
    r = IO.select([sock], [], [], 60)
    raise 'timeout' if r.nil?
    line = sock.gets
    if line.nil?
      raise 'failed to contact balancer process'
    end
    res = JSON.parse(line, :symbolize_names => true)
    raise res[:reason] if res[:status] != 'ok'
  rescue Exception => err
    raise err if Time.now - t0 > 60
    sleep 1
    retry
  ensure
    sock.close unless sock.nil?
  end
end

def allocate_and_wait(alloc_id)
  retries = 0
  sock = nil
  begin
    sock = UNIXSocket.new($sockpath)
    sock.puts JSON.dump({:operation => :allocate, :allocation => alloc_id})
    r = IO.select([sock], [], [], 60)
    raise 'timeout' if r.nil?
    line = sock.gets
    if line.nil?
      raise 'failed to contact balancer process'
    end
    res = JSON.parse(line, :symbolize_names => true)
    raise res[:reason] if res[:status] != 'ok'
  rescue Exception => err
    retries += 1
    if retries < 5
      sleep 2
      retry
    end
    raise err
  ensure
    sock.close unless sock.nil?
  end
end

$db_pool = ConnectionPool.new(size: 32) do
  db = PG.connect(dbname: 'control')
  db.type_map_for_results = PG::BasicTypeMapForResults.new db
  db.type_map_for_queries = PG::BasicTypeMapForQueries.new db
  db
end

$dbssh_pool = ConnectionPool.new(size: 4) do
  db = PG.connect(dbname: 'sshportal')
  db.type_map_for_results = PG::BasicTypeMapForResults.new db
  db.type_map_for_queries = PG::BasicTypeMapForQueries.new db
  db
end

module Control
  class Application < Sinatra::Base
    set :environment, :production

    before do
      if request.get_header('HTTP_X_UQ_USER')
        @auth = SSOVerification.new(request: request)
      else
        keys = {}
        $db_pool.with do |db|
          db.exec('select id, auth_key from zones').values.each do |id, auth_key|
            next if auth_key.nil?
            keys["zones/#{id}"] = {
              :public_key => auth_key,
              :type => :zone,
              :id => id
            }
          end
          db.exec('select hostname, auth_key from nfs_servers').values.each do |id, auth_key|
            next if auth_key.nil?
            keys["nfs/#{id}"] = {
              :public_key => auth_key,
              :type => :nfs_server,
              :hostname => id
            }
          end
          db.exec('select hostname, auth_key from workers').values.each do |hostname, auth_key|
            next if auth_key.nil?
            keys["workers/#{hostname}"] = {
              :public_key => auth_key,
              :type => :worker,
              :hostname => hostname
            }
          end
        end
        keystore = FingerprintKeyStore.new(keys)
        msg = RackMessageWrapper.new(request: request)
        @auth = AuthzVerification.new(message: msg, key_store: keystore,
          required_headers: %w{(request-target) host date})
      end
    end

    get '/' do
      halt 403, "access denied\r\n" unless @auth.valid?
      user = @auth.key_info[:user]
      $db_pool.with do |db|
        r = db.exec_params('select * from zones where owner = $1', [user])
        halt 404, "no zone allocated for #{user}\r\n" if r.ntuples == 0
        @zone = r[0].symbolize
        @zone[:alias] = "comp4703-#{@zone[:id].split('-').first}"
        @zone[:url] = "https://#{@zone[:alias]}.uqcloud.net"
        r = db.exec_params('select * from quotas where username = $1', [user])
        @quota = r[0].symbolize
        r = db.exec_params('select * from allocations where zone_id = $1
          and state != \'closed\'', [@zone[:id]])
        @allocations = []
        r.each { |a| @allocations << a.symbolize }
      end
      erb :index
    end

    get '/connpools' do
      JSON.dump({
        db: {
          size: $db_pool.size,
          available: $db_pool.available
        },
        dbssh: {
          size: $dbssh_pool.size,
          available: $dbssh_pool.available
        }
      })
    end

    get '/puma/stats' do
      Puma.stats
    end

    get '/nfs/exports' do
      halt 403, "access denied\r\n" unless @auth.valid? and @auth.key_info[:type] == :nfs_server
      mounts = []
      $db_pool.with do |db|
        r = db.exec('select
          z.owner as username, w.vpn_addr as mountip
          from allocations as a
          join workers as w on w.hostname = a.worker_hostname
          join zones as z on z.id = a.zone_id
          where a.state != \'closed\'
          order by a.id asc')
        r.each do |row|
          mounts << row.symbolize
        end
      end
      shash = Digest::SHA256.hexdigest(JSON.dump(mounts))
      JSON.dump({
        :mounts => mounts,
        :digest => shash
      })
    end

    get '/nfs/exports/:digest' do |digest|
      halt 403, "access denied\r\n" unless @auth.valid? and @auth.key_info[:type] == :nfs_server
      t0 = Time.now
      loop do
        mounts = []
        $db_pool.with do |db|
          r = db.exec('select
            z.owner as username, w.vpn_addr as mountip
            from allocations as a
            join workers as w on w.hostname = a.worker_hostname
            join zones as z on z.id = a.zone_id
            where a.state != \'closed\'
            order by a.id asc')
          r.each do |row|
            mounts << row.symbolize
          end
        end
        shash = Digest::SHA256.hexdigest(JSON.dump(mounts))
        if shash == digest and (Time.now - t0) < 300
          await_any_allocation
          next
        end
        return JSON.dump({
          :mounts => mounts,
          :digest => shash
        })
      end
    end

    post '/worker/ready' do
      halt 403, "access denied\r\n" unless @auth.valid? and @auth.key_info[:type] == :worker
      hostname = @auth.key_info[:hostname]
      $db_pool.with do |db|
        res = db.exec_params('update workers
          set state = $2, state_change = now()
          where hostname = $1',
          [hostname, 'ready'])
        halt 500, "db error\r\n" if res.cmd_tuples < 1
      end
      rebalance
      "ok: worker #{hostname} marked ready\r\n"
    end

    post '/worker/idle' do
      halt 403, "access denied\r\n" unless @auth.valid? and @auth.key_info[:type] == :worker
      hostname = @auth.key_info[:hostname]
      $db_pool.with do |db|
        r = db.exec_params('update allocations
          set state = \'allocated\'
          where worker_hostname = $1
          and state = \'busy\'', [hostname])
        halt 200, "ok: no allocations changed\r\n" if r.cmd_tuples < 1
      end
      rebalance
      "ok: worker #{hostname} marked idle\r\n"
    end

    post '/worker/busy' do
      halt 403, "access denied\r\n" unless @auth.valid? and @auth.key_info[:type] == :worker
      hostname = @auth.key_info[:hostname]
      $db_pool.with do |db|
        r = db.exec_params('update allocations
          set state = \'busy\'
          where worker_hostname = $1
          and state = \'allocated\'', [hostname])
        halt 200, "ok: no allocations changed\r\n" if r.cmd_tuples < 1
      end
      rebalance
      "ok: worker #{hostname} marked busy\r\n"
    end

    put '/worker/provision/:token' do |token|
      request.body.rewind
      auth_key = request.body.read.strip
      r = nil
      $db_pool.with do |db|
        r = db.exec_params('update workers
          set provision_token = NULL, auth_key = $1
          where provision_token = $2
          returning hostname',
          [auth_key, token])
      end
      halt 403, "invalid provision token\r\n" if r.ntuples < 1
      "ok: worker auth key saved for #{r[0]['hostname']}\r\n"
    end

    get '/worker/assignment' do
      halt 403, "access denied\r\n" unless @auth.valid? and @auth.key_info[:type] == :worker
      hostname = @auth.key_info[:hostname]
      alloc = zone = key = quota = nfs = nil
      $db_pool.with do |db|
        r = db.exec_params('select * from allocations
          where worker_hostname = $1
          and state in ($2, $3)', [hostname, 'busy', 'allocated'])
        halt 404, "no valid assignment\r\n" if r.ntuples < 1
        alloc = r[0].symbolize
        r = db.exec_params('select * from zones
          where id = $1', [alloc[:zone_id]])
        zone = r[0].symbolize
        r = db.exec_params('select * from quotas
          where username = $1', [zone[:owner] ? zone[:owner] : ''])
        quota = r[0].symbolize
        r = db.exec('select * from nfs_servers limit 1')
        nfs = r[0].symbolize
      end
      key = Base64.encode64(
        OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new,
        zone[:id], $mungekey))
      JSON.dump({
        state: alloc[:state],
        last_connect: alloc[:last_connect],
        zone_id: zone[:id],
        zone_ip: zone[:vpn_addr],
        owner: zone[:owner],
        munge_key: key,
        quota_mins: quota[:quota_mins],
        used_mins: quota[:used_mins],
        nfs_server_ip: nfs[:ip],
        nfs_server: nfs[:hostname]
      })
    end

    get '/zone/info' do
      unless @auth.valid? and @auth.key_info[:type] == :zone
        rebalance
        halt 403, "access denied\r\n"
      end

      zone = nil
      $db_pool.with do |db|
        r = db.exec_params('select * from zones
          where id = $1', [@auth.key_info[:id]])
        zone = r[0].symbolize
      end
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
      halt 200, "ok: admin user\r\n" if %w{sshportal admin}.include?(username)
      halt 403, "access denied\r\n" unless @auth.valid? and @auth.key_info[:id] == $ctrlzone

      request.body.rewind
      auth_key = request.body.read.strip

      r = zone = alloc_id = nil
      do_wait = false
      $db_pool.with do |db|
        if username =~ /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
          r = db.exec_params('select * from zones where id = $1', [username])
          zone = r[0].symbolize if r.ntuples == 1
        end
        if zone.nil?
          r = db.exec_params('select * from zones where owner = $1', [username])
          zone = r[0].symbolize if r.ntuples == 1
        end
        if zone.nil?
          r = db.exec_params('select * from zones where auth_key like $1', [auth_key + '%'])
          zone = r[0].symbolize if r.ntuples == 1
        end
        halt 200, "ok: zone not found\r\n" if zone.nil?

        r = db.exec_params('select * from quotas
          where username = $1', [zone[:owner] ? zone[:owner] : ''])
        halt 404, "no user quota found for '#{zone[:owner]}'\r\n" if r.ntuples < 1
        quota = r[0].symbolize
        if quota[:used_mins] > quota[:quota_mins]
          halt 429, "user '#{zone[:owner]}' is over time quota (used #{quota[:used_mins]} minutes out of #{quota[:quota_mins]})\r\n"
        end

        db.exec('begin')
        db.exec('lock table allocations')
        r = db.exec_params('select * from allocations where
          zone_id = $1 and state in ($2, $3, $4)',
          [zone[:id], 'waiting', 'allocated', 'busy'])

        if r.ntuples >= 1
          alloc_id = r[0]['id']
          db.exec('commit')
          do_wait = true if r[0]['state'] == 'waiting'
        else
          r = db.exec_params('insert into allocations
            (zone_id) values ($1) returning id',
            [zone[:id]])
          alloc_id = r[0]['id']
          db.exec('commit')
          do_wait = true
        end
      end

      allocate_and_wait(alloc_id) if do_wait

      $db_pool.with do |db|
        r = db.exec_params('select * from allocations where id = $1',
          [alloc_id])
        if r[0]['state'] == 'allocated' or r[0]['state'] == 'busy'
          db.exec_params('update allocations
            set state = $2, last_connect = now()
            where id = $1',
            [alloc_id, 'busy'])
          $dbssh_pool.with do |dbssh|
            dbssh.exec_params('update users
              set comment = NULL
              where id = $1', [r[0]['ssh_user_id']])
          end
        end
      end

      return "ok: allocation #{alloc_id} is now #{r[0]['state']} on #{r[0]['hostname']}\n"
    end
  end
end
