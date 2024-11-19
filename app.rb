require 'sinatra'
require 'json'
require 'pg'
require 'ssh_data'
require 'digest'
require 'socket'
require 'logger'
require 'openssl'
require 'connection_pool'
require 'http_signatures'
require 'sinatra/reloader'
require 'duration'
require './http_sig_ecdsa'
require './http_sig_utils'
require './utils'

$sockpath = '/run/comp4703-balancer.sock'
$mungekey = Base64.decode64('l3ypcbQpc4ksNdxIl+QehjUR')
$ctrlzone = `zonename`.strip

$log = Logger.new(STDERR)
$log.level = Logger::DEBUG

def rebalance
  begin
    sock = UNIXSocket.new($sockpath)
    sock.puts JSON.dump({:operation => :rebalance})
    sock.close
  rescue Exception
  end
end

class TimeoutError < RuntimeError
end

def await_any_allocation
  t0 = Time.now
  sock = nil
  begin
    sock = UNIXSocket.new($sockpath)
    sock.puts JSON.dump({:operation => :wait_any})
    r = IO.select([sock], [], [], 10)
    raise TimeoutError.new if r.nil?
    line = sock.gets
    if line.nil?
      raise 'failed to contact balancer process'
    end
    res = JSON.parse(line, :symbolize_names => true)
    raise res[:reason] if res[:status] != 'ok'
  rescue TimeoutError
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

def get_config(key)
  $db_pool.with do |db|
    r = db.exec_params('select * from config
      where key = $1', [key.to_s])
    raise "Config key not found: #{key}" if r.ntuples < 1
    r[0]['value']
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
    set :environment, :development

    before do
      if request.get_header('HTTP_X_UQ_USER')
        xusers = get_config(:xusers).split
        @auth = SSOVerification.new(request: request, admin_users: xusers)
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

        r = db.exec_params('select * from allocations where zone_id = $1
          and state = \'closed\' order by closed desc limit $2',
          [@zone[:id], 10])
        @past_allocations = []
        r.each { |a| @past_allocations << a.symbolize }
        r = db.exec_params('select count(*) as count from allocations
          where zone_id = $1 and state = \'closed\'', [@zone[:id]])
        @past_count = r[0]['count']

        @alloc_reports = {}
        @sessions = {}
      end
      erb :index
    end

    get '/admin' do
      halt 403, "access denied\r\n" unless @auth.valid? and @auth.key_info[:admin]
      $db_pool.with do |db|
        r = db.exec('select * from config order by key')
        @config = []
        r.each { |c| @config << c.symbolize }

        r = db.exec('select * from budgets')
        @budgets = []
        r.each { |b| @budgets << b.symbolize }
        @budget = @budgets.find { |b| b[:name] == "comp4703-#{Time.now.year}" }

        r = db.exec('select * from nfs_servers')
        @nfs_servers = []
        r.each { |c| @nfs_servers << c.symbolize }

        r = db.exec('select sum(used_mins) as used, sum(quota_mins) as quota from quotas')
        @budget[:total_used_mins] = r[0]['used']
        @budget[:total_quota_mins] = r[0]['quota']

        r = db.exec('
          select
            q.*,
            z.id as zone_id,
            sum(
              case
                when a.state is null then 0
                when a.state = \'closed\' then 0
                else 1
              end
            ) as active,
            count(a.state) as total,
            max(a.last_connect) as last_connect
          from quotas as q
          join zones as z on z.owner = q.username
          left outer join allocations as a on a.zone_id = z.id
          group by q.username, z.id
          order by q.username desc')
        @quotas = []
        r.each { |q| @quotas << q.symbolize }

        r = db.exec('select * from workers order by hostname')
        @workers = []
        r.each { |w| @workers << w.symbolize }

        r = db.exec_params('select * from allocations
          where (state != \'closed\' or closed >= $1)
          order by created desc', [Time.now - 3600*12])
        @allocations = []
        r.each { |w| @allocations << w.symbolize }

        r = db.exec('select * from zones order by id')
        @zones = {}
        r.each do |z|
          z.symbolize!
          @zones[z[:id]] = z
        end

        poolhist = []
        r = db.exec('select * from pool_size_history order by time asc')
        r.each { |row| poolhist << row.symbolize }
        @poolhistjson = JSON.dump(poolhist)
      end
      erb :admin
    end

    get '/admin/quota/:user' do |user|
      halt 403, "access denied\r\n" unless @auth.valid? and @auth.key_info[:admin]
      $db_pool.with do |db|
        r = db.exec_params('select * from quotas where username = $1', [user])
        @quota = r[0].symbolize
      end
      erb :edit_quota
    end

    post '/admin/quota/:user' do |user|
      halt 403, "access denied\r\n" unless @auth.valid? and @auth.key_info[:admin]
      quota_mins = params[:quota_mins].to_i
      home_quota_gb = params[:home_quota_gb].to_i
      conda_quota_gb = params[:conda_quota_gb].to_i
      cache_quota_gb = params[:cache_quota_gb].to_i
      $db_pool.with do |db|
        r = db.exec_params('select * from quotas where username = $1',
          [user])
        halt 404, "no such user\r\n" unless r.ntuples > 0

        quota = r[0].symbolize
        changes = []
        changes << "quota_mins = #{quota_mins}" if quota[:quota_mins] != quota_mins
        changes << "home_quota_gb = #{home_quota_gb}" if quota[:home_quota_gb] != home_quota_gb
        changes << "conda_quota_gb = #{conda_quota_gb}" if quota[:conda_quota_gb] != conda_quota_gb
        changes << "cache_quota_gb = #{cache_quota_gb}" if quota[:cache_quota_gb] != cache_quota_gb
        $log.info("updating quota for #{user}: #{changes.join('; ')}") unless changes.empty?

        r = db.exec_params('update quotas
          set quota_mins = $2, home_quota_gb = $3, conda_quota_gb = $4,
          cache_quota_gb = $5 where username = $1',
          [user, quota_mins, home_quota_gb, conda_quota_gb, cache_quota_gb])
        halt 404, "no such user\r\n" unless r.cmd_tuples > 0
      end
      redirect "/admin/quota/#{user}?saved=1&return_to=#{params[:return_to]}", 303
    end

    get '/admin/sessions/:zoneid' do |zone_id|
      $db_pool.with do |db|
        r = db.exec_params('select * from zones where id = $1', [zone_id])
        halt 404, "no zone found with id #{zone_id}\r\n" if r.ntuples == 0
        @zone = r[0].symbolize
      end
      halt 403, "access denied\r\n" unless @auth.valid? and (
        @auth.key_info[:admin] or
        @auth.key_info[:user] == @zone[:owner])
      @sudo = true
      $db_pool.with do |db|
        @zone[:alias] = "comp4703-#{@zone[:id].split('-').first}"
        @zone[:url] = "https://#{@zone[:alias]}.uqcloud.net"
        r = db.exec_params('select * from quotas where username = $1',
          [@zone[:owner]])
        @quota = r[0].symbolize

        r = db.exec_params('select * from allocations where zone_id = $1
          and state != \'closed\'', [@zone[:id]])
        @allocations = []
        r.each { |a| @allocations << a.symbolize }

        @sessions = {}

        @allocations.each do |alloc|
          $dbssh_pool.with do |dbssh|
            r = dbssh.exec_params('select * from sessions where
              user_id = $1 or host_id = $2 order by created_at asc',
              [alloc[:ssh_user_id], alloc[:ssh_host_id]])
            @sessions[alloc[:id]] = []
            r.each do |row|
              @sessions[alloc[:id]] << row.symbolize
            end
          end
        end

        r = db.exec_params('select * from allocations where zone_id = $1
          and state = \'closed\' order by closed desc limit $2',
          [@zone[:id], 30])
        @past_allocations = []
        r.each { |a| @past_allocations << a.symbolize }

        @past_allocations.each do |alloc|
          next if (Time.now - alloc[:closed]) > 3600*24*3
          $dbssh_pool.with do |dbssh|
            r = dbssh.exec_params('select * from old_sessions where
              allocation_id = $1 order by created_at asc', [alloc[:id]])
            @sessions[alloc[:id]] = []
            r.each do |row|
              @sessions[alloc[:id]] << row.symbolize
            end
          end
        end

        r = db.exec_params('select count(*) as count from allocations
          where zone_id = $1 and state = \'closed\'', [@zone[:id]])
        @past_count = r[0]['count']

        tlimit = Time.now - 3600*24*3
        tlimit = Time.now - 3600*24*3650*3 if params[:all]
        r = db.exec_params('select ar.*
          from allocations as a
          join alloc_reports ar on ar.allocation_id = a.id
          where a.zone_id = $1 and ar.time >= $2
          order by a.id asc, ar.time asc',
          [@zone[:id], tlimit])
        @alloc_reports = Hash.new([])
        held_reports = {}
        r.each do |row|
          row.symbolize!
          aid = row[:allocation_id]
          l = @alloc_reports[aid].last
          if l and l[:state] == row[:state] and l[:reason] == row[:reason] and
                l[:data].approx_equal?(row[:data], epsilon: 0.5)
            held_reports[aid] = row
            next
          end
          if held_reports[aid]
            @alloc_reports[aid] += [held_reports[aid]]
            held_reports.delete(aid)
          end
          @alloc_reports[aid] += [row]
        end
        held_reports.each do |aid, report|
          @alloc_reports[aid] += [report]
        end
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

    get '/nfs/quotas' do
      halt 403, "access denied\r\n" unless @auth.valid? and @auth.key_info[:type] == :nfs_server
      $db_pool.with do |db|
        r = db.exec('select * from quotas')
        fs = {
          :home => {},
          :conda => {},
          :cache => {}
        }
        r.each do |row|
          row.symbolize!
          fs[:home][row[:username]] = row[:home_quota_gb]
          fs[:conda][row[:username]] = row[:conda_quota_gb]
          fs[:cache][row[:username]] = row[:cache_quota_gb]
        end
        JSON.dump(fs)
      end
    end

    put '/nfs/usage' do
      halt 403, "access denied\r\n" unless @auth.valid? and @auth.key_info[:type] == :nfs_server
      halt 403, "error: x-body-sha256 not signed\r\n" unless @auth.signed_header?('x-body-sha256')
      bodysha = request.get_header('HTTP_X_BODY_SHA256')
      halt 403, "error: x-body-sha256 not included\r\n" if bodysha.nil?
      bodysha = Digest::SHA256.base64digest(bodysha)
      request.body.rewind
      data = request.body.read
      halt 400, "error: expected a JSON body\r\n" if data.nil?
      oursha = Digest::SHA256.base64digest(Digest::SHA256.base64digest(data))
      halt 400, "error: body-sha256 did not match body\r\n" if bodysha != oursha
      obj = JSON.parse(data)

      $db_pool.with do |db|
        db.exec('begin')

        pool_usage = (obj['pool'] || {}).symbolize
        obj.delete('pool')
        if pool_usage[:used]
          db.exec_params('update nfs_servers set used_mb = $2, total_mb = $3
            where hostname = $1',
            [@auth.key_info[:hostname],
             (pool_usage[:used] / 1024.0 / 1024.0).round,
             ((pool_usage[:used] + pool_usage[:available]) / 1024.0 / 1024.0).round])
        end

        db.prepare('update-quota-usage',
          'update quotas set home_used_mb = $2, conda_used_mb = $3, cache_used_mb = $4
          where username = $1')
        obj.each do |username, used|
          used.symbolize!
          db.exec_prepared('update-quota-usage', [username,
            used[:home], used[:conda], used[:cache]])
        end
        db.exec('deallocate "update-quota-usage"')
        db.exec('commit')
      end
      "ok: usage updated\r\n"
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
          begin
            await_any_allocation
          rescue Exception
          end
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
      $log.info("worker #{hostname} reporting ready")
      "ok: worker #{hostname} marked ready\r\n"
    end

    post '/worker/idle' do
      halt 403, "access denied\r\n" unless @auth.valid? and @auth.key_info[:type] == :worker
      hostname = @auth.key_info[:hostname]
      alloc = nil

      $log.info("worker #{hostname} reporting idle")

      $db_pool.with do |db|
        r = db.exec_params('select * from allocations
          where worker_hostname = $1 and state != \'closed\'', [hostname])
        halt 200, "ok: no allocations changed\r\n" if r.ntuples < 1

        alloc = r[0].symbolize

        if alloc[:state] == 'busy'
          r = db.exec_params('update allocations
            set state = \'allocated\' where id = $1 and state = \'busy\'',
            [alloc[:id]])
          halt 200, "ok: no allocations changed\r\n" if r.cmd_tuples < 1
        end
      end
      rebalance

      request.body.rewind
      data = request.body.read
      begin
        obj = JSON.parse(data, :symbolize_names => true)
        if obj[:reason]
          $db_pool.with do |db|
            type = 'idle'
            reason = obj[:reason]
            obj.delete(:reason)
            r = db.exec_params('insert into alloc_reports
              (allocation_id, time, type, reason, data)
              values ($1, now(), $2, $3, $4)',
              [alloc[:id], type, reason, JSON.dump(obj)])
            halt 500, "error: bad insert\r\n" if r.cmd_tuples < 1
          end
        end
      rescue Exception => ex
        $log.debug("worker #{hostname} idle report failed body parsing: #{ex.inspect}")
      end

      "ok: worker #{hostname} marked idle\r\n"
    end

    post '/worker/busy' do
      halt 403, "access denied\r\n" unless @auth.valid? and @auth.key_info[:type] == :worker
      hostname = @auth.key_info[:hostname]
      $log.info("worker #{hostname} reporting busy")
      alloc = nil
      $db_pool.with do |db|
        r = db.exec_params('select * from allocations
          where worker_hostname = $1 and state != \'closed\'', [hostname])
        halt 200, "ok: no allocations changed\r\n" if r.ntuples < 1

        alloc = r[0].symbolize

        if alloc[:state] == 'allocated'
          r = db.exec_params('update allocations
            set state = \'busy\' where id = $1 and state = \'allocated\'',
            [alloc[:id]])
          halt 200, "ok: no allocations changed\r\n" if r.cmd_tuples < 1
        end
      end

      request.body.rewind
      data = request.body.read
      begin
        obj = JSON.parse(data, :symbolize_names => true)
        if obj[:reason]
          $db_pool.with do |db|
            type = 'busy'
            reason = obj[:reason]
            obj.delete(:reason)
            r = db.exec_params('insert into alloc_reports
              (allocation_id, time, type, reason, data)
              values ($1, now(), $2, $3, $4)',
              [alloc[:id], type, reason, JSON.dump(obj)])
            halt 500, "error: bad insert\r\n" if r.cmd_tuples < 1
          end
        end
      rescue Exception => ex
        $log.debug("worker #{hostname} busy report failed body parsing: #{ex.inspect}")
      end

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
      hostname = r[0]['hostname']
      halt 403, "invalid provision token\r\n" if r.ntuples < 1
      $log.info("worker #{hostname} uploaded auth key, continuing with provisioning")
      "ok: worker auth key saved for #{hostname}\r\n"
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
        allocated: alloc[:allocated],
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
          $log.info("user #{zone[:owner]} (#{zone[:id]}) denied due to quota")
          used = Duration.new(minutes: quota[:used_mins])
          limit = Duration.new(minutes: quota[:quota_mins])
          halt 429, "user '#{zone[:owner]}' is over time quota (used #{used} out of #{limit})\r\n"
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
          $log.info("starting new allocation for #{zone[:owner]} (#{zone[:id]}")
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
          # $dbssh_pool.with do |dbssh|
          #   dbssh.exec_params('update users
          #     set comment = NULL
          #     where id = $1', [r[0]['ssh_user_id']])
          # end
        end
      end

      return "ok: allocation #{alloc_id} is now #{r[0]['state']} on #{r[0]['hostname']}\n"
    end
  end
end
