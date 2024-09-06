require 'aws-sdk-ec2'
require 'json'
require 'base64'
require 'socket'
require 'pg'
require 'securerandom'
require 'ssh_data'
require 'logger'
require 'etc'
require 'digest'
require 'erb'
require './utils'

ENV['SSH_AUTH_SOCK'] = '/run/zone-auth-agent.sock'
ENV['SDC_URL'] = 'https://cloudapi.gps-1.uqcloud.net'
ENV['SDC_KEY_ID'] = %x{ssh-add -l}.split("\n").first.split[1].strip
ENV['SDC_ACCOUNT'] = %x{mdata-get sdc:owner_uuid}.strip
ENV['SDC_USER'] = 'machine'

$log = Logger.new(STDOUT)
$log.level = Logger::DEBUG

$db = PG.connect(dbname: 'control')
$dbssh = PG.connect(dbname: 'sshportal')

$db.type_map_for_results = PG::BasicTypeMapForResults.new $db
$db.type_map_for_queries = PG::BasicTypeMapForQueries.new $db
$dbssh.type_map_for_results = PG::BasicTypeMapForResults.new $dbssh
$dbssh.type_map_for_queries = PG::BasicTypeMapForQueries.new $dbssh

def get_config(key)
  r = $db.exec_params('select * from config
    where key = $1', [key.to_s])
  raise "Config key not found: #{key}" if r.ntuples < 1
  r[0]['value']
end

$profile = 'comp4703';
$vpcname = 'comp4703-vpn'
$netname = 'comp4703-vpn'
$sockpath = '/run/comp4703-balancer.sock'
$ec2keyname = 'sshportal-default'

r = $dbssh.exec_params('select * from ssh_keys where name = $1', ['default'])
$default_keyid = r[0]['id']
$default_pubkey = r[0]['pub_key']

nets = %x{triton network list -j}.split("\n").map { |l|
  JSON.parse(l, :symbolize_names => true) }
$vpnnet = nets.find { |n| n[:name] == $netname }[:id]

nics = JSON.parse(%x{mdata-get sdc:nics}, :symbolize_names => true)
vpnif = nics.find { |n| n[:network_uuid] == $vpnnet }
$myaddr = vpnif[:ip]

$ec2 = Aws::EC2::Client.new(profile: $profile)
$ec2rsrc = Aws::EC2::Resource.new(client: $ec2)

$alloc_sockmap = Hash.new([])

$last_zone_hash = nil
def update_zone_keys
  vms = %x{triton inst ls -j}.split("\n").map { |l|
    JSON.parse(l, :symbolize_names => true) }
  zones = []
  vms.each do |vm|
    next unless vm[:nics]
    vpnnic = vm[:nics].find { |n| n[:network] == $vpnnet }
    next unless vpnnic
    next unless vm[:auth_key]
    zones << {
      :id => vm[:id],
      :vpn_addr => vpnnic[:ip],
      :auth_key => vm[:auth_key].strip,
      :owner => vm[:metadata][:owner]
    }
  end
  zone_hash = Digest::SHA256.hexdigest(JSON.dump(zones))
  return if zone_hash == $last_zone_hash
  $log.info('updating zone keys (%d zones now)' % zones.size)
  $db.exec('begin')
  $db.exec('truncate table zones')
  $db.prepare('insert-zone', 'insert into zones
    (id, vpn_addr, owner, auth_key)
    values ($1, $2, $3, $4)')
  zones.each do |z|
    r = $db.exec_prepared('insert-zone', [
      z[:id], z[:vpn_addr], z[:owner], z[:auth_key]
    ])
    raise "failed to insert zone: #{z.inspect}" unless r.cmd_tuples == 1
  end
  $db.exec('deallocate "insert-zone"')
  $db.exec('commit')
  $last_zone_hash = zone_hash
end

class TplParams
  def initialize(token)
    @token = token
    @xusers = get_config(:xusers).split
    @default_keyid = $default_keyid
    @default_pubkey = $default_pubkey
    @myaddr = $myaddr
  end
  def get_binding
    binding
  end
  def heredoc(fname)
    tpl = ERB.new(File.read("#{__dir__}/#{fname}"), trim_mode: '-')
    delim = SecureRandom.hex(4).upcase
    "<<\"#{delim}\"\n#{tpl.result(get_binding)}\n#{delim}\n"
  end
end

def provision
  $log.info('provisioning a new instance')
  token = SecureRandom.base64(18).gsub(/[^a-zA-Z0-9]/, '')

  res = $ec2.describe_images(filters: [
    {name: 'name', values: ['Deep Learning Base OSS Nvidia Driver GPU AMI (Ubuntu 22.04) *']},
    {name: 'architecture', values: ['x86_64']}
  ], owners: ['amazon'])
  img = res.images.sort_by { |i| i.creation_date }.last

  res = $ec2.describe_vpcs(:filters => [{name: 'tag:Name', values: [$vpcname]}])
  vpc = res.vpcs.first

  res = $ec2.describe_subnets(:filters => [{name: 'vpc-id', values: [vpc.vpc_id]}])
  subnet = res.subnets.filter do |s|
    s.tags.find do |t|
      t.key == 'Name' and (
        t.value.include?('se-2a') and not t.value.include?('public')
      )
    end
  end.shuffle.first

  res = $ec2.describe_key_pairs(key_names: [$ec2keyname])
  key = res.key_pairs.first

  params = TplParams.new(token)
  tpl = ERB.new(File.read("#{__dir__}/provision-script.erb"), trim_mode: '-')
  script = tpl.result(params.get_binding)
  escript = Base64.encode64(script)

  insts = $ec2rsrc.create_instances(
    image_id: img.image_id,
    min_count: 1,
    max_count: 1,
    key_name: key.key_name,
    instance_type: get_config(:instance_type),
    user_data: escript,
    network_interfaces: [
      { device_index: 0, associate_public_ip_address: false, subnet_id: subnet.subnet_id }
    ],
    tag_specifications: [
      {
        resource_type: 'instance',
        tags: [{ key: 'Control', value: 'true' }]
      }
    ],
    private_dns_name_options: {
      hostname_type: 'resource-name'
    }
  )
  inst = insts.first

  ip = inst.private_ip_address
  $db.exec_params('insert into workers (hostname, vpn_addr, provision_token) values ($1, $2, $3)',
    [inst.id, ip, token])
  $log.info("started provisioning #{inst.id} (#{ip})")
end

def rebalance
  $log.info("starting rebalance")

  update_zone_keys

  # first, reconcile AWS' list of worker instances with our db
  # make sure everything is up to date
  aws_workers = {}
  res = $ec2.describe_instances({
    filters: [
      { name: 'tag:Control', values: ['true'] }
    ]
  })
  res.reservations.each do |resv|
    resv.instances.each do |inst|
      next if inst.state.name == 'terminated'
      aws_workers[inst.instance_id] = {
        hostname: inst.instance_id,
        vpn_addr: inst.private_ip_address,
        state: inst.state.name,
        inst: Aws::EC2::Instance.new(inst.instance_id, client: $ec2)
      }
    end
  end
  db_workers = {}
  $db.exec('select * from workers') do |res|
    res.each do |row|
      row.symbolize!
      db_workers[row[:hostname]] = row
    end
  end

  # check for workers that are in EC2 but not in our DB
  # terminate these
  aws_workers.each do |wname, info|
    next if db_workers[wname] and db_workers[wname][:state] != 'destroying'
    next if info[:state] == 'shutting-down'
    $log.warn("orphaned worker found in EC2, terminating: #{wname}")
    info[:inst].terminate
  end

  # check for workers that are in our DB but don't exist in EC2
  # unallocate these and get rid of them
  db_workers.each do |wname, info|
    next if aws_workers[wname] and not %w{shutting-down terminated}.include?(aws_workers[wname][:state])
    next if info[:state] == 'provisioning' and (Time.now - info[:state_change]) < 30
    $log.warn("worker found in DB missing from EC2, deleting: #{wname}")
    r = $db.exec_params('select id, zone_id from allocations
      where worker_hostname = $1 and state in ($2, $3)',
      [wname, 'allocated', 'busy'])
    r.each do |alloc|
      alloc.symbolize!
      $log.info("allocation #{alloc[:id]} (for #{alloc[:zone_id]}) was on #{wname}")
      unallocate alloc[:id]
    end
    $db.exec_params('delete from workers where hostname = $1', [wname])
    db_workers.delete(wname)
  end

  # alert about workers that have spent too long in 'provisioning' state
  db_workers.each do |wname, info|
    next unless info[:state] == 'provisioning' and (Time.now - info[:state_change]) > 1800
    $log.warn("provision of #{wname} seems to be taking too long!")
  end

  states = Hash.new(0)
  db_workers.each do |wname, info|
    next unless aws_workers[wname] or info[:state] == 'provisioning'
    states[info[:state].to_sym] += 1
    states[:all] += 1
  end

  waiting = []

  charge_increment_mins = get_config(:charge_increment_mins).to_i

  # go through all the open allocations and check if they can be charged to
  # quota or unallocated (due to being idle)
  allocations = Hash.new([])
  $db.exec('select * from allocations
      where state != \'closed\' order by created asc') do |res|
    res.each do |row|
      row.symbolize!

      # collect all the 'waiting' allocations for us to use in the next step
      waiting << row if row[:state] == 'waiting'
      if row[:state] != 'waiting'
        # notify anyone waiting on this alloc, just in case there's a race
        notify_alloc(row[:id], row[:state], do_any: false)
      end

      next unless %w{allocated busy}.include?(row[:state])

      allocated = row[:allocated].to_datetime
      next if DateTime.now - allocated < Rational(3, 24*60)

      # first, update quota charging for this allocation
      charged = row[:allocated].to_datetime
      charged = row[:charged_until].to_datetime if row[:charged_until]
      now = DateTime.now
      if (now - charged) > Rational(charge_increment_mins, 24*60)
        mins = ((now - charged) / Rational(1, 24*60)).to_i
        $db.exec('begin')
        r = $db.exec_params('update quotas
          set used_mins = used_mins + $1
          where username = (select coalesce(owner,\'\') from zones where id = $2)
          returning username, used_mins, quota_mins', [mins, row[:zone_id]])
        quota = r[0].symbolize
        $db.exec_params('update allocations set
          charged_until = $1 where id = $2', [now, row[:id]])
        $db.exec('commit')
        if quota[:used_mins] > quota[:quota_mins]
          $log.info("user '#{quota[:username]}' is over quota, kicking them")
          $dbssh.exec_params('update users
            set comment = $1
            where id = $2',
            ['DISABLED', row[:ssh_user_id]])
        end
      end

      # now work out if we can unallocate it or not
      action = nil

      # work out the last time a connection was active on this allocation
      last_active = row[:last_connect] ? row[:last_connect].to_datetime : nil
      last_connect = nil
      r = $dbssh.exec_params('select * from sessions
        where host_id = $1 and user_id = $2',
        [row[:ssh_host_id], row[:ssh_user_id]])
      r.each do |sess|
        sess.symbolize!
        if sess[:stopped_at].nil? and sess[:status] != 'closed'
          last_active = DateTime.now
          break
        end
        created = sess[:created_at].to_datetime
        last_active = created if last_active.nil? or created > last_active
        last_connect = created if last_connect.nil? or created > last_connect
        next unless sess[:stopped_at]
        stopped = sess[:stopped_at].to_datetime
        last_active = stopped if last_active.nil? or stopped > last_active
      end

      if not last_active.nil?
        $db.exec_params('update allocations
          set last_connect = $2
          where id = $1', [row[:id], last_active])
      end

      # if the session was never connected to and it's been 15 min, kill it
      action = :unallocate if row[:state] == 'allocated' and last_active.nil? and
        DateTime.now - allocated > Rational(15, 24*60)

      # if the session is idle and the last active connection was >10 min ago, kill it
      action = :unallocate if row[:state] == 'allocated' and last_active and
        DateTime.now - last_active > Rational(10, 24*60)

      # if the session is idle and the last connection start was >15 min ago, kill it
      action = :unallocate if row[:state] == 'allocated' and last_connect and
        DateTime.now - last_connect > Rational(15, 24*60)

      # maximum job limit: 5 days
      action = :unallocate if row[:state] == 'busy' and
        DateTime.now - allocated > Rational(5, 1)

      if action == :unallocate
        unallocate row[:id]
        worker = db_workers[row[:worker_hostname]]
        states[worker[:state].to_sym] -= 1
        worker[:state] = :ready
        states[:ready] += 1
      end
    end
  end

  # assign any waiting allocations to spares if we have them
  while not waiting.empty? and states[:ready] > 0
    alloc = waiting.shift
    wname, info = db_workers.find { |wname, info|
      info[:state] == 'ready' }
    states[info[:state].to_sym] -= 1
    info[:state] = 'assigned'
    states[:assigned] += 1
    allocate alloc[:id], wname
  end

  pool_max = get_config(:pool_max).to_i
  pool_spares = get_config(:pool_spares).to_i
  pool_idle_mins = get_config(:pool_idle_mins).to_i

  # next work out if we need more spares, and if so, how many
  spares = states[:provisioning] + states[:ready]
  total = states[:all]

  want = waiting.size + pool_spares - spares
  limit = pool_max - total
  want = limit if want > limit

  r = $db.exec_params('select * from pool_size_history where time > $1',
    [Time.now - 3600])
  max_size = max_time = nil
  r.each do |sample|
    sample.symbolize!
    if max_size.nil? or sample[:total] > max_size
      max_time = sample[:time]
      max_size = sample[:total]
    end
  end
  min_size = 1
  unless max_time.nil?
    min_size = (max_size - ((Time.now - max_time) / 60.0) / pool_idle_mins.to_f).ceil
  end

  $db.exec_params('insert into pool_size_history (total, spares)
    values ($1, $2)', [total, spares])
  $db.exec_params('delete from pool_size_history where time <= $1',
    [Time.now - 24*3600*7])

  $log.debug("spares = %d, total = %d (want spares = %d, max = %d)" % [
    spares, total, pool_spares, pool_max])
  $log.debug("shrink limit = %d" % [min_size])
  $log.debug("want extras = %d, limit = %d" % [want, limit])

  # provision new instances!
  want.times { provision }

  # finally, check for any extra idle spares we can terminate
  if states[:ready] > pool_spares and states[:all] > min_size
    db_workers.each do |hostname, info|
      next unless info[:state] == 'ready'

      r = $db.exec_params('select max(closed) as lastclose from allocations
        where worker_hostname = $1', [hostname])
      lastclose = r[0]['lastclose']
      if not lastclose.nil?
        lastclose = lastclose.to_datetime
        next if (DateTime.now - lastclose) < Rational(pool_idle_mins, 24*60)
      end

      r = $db.exec_params('select max(allocated) as lastalloc from allocations
        where worker_hostname = $1', [hostname])
      lastalloc = r[0]['lastalloc']
      if not lastalloc.nil?
        lastalloc = lastalloc.to_datetime
        next if (DateTime.now - lastclose) < Rational(5, 24*60)
      end

      $log.info("terminating idle spare #{hostname}")
      $db.exec_params('update workers
        set state = $1, state_change = now()
        where hostname = $2',
        ['destroying', hostname])
      awsinfo = aws_workers[hostname]
      awsinfo[:inst].terminate
      states[:ready] -= 1
      states[:all] -= 1
      break if states[:ready] <= pool_spares or states[:all] <= min_size
    end
  end
  $log.info("rebalance finished")
end

def notify_alloc(alloc_id, state, do_any: true)
  $alloc_sockmap[alloc_id].each do |sock|
    begin
      sock.puts JSON.dump({
        :status => :ok,
        :allocation => alloc_id,
        :state => state
      })
    rescue
    end
  end
  $alloc_sockmap.delete(alloc_id)
  return unless do_any
  $alloc_sockmap[:any].each do |sock|
    begin
      sock.puts JSON.dump({
        :status => :ok,
        :allocation => alloc_id,
        :state => state
      })
    rescue
    end
  end
  $alloc_sockmap.delete(:any)
end

def unallocate(alloc_id)
  r = $db.exec_params('select * from allocations where id = $1', [alloc_id])
  alloc = r[0].symbolize

  $dbssh.exec('begin');
  $db.exec('begin');
  now = DateTime.now
  charged = alloc[:allocated].to_datetime
  if alloc[:charged_until]
    charged = alloc[:charged_until].to_datetime
  end
  mins = ((now - charged) / Rational(1, 24*60)).to_i
  r = $db.exec_params('update quotas
    set used_mins = used_mins + $1
    where username = (select coalesce(owner,\'\') from zones where id = $2)
    returning used_mins, quota_mins', [mins, alloc[:zone_id]])
  $db.exec_params('update allocations
    set charged_until = $2
    where id = $1', [alloc_id, now])

  r = $dbssh.exec_params('delete from user_keys where user_id = $1',
    [alloc[:ssh_user_id]])
  raise 'delete failed' unless r.cmd_tuples == 1

  r = $dbssh.exec_params('delete from user_user_groups where user_id = $1',
    [alloc[:ssh_user_id]])
  raise 'delete failed' unless r.cmd_tuples == 1
  r = $dbssh.exec_params('delete from host_host_groups where host_id = $1',
    [alloc[:ssh_host_id]])
  raise 'delete failed' unless r.cmd_tuples == 1
  r = $dbssh.exec_params('delete from user_group_acls where user_group_id = $1',
    [alloc[:ssh_user_group_id]])
  raise 'delete failed' unless r.cmd_tuples == 1
  r = $dbssh.exec_params('delete from host_group_acls where host_group_id = $1',
    [alloc[:ssh_host_group_id]])
  raise 'delete failed' unless r.cmd_tuples == 1

  r = $dbssh.exec_params('delete from user_groups where id = $1',
    [alloc[:ssh_user_group_id]])
  raise 'delete failed' unless r.cmd_tuples == 1
  r = $dbssh.exec_params('delete from host_groups where id = $1',
    [alloc[:ssh_host_group_id]])
  raise 'delete failed' unless r.cmd_tuples == 1

  $dbssh.exec_params('delete from sessions
    where user_id = $1 or host_id = $2',
    [alloc[:ssh_user_id], alloc[:ssh_host_id]])

  r = $dbssh.exec_params('delete from hosts where id = $1',
    [alloc[:ssh_host_id]])
  raise 'delete failed' unless r.cmd_tuples == 1
  r = $dbssh.exec_params('delete from users where id = $1',
    [alloc[:ssh_user_id]])
  raise 'delete failed' unless r.cmd_tuples == 1

  r = $dbssh.exec_params('delete from acls where id = $1',
    [alloc[:ssh_acl_id]])
  raise 'delete failed' unless r.cmd_tuples == 1

  r = $db.exec_params('update allocations set state = $2, closed = now()
    where id = $1', [alloc_id, 'closed'])
  raise 'failed to update state' unless r.cmd_tuples == 1
  r = $db.exec_params('update workers
    set state = $2, state_change = now()
    where hostname = $1',
    [alloc[:worker_hostname], 'ready'])
  raise 'failed to update worker state' unless r.cmd_tuples == 1

  $dbssh.exec('commit');
  $db.exec('commit');

  notify_alloc(alloc_id, 'closed')
end

def allocate(alloc_id, hostname)
  alloc = $db.exec_params('select * from allocations where id = $1', [alloc_id])[0].symbolize
  zone = $db.exec_params('select * from zones where id = $1', [alloc[:zone_id]])[0].symbolize
  worker = $db.exec_params('select * from workers where hostname = $1', [hostname])[0].symbolize

  $db.exec('begin')
  $dbssh.exec('begin')

  r = $db.exec_params('update allocations set
      state = $2, worker_hostname = $3, allocated = now()
      where id = $1', [alloc_id, 'allocated', hostname])
  raise "Invalid alloc id" unless r.cmd_tuples == 1
  r = $db.exec_params('update workers
    set state = $2, state_change = now()
    where hostname = $1', [hostname, 'assigned'])
  raise "Invalid worker hostname" unless r.cmd_tuples == 1

  r = $dbssh.exec_params('insert into acls
    (created_at, action, comment) values (now(), $1, $2)
    returning id', ['allow', "created for allocation #{alloc_id}"])
  raise 'failed to insert acl' unless r.cmd_tuples > 0
  acl_id = r[0]['id']

  host_name = zone[:owner] || zone[:id].split('-').first
  r = $dbssh.exec_params('insert into hosts
    (name, ssh_key_id, url, logging)
    values ($1, $2, $3, $4) returning id',
    [host_name, $default_keyid,
     "ssh://comp4703@#{worker[:vpn_addr]}", 'disabled'])
  raise 'failed to insert host' unless r.cmd_tuples > 0
  host_id = r[0]['id']

  r = $dbssh.exec_params('insert into host_groups
    (created_at, name, comment) values (now(), $1, $2)
    returning id',
    [hostname, "automatic control hostgroup for allocation #{alloc_id}"])
  host_group_id = r[0]['id']

  email = "#{zone[:owner] || 'nobody'}@#{zone[:id].split('-').first}"
  r = $dbssh.exec_params('insert into users
    (created_at, email, name) values (now(), $1, $2)
    returning id', ["#{zone[:id]}", email])
  user_id = r[0]['id']

  r = $dbssh.exec_params('insert into user_groups
    (created_at, name, comment) values (now(), $1, $2)
    returning id', ["#{zone[:id]}", "created for allocation #{alloc_id}"])
  user_group_id = r[0]['id']

  key = SSHData::PublicKey.parse_openssh(zone[:auth_key])
  keydata = Base64.encode64(key.rfc4253)
  r = $dbssh.exec_params('insert into user_keys
    (created_at, user_id, comment, authorized_key, key)
    values (now(), $1, $2, $3, decode($4, \'base64\'))',
    [user_id, "zone auth pubkey for #{zone[:id]}",
     zone[:auth_key].strip + "\n",
     keydata])
  raise "failed to insert pubkey" unless r.cmd_tuples == 1

  r = $dbssh.exec_params('insert into user_user_groups
    (user_id, user_group_id) values ($1, $2)',
    [user_id, user_group_id])
  raise 'insert failed' unless r.cmd_tuples == 1
  r = $dbssh.exec_params('insert into host_host_groups
    (host_id, host_group_id) values ($1, $2)',
    [host_id, host_group_id])
  raise 'insert failed' unless r.cmd_tuples == 1
  r = $dbssh.exec_params('insert into user_group_acls
    (user_group_id, acl_id) values ($1, $2)',
    [user_group_id, acl_id])
  raise 'insert failed' unless r.cmd_tuples == 1
  r = $dbssh.exec_params('insert into host_group_acls
    (host_group_id, acl_id) values ($1, $2)',
    [host_group_id, acl_id])
  raise 'insert failed' unless r.cmd_tuples == 1

  r = $db.exec_params('update allocations set
    ssh_user_id = $2, ssh_host_id = $3,
    ssh_host_group_id = $4, ssh_user_group_id = $5,
    ssh_acl_id = $6
    where id = $1',
    [alloc_id, user_id, host_id, host_group_id, user_group_id, acl_id])
  raise 'failed to upate allocation' unless r.cmd_tuples > 0

  $db.exec('commit')
  $dbssh.exec('commit')

  notify_alloc(alloc_id, 'allocated')
end

File.unlink($sockpath) if File.exist?($sockpath)
listensock = UNIXServer.new($sockpath)
File.chown(nil, Etc.getgrnam('www-data').gid, $sockpath)
File.chmod(0660, $sockpath)
$log.info("listening on #{$sockpath}")

socks = []
loop do
  need_rebal = false
  socks = socks.select { |s| not s.closed? }
  ret = IO.select(socks + [listensock], [], [], 10)
  if ret.nil?
    rebalance
    next
  end
  rs, _ws, errs = ret
  if rs.include?(listensock)
    sock = listensock.accept
    uid, gid = sock.getpeereid
    $log.info("accepted connection #{sock} from #{uid}:#{gid}")
    socks << sock
  end
  rs.each do |sock|
    next if sock == listensock
    line = nil
    begin
      line = sock.readline(1024)
    rescue Errno::ENOTCONN, EOFError
      sock.close
      socks.delete(sock)
      next
    end
    if line.nil? and not sock.eof?
      sock.puts(JSON.dump({:status => :error, :reason => 'Protocol (line length) error'}))
    end
    if line.nil?
      sock.close
      socks.delete(sock)
      next
    end
    begin
      obj = JSON.parse(line, :symbolize_names => true)
    rescue
      sock.puts(JSON.dump({:status => :error, :reason => 'Protocol error'}))
      socks.delete(sock)
      sock.close
      next
    end
    if obj[:operation] == 'rebalance'
      need_rebal = true
    elsif obj[:operation] == 'allocate'
      $alloc_sockmap[obj[:allocation]] += [sock]
      need_rebal = true
    elsif obj[:operation] == 'wait_any'
      $alloc_sockmap[:any] += [sock]
    else
      sock.puts(JSON.dump({:status => :error, :reason => 'Invalid operation'}))
    end
  end
  rebalance if need_rebal
end
