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
    not s.tags.find do |t|
      t.key == 'Name' and (
        t.value.include?('public') or t.value.include?('se-2b')
      )
    end
  end.shuffle.first

  res = $ec2.describe_key_pairs(key_names: [$ec2keyname])
  key = res.key_pairs.first

  xusers = get_config(:xusers).split

  script = <<EOS
#!/bin/bash
set -ex
log=/var/log/userdata-script
touch ${log}
chmod 0600 ${log}
exec >>${log} 2>&1

# stop background upgrades
systemctl stop unattended-upgrades.service
systemctl stop apt-daily-upgrade.timer
systemctl stop apt-daily.timer

# stop docker etc
for x in docker.service containerd.service snapd.service docker.socket snapd.socket; do
  systemctl stop ${x}
  systemctl disable ${x}
done

# xusers
groupadd xusers
for user in #{xusers.join(' ')}; do
  useradd -g xusers -s /bin/bash -m ${user}
  mkdir -p /home/${user}/.ssh
  curl -o /home/${user}/.ssh/authorized_keys https://api.uqcloud.net/sshkeys/none/${user}
done
echo "%xusers ALL=(ALL) NOPASSWD: ALL" | tee -a /etc/sudoers

# delete the default ubuntu user
userdel -fr ubuntu

# basic packages
apt-get update
#apt-get upgrade -y
apt-get install -y nodejs npm diod munge ruby cachefilesd
npm install -g sshpk

# npm refuses to install from git+https now
cd /usr/local/lib
git clone https://github.com/eait-itig/node-smartdc-auth
cd node-smartdc-auth
npm install
npm install -g .
chmod -R a+rX /usr/local/lib/node-smartdc-auth

# set up auth key
mkdir -p /var/lib/auth-keys/keys
chmod 0700 /var/lib/auth-keys/keys
ssh-keygen -t ecdsa -b 256 -P '' -C $(hostname) -f /var/lib/auth-keys/keys/default
mkdir -p /var/lib/auth-keys/sockets
curl -T /var/lib/auth-keys/keys/default.pub http://#{$myaddr}:443/worker/provision/#{token}

cat >/etc/systemd/system/auth-agent.service <<EOF
[Unit]
Description=ssh-agent for auth to control system
After=network.target

[Service]
User=root
Environment=SSH_AUTH_SOCK=/var/lib/auth-keys/sockets/default
Type=forking
ExecStart=/usr/bin/ssh-agent -a /var/lib/auth-keys/sockets/default
PermissionsStartOnly=true
ExecStartPost=/usr/bin/ssh-add /var/lib/auth-keys/keys/default
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable auth-agent
systemctl start auth-agent

KEYID=$(ssh-keygen -l -f /var/lib/auth-keys/keys/default.pub | awk '{print $2}')

echo 'export SSH_AUTH_SOCK=/var/lib/auth-keys/sockets/default' >/etc/profile.d/authkeys.sh
echo "export SDC_KEY_ID=${KEYID}" >>/etc/profile.d/authkeys.sh
echo "export SDC_ACCOUNT=$(hostname)" >>/etc/profile.d/authkeys.sh
source /etc/profile.d/authkeys.sh

# conda env
mkdir /opt/dlami/nvme/conda
mkdir /conda
mount --bind /opt/dlami/nvme/conda /conda

#curl https://stluc.manta.uqcloud.net/comp4703/public/conda2.tar.gz | tar -C/ -zxf -
curl https://uq-comp4703.s3.ap-southeast-2.amazonaws.com/conda2.tar.gz | tar -C/ -zxf -
#curl -o /tmp/conda-install.sh https://repo.anaconda.com/miniconda/Miniconda3-py38_23.5.1-0-Linux-x86_64.sh
#bash /tmp/conda-install.sh -b -p -u /conda
#rm -f /tmp/conda-install.sh
#/conda/bin/conda install -y python=3.8
#/conda/bin/conda update -y conda
#/conda/bin/conda install -y --freeze-installed ipython matplotlib scipy
#/conda/bin/conda install -y --freeze-installed pytorch torchvision torchaudio pytorch-cuda=12.4 -c pytorch -c nvidia
#/conda/bin/conda install -y --freeze-installed numpy pandas seaborn scikit-learn nltk spacy transformers datasets umap-learn gensim  clean-text markdownify dataclassy gguf html5lib humanize jsons lxml nbconvert sentencepiece protobuf einops conllu torchmetrics conda-forge::pycocotools pytest elasticsearch streamlit rouge-score fire gitpython jiwer evaluate pillow sacrebleu rich
#/conda/bin/pip install -U librosa stanza albumentations colabtools wikitextparser warcio tensorflow_datasets timm subword-nmt seqeval elasticsearch tensorboard mteb

# set up the login user
groupadd -g 1000 comp4703
useradd -u 1000 -g comp4703 -G plugdev,video -s /bin/bash -m comp4703
mkdir -p /home/comp4703/.ssh
echo '#{$default_pubkey}' >/home/comp4703/.ssh/authorized_keys

chown -R comp4703 /conda

cat >>/usr/local/sbin/pam-session-setup <<EOF
#!/usr/bin/env ruby
require 'json'
require 'base64'
require 'logger'
require 'open3'

User = ENV['PAM_USER']
Action = ENV['PAM_TYPE']

LOCK_FILE = '/run/pam-session-setup.lock'
LOG_FILE = '/var/log/pam-session-setup.log'

exit 0 if %w{root #{xusers.join(' ')}}.include?(User)
exit 0 unless %w{open_session}.include?(Action)

def sh(cmd, input = nil)
    $log.info("CMD: \#{cmd}")
    $logfile.flush
    Open3.popen3(cmd) do |stdin, stdout, stderr, waiter|
        stdin.write(input) if not input.nil?
        stdin.close
        fds = [stdout, stderr]
        loop do
            rs, _, _ = IO.select(fds)
            rs.each do |fd|
                if fd.eof?
                    fds.delete(fd)
                    next
                end
                line = fd.readline.chomp
                if fd == stdout
                    $log.info('> ' + line)
                elsif fd == stderr
                    $log.error('> ' + line)
                end
            end
            break if fds.empty?
        end
        exit_status = waiter.value
        if exit_status != 0
            raise Exception.new("Command '\#{cmd}' exited with status \#{exit_status}")
        end
    end
end

$lock = File.open(LOCK_FILE, File::CREAT)
$lock.flock(File::LOCK_EX)

$logfile = File.open(LOG_FILE, File::WRONLY | File::APPEND | File::CREAT | File::SYNC)
$log = Logger.new($logfile)
$log.level = Logger::DEBUG

ENV['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
ENV['SSH_AUTH_SOCK'] = '/var/lib/auth-keys/sockets/default'
ENV['SDC_KEY_ID'] = '${KEYID}'
ENV['SDC_ACCOUNT'] = %x{hostname}.strip

zinfo = JSON.parse(%x{sdc-curl -s http://#{$myaddr}:443/worker/assignment})
zid = zinfo['zone_id']
zip = zinfo['zone_ip']

$log.info "setting up worker for \#{zinfo['owner']} (\#{zid})"

if not File.exist?('/etc/zoneid') or File.new('/etc/zoneid').read.strip != zid
  $log.info 'looks like a change of owner, killing processes'
  sh("pkill -u \#{User}")
  sh("pkill -U \#{User}")
  f = File.new('/etc/munge/munge.key', 'w')
  f.write Base64.decode64(zinfo['munge_key'])
  f.close
  sh("chown munge:munge /etc/munge/munge.key")
  sh("chmod 0600 /etc/munge/munge.key")
  sh("systemctl restart munge")
end

$log.info("mounting filesystems")
sh("mkdir -p /home/\#{zinfo['owner']}")
#puts " - /conda"
#%x{diodmount -n \#{zip}:/conda /conda -o cache=fscache,cachetag=conda,ro,noatime,async,nosuid,nodev}
$log.info("mounting /var/www")
sh("diodmount -n \#{zip}:/var/www /var/www -o noatime,async,nosuid,nodev")
if zinfo['owner']
  $log.info "mounting /home/\#{zinfo['owner']}"
  sh("diodmount -n \#{zip}:/home/\#{zinfo['owner']} /home/\#{zinfo['owner']} -o noatime,async,nosuid,nodev")
end

$log.info('writing zoneid file')
f = File.new('/etc/zoneid', 'w')
f.puts zid
f.close

$lock.flock(File::LOCK_UN)

exit 0
EOF
chmod a+x /usr/local/sbin/pam-session-setup

cat >>/etc/security/namespace.conf <<EOF
/tmp  /tmp/inst/    user:mntopts=nosuid,nodev  root,#{xusers.join(',')}
/var/tmp  /var/tmp/inst/  user:mntopts=nosuid,nodev  root,#{xusers.join(',')}
/dev/shm  /dev/shm/inst/  tmpfs:mntopts=nosuid,nodev,size=2g  root,#{xusers.join(',')}
/opt/dlami/nvme /opt/dlami/nvme/inst/ user  root,#{xusers.join(',')}
EOF
cat >>/etc/pam.d/common-session <<EOF
session required        pam_namespace.so
session required        pam_exec.so       /usr/local/sbin/pam-session-setup
EOF
cat >>/etc/pam.d/common-session-noninteractive <<EOF
session required        pam_namespace.so
session required        pam_exec.so       /usr/local/sbin/pam-session-setup
EOF

mkdir /opt/dlami/nvme/fscache
cat >/etc/cachefilesd.conf <<EOF
dir /opt/dlami/nvme/fscache
tag conda
brun 60%
bcull 55%
bstop 50%
EOF
cat >/etc/default/cachefilesd <<EOF
DAEMON_OPTS=""
RUN=yes
EOF
systemctl enable cachefilesd
systemctl restart cachefilesd

ln -s /opt/dlami/nvme /scratch
mkdir -p /var/www/notebooks
mkdir -p /conda

chmod -x /etc/update-motd.d/*
rm -f /etc/sudoers.d/90-cloud-init-users

sdc-curl -XPOST http://#{$myaddr}:443/worker/ready

exit 0
EOS
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
    ]
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

  aws_workers.each do |wname, info|
    next if db_workers[wname] and db_workers[wname][:state] != 'destroying'
    next if info[:state] == 'shutting-down'
    $log.warn("orphaned worker found in EC2, terminating: #{wname}")
    info[:inst].terminate
  end

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

  db_workers.each do |wname, info|
    next unless info[:state] == 'provisioning' and (Time.now - info[:state_change]) > 1800
    $log.warn("provision of #{wname} seems to be taking too long, will ignore it")
    db_workers.delete(wname)
  end

  states = Hash.new(0)
  db_workers.each do |wname, info|
    next unless aws_workers[wname] or info[:state] == 'provisioning'
    states[info[:state].to_sym] += 1
    states[:all] += 1
  end

  waiting = []

  charge_increment_mins = get_config(:charge_increment_mins).to_i

  allocations = Hash.new([])
  $db.exec('select * from allocations order by created asc') do |res|
    res.each do |row|
      row.symbolize!
      waiting << row if row[:state] == 'waiting'
      if row[:state] != 'waiting'
        $alloc_sockmap[row[:id]].each do |sock|
          sock.puts JSON.dump({
            :status => :ok,
            :allocation => row[:id],
            :state => row[:state]
          })
        end
        $alloc_sockmap.delete(row[:id])
      end

      next unless %w{allocated busy}.include?(row[:state])
      allocated = row[:allocated].to_datetime
      next if DateTime.now - allocated < Rational(3, 24*60)

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

      r = $dbssh.exec_params('select * from sessions
        where host_id = $1 and user_id = $2',
        [row[:ssh_host_id], row[:ssh_user_id]])
      action = :unallocate
      r.each do |sess|
        sess.symbolize!
        if sess[:stopped_at].nil? and sess[:status] != 'closed'
          action = nil
        end
        created = sess[:created_at].to_datetime
        if DateTime.now - created < Rational(3, 24*60)
          action = :unbusy unless action.nil?
        end
        next unless sess[:stopped_at]
        stopped = sess[:stopped_at].to_datetime
        if DateTime.now - stopped < Rational(3, 24*60)
          action = :unbusy unless action.nil?
        end
      end

      next unless action
      if action == :unbusy
        $db.exec('begin')
        $db.exec_params('update workers
          set state = $2, state_change = now()
          where hostname = $1',
          [row[:worker_hostname], 'assigned'])
        $db.exec_params('update allocations set state = $2
          where id = $1', [row[:id], 'allocated'])
        $db.exec('commit')
      elsif action == :unallocate
        unallocate row[:id]
        states[:assigned] -= 1
        states[:ready] += 1
      end
    end
  end

  # assign any waiting allocations to spares if we have them
  while not waiting.empty? and states[:ready] > 0
    alloc = waiting.shift
    wname, info = db_workers.find { |wname, info|
      info[:state] == 'ready' }
    info[:state] = 'assigned'
    states[:ready] -= 1
    states[:assigned] += 1
    allocate alloc[:id], wname
  end

  pool_max = get_config(:pool_max).to_i
  pool_spares = get_config(:pool_spares).to_i
  pool_idle_mins = get_config(:pool_idle_mins).to_i

  # next work out if we need more spares, and if so, how many
  spares = states[:provisioning] + states[:ready]
  total = states[:all]
  $log.debug("spares = %d, total = %d (want spares = %d, max = %d)" % [
    spares, total, pool_spares, pool_max])

  want = waiting.size + pool_spares - spares
  limit = pool_max - total
  $log.debug("want extras = %d, limit = %d" % [want, limit])
  want = limit if want > limit

  # provision new instances!
  want.times { provision }

  # finally, check for any extra idle spares we can terminate
  if states[:ready] > pool_spares
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
      break if states[:ready] <= pool_spares
    end
  end
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
     "ssh://comp4703@#{worker[:vpn_addr]}", 'everything'])
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

  $alloc_sockmap[alloc_id].each do |sock|
    sock.puts JSON.dump({
      :status => :ok,
      :allocation => alloc_id,
      :state => 'allocated'
    })
  end
  $alloc_sockmap.delete(alloc_id)
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
    else
      sock.puts(JSON.dump({:status => :error, :reason => 'Invalid operation'}))
    end
  end
  rebalance if need_rebal
end
