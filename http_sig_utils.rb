require 'json'
require 'ssh_data'
require 'http_signatures'

class FingerprintKeyStore < HttpSignatures::KeyStore
  def initialize(key_hash)
    @fpidx = {}
    super(key_hash)
    key_hash.each do |id, k|
      kk = SSHData::PublicKey.parse_openssh(k.fetch(:public_key))
      @fpidx[kk.fingerprint(md5: true).downcase] = id
    end
  end

  def fetch(id)
    return @keys.fetch(id) if @keys.has_key?(id)
    fp = id.split('/').last.downcase
    return @keys.fetch(@fpidx[fp]) if @fpidx.has_key?(fp)
    raise KeyError.new("key not found: #{id}")
  end
end

class RackMessageWrapper
  def initialize(request:)
    @req = request
  end

  def fetch(key)
    @req.get_header("HTTP_#{key.upcase.gsub('-','_')}")
  end

  def [](key)
    fetch(key)
  end

  def method
    @req.get_header('REQUEST_METHOD')
  end

  def path
    @req.get_header('REQUEST_PATH')
  end
end

class SSOVerification
  def initialize(request:, admin_users: [])
    @req = request
    @admins = admin_users
    @user = @req.get_header('HTTP_X_UQ_USER')
    blob = @req.get_header('HTTP_X_KVD_PAYLOAD')
    begin
      @blob = JSON.parse(blob, :symbolize_names => true)
    rescue Exception
      @blob = nil
    end
  end

  def valid?
    not @user.nil? and not @blob.nil?
  end

  def is_admin?
    @admins.include?(@user) or @blob[:groups].include?('eait:itig')
  end

  def key_info
    {:type => :sso, :user => @user, :admin => is_admin?}
  end
end

class AuthzVerification < HttpSignatures::Verification
  def initialize(message:, key_store:, required_headers:[])
    super(message: message, key_store: key_store)
    @reqhdrs = required_headers
  end

  def key_id
    parsed_parameters['keyId']
  end

  def key_info
    ki = key.secret.dup
    ki.delete(:private_key)
    return ki
  end

  def signature_header_present?
    hdr = fetch_header('Authorization')
    if not hdr.nil? and hdr =~ /^Signature /
      true
    else
      false
    end
  end

  def signed_header?(hdr)
    signedhdrs = header_list.to_a
    signedhdrs.include?(hdr)
  end

  def valid?
    begin
      return false if not super
      signedhdrs = header_list.to_a
      @reqhdrs.each { |h| return false unless signedhdrs.include?(h) }
      return true
    rescue KeyError
      return false
    end
  end

  def signature_header
    val = fetch_header('Authorization')
    val =~ /^Signature +(.+)$/
    $1
  end

  def parsed_parameters
    @_parsed_parameters ||= HttpSignatures::SignatureParametersParser.new(signature_header).parse
  end
end
