require 'openssl'
require 'ssh_data'

module HttpSignatures
  module Algorithm

    class Ecdsa
      def initialize(digest_name)
        @digest_name = digest_name
      end

      def name
        "ecdsa-#{@digest_name}"
      end

      def sign(key, data)
        pkey = nil
        begin
          pkey = OpenSSL::PKey::EC.new(public_key(key))
        rescue ArgumentError, OpenSSL::PKey::ECError
          pkey = SSHData::PublicKey.parse_openssh(public_key(key)).openssl
        end
        pkey.sign(@digest_name, data)
      end
      def verify(key, sign, data)
        pkey = nil
        begin
          pkey = OpenSSL::PKey::EC.new(public_key(key))
        rescue ArgumentError, OpenSSL::PKey::ECError
          pkey = SSHData::PublicKey.parse_openssh(public_key(key)).openssl
        end
        pkey.verify(@digest_name, sign, data)
      end

      def private_key(key)
        key.fetch(:private_key)
      end
      def public_key(key)
        key.fetch(:public_key)
      end
    end

    class <<self
      alias_method :orig_create, :create
    end
    def self.create(name)
      case name
      when 'ecdsa-sha256' then Ecdsa.new('sha256')
      when 'ecdsa-sha384' then Ecdsa.new('sha384')
      when 'ecdsa-sha512' then Ecdsa.new('sha512')
      else return self.orig_create(name)
      end
    end

  end

  class VerificationAlgorithm
    class Ecdsa
      def initialize(algorithm)
        @algorithm = algorithm
      end

      def valid?(message:, key:, header_list:, provided_signature_base64:)
        @algorithm.verify(
          key.secret,
          Base64.strict_decode64(provided_signature_base64),
          SigningString.new(
            header_list: header_list,
            message: message,
          ).to_str
        )
      end
    end
    class <<self
      alias_method :orig_create, :create
    end
    def self.create(algorithm)
      case algorithm
      when HttpSignatures::Algorithm::Ecdsa then Ecdsa.new(algorithm)
      else return self.orig_create(algorithm)
      end
    end
  end
end
