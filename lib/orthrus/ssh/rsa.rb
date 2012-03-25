require 'orthrus/ssh/key'

module Orthrus::SSH
  class RSAPrivateKey < PrivateKey
    def initialize(k)
      super k, OpenSSL::Digest::SHA1
    end

    def public_identity
      d = Utils.write_string("ssh-rsa") +
          Utils.write_bignum(@key.e) +
          Utils.write_bignum(@key.n)

      [d].pack("m").gsub("\n","")
    end
  end

  class RSAPublicKey < PublicKey
    def self.parse(data)
      raw = data.unpack("m").first

      type = Utils.read_string(raw)
      unless type == "ssh-rsa"
        raise "Unvalid key data"
      end

      k = OpenSSL::PKey::RSA.new
      k.e = Utils.read_bignum(raw)
      k.n = Utils.read_bignum(raw)

      new k
    end

    def initialize(k)
      super k, OpenSSL::Digest::SHA1
    end
  end
end
