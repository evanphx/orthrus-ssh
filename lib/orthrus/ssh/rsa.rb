require 'orthrus/ssh/key'

module Orthrus::SSH

  module RSA
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

  class RSAPrivateKey < PrivateKey
    include RSA
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

    include RSA
  end
end
