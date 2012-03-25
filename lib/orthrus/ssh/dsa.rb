require 'orthrus/ssh/key'

module Orthrus::SSH
  module DSA
    def initialize(k)
      super k, OpenSSL::Digest::DSS1
    end

    def public_identity
      d = Utils.write_string("ssh-dss") +
          Utils.write_bignum(@key.p) +
          Utils.write_bignum(@key.q) +
          Utils.write_bignum(@key.g) +
          Utils.write_bignum(@key.pub_key)

      [d].pack("m").gsub("\n","")
    end
  end

  class DSAPrivateKey < PrivateKey
    include DSA
  end

  class DSAPublicKey < PublicKey
    def self.parse(data)
      raw = data.unpack("m").first

      type = Utils.read_string(raw)
      unless type == "ssh-dss"
        raise "Unvalid key data"
      end

      k = OpenSSL::PKey::DSA.new
      k.p = Utils.read_bignum raw
      k.q = Utils.read_bignum raw
      k.g = Utils.read_bignum raw
      k.pub_key = Utils.read_bignum raw

      new k
    end

    include DSA
  end

end
