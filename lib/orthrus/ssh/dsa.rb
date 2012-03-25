require 'orthrus/ssh/key'

module Orthrus::SSH
  module DSA
    def initialize(k)
      super k, OpenSSL::Digest::DSS1
    end

    def public_identity(base64=true)
      d = Utils.write_string("ssh-dss") +
          Utils.write_bignum(@key.p) +
          Utils.write_bignum(@key.q) +
          Utils.write_bignum(@key.g) +
          Utils.write_bignum(@key.pub_key)

      return d unless base64

      [d].pack("m").gsub("\n","")
    end

    def type
      "ssh-dss"
    end
  end

  class DSAPrivateKey < PrivateKey
    include DSA

    def sign(data)
      sig = super data

      a1sig = OpenSSL::ASN1.decode sig

      sig_r = a1sig.value[0].value.to_s(2)
      sig_s = a1sig.value[1].value.to_s(2)

      if sig_r.length > 20 || sig_s.length > 20
        raise OpenSSL::PKey::DSAError, "bad sig size"
      end

      sig_r = "\0" * ( 20 - sig_r.length ) + sig_r if sig_r.length < 20
      sig_s = "\0" * ( 20 - sig_s.length ) + sig_s if sig_s.length < 20
      return sig_r + sig_s
    end
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

    # Adapted from net-ssh
    # Verifies the given signature matches the given data.
    def verify(sig, data)
      sig_r = sig[0,20].unpack("H*")[0].to_i(16)
      sig_s = sig[20,20].unpack("H*")[0].to_i(16)

      a1sig = OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::Integer(sig_r),
        OpenSSL::ASN1::Integer(sig_s)
      ])

      super a1sig.to_der, data
    end
  end

end
