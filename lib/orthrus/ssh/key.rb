module Orthrus::SSH
  class Key
    def initialize(k, digest)
      @key = k
      @digest = digest
    end

    def rsa?
      @key.kind_of? OpenSSL::PKey::RSA
    end

    def dsa?
      @key.kind_of? OpenSSL::PKey::DSA
    end
  end

  class PrivateKey < Key
    def sign(data)
      @key.sign @digest.new, data
    end

    def hexsign(data)
      [sign(data)].pack("m").gsub("\n","")
    end
  end

  class PublicKey < Key
    def verify(sign, data)
      @key.verify @digest.new, sign, data
    end

    def hexverify(sign, data)
      verify sign.unpack("m").first, data
    end
  end

end
