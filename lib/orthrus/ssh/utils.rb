module Orthrus::SSH
  module Utils
    def self.write_bignum(bn)
      # Cribbed from net-ssh
      if bn.zero?
        return [0].pack("N")
      else
        buf = bn.to_s(2)
        if buf.getbyte(0)[7] == 1
          return [buf.length+1, 0, buf].pack("NCA*")
        else
          return [buf.length, buf].pack("NA*")
        end
      end
    end

    def self.write_string(str)
      [str.size].pack("N") + str
    end

    def self.sha1_hash(data)
      OpenSSL::Digest::SHA1.hexdigest data
    end

  end
end
