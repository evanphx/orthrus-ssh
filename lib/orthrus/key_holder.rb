module Orthrus
  class KeyHolder
    def initialize
      @keys = {}
    end

    def add_key(name, key)
      @keys[name] = key
    end

    def key(name)
      @keys[name]
    end
  end
end
