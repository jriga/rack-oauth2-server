require "uri"
require "openssl"
require "rack/oauth2/server/errors"
require "rack/oauth2/server/utils"

module Rack
  module OAuth2
    class Server

      class << self
        # Create new instance of the klass and populate its attributes.
        def new_instance(klass, fields)
          return unless fields
          instance = klass.new
          fields.each do |name, value|
            instance.instance_variable_set :"@#{name}", value
          end
          instance
        end

        # Long, random and hexy.
        def secure_random
          OpenSSL::Random.random_bytes(32).unpack("H*")[0]
        end
        
        # @private
        def create_indexes(&block)
          if block
            @create_indexes ||= []
            @create_indexes << block
          elsif @create_indexes
            @create_indexes.each do |block|
              block.call
            end
            @create_indexes = nil
          end
        end
 
        def database
          return @database if @database
          raise "No database Configured. You must configure it using Server.options.database = (mongodb://username:password@localhost:27017/database || mysql://username:password@localhost:3306/database)" unless Server.options.database
          
          begin
            db_uri =  URI.parse(Server.options.database)
            
            require ::File.dirname(__FILE__) + "/models/adapters/#{db_uri.scheme}_adapter"
            @database_adapter = db_uri.scheme
            @database = Adapter.connect!(Server.options.database)
#          rescue
#            raise "Unknown database adapter '#{db_uri.scheme}'. Use mongodb://username:password@localhost:27017/database or mysql://username:password@localhost:3306/database"
          end
          
        end
      end
 
    end
  end
end
