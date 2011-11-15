require 'sequel'
require 'uuid'

module Rack
  module OAuth2
    class Server

      class Adapter
        SCHEMA_VERSION = 1 unless defined?(SCHEMA_VERSION)

        class Migration
          def self.up(db)
            puts db.inspect
            puts "Running migration"
            
            db.create_table :clients do
              String :id, :primary_key => true
              String :secret, :null => false
              String :display_name
              String :link
              String :image_url
              String :redirect_uri
              String :scope
              String :notes, :text => true
              Integer :revoked
              Integer :tokens_granted, :default => 0
              Integer :tokens_revoked, :default => 0
              Integer :created_at
              Integer :updated_at

              index [:display_name, :link]
            end

            db.create_table :access_tokens  do
              String :token, :primary_key => true
              String :identity
              String :client_id, :null => false
              String :scope
              Integer :expires_at
              Integer :last_access
              Integer :prev_access
              Integer :revoked
              Integer :created_at
              Integer :updated_at

              index [:identity, :client_id]
            end

            db.create_table :access_grants do
              String :id, :primary_key => true
              String :identity
              String :client_id, :null => false
              String :redirect_uri
              String :scope
              String :access_token
              Integer :granted_at
              Integer :expires_at
              Integer :revoked
              Integer :created_at
              Integer :updated_at

              index [:identity, :client_id]
            end

            db.create_table :auth_requests do
              primary_key :id
              String :redirect_uri
              String :client_id, :null => false
              String :scope
              String :state
              String :response_type
              String :grant_code
              String :access_token
              Integer :authorized_at
              Integer :revoked
              Integer :created_at
              Integer :updated_at

              index [:client_id]
            end

            db.create_table :schema_migrations do
              String :version, :primary_key => true
            end
            puts "Migration done"
          end
        end

        class << self
          def connect!(uri)
            database = Sequel.connect(uri)
            version = current_version(database)

            puts "current_version: #{version}"
            puts "SCHEMA_VERSION: #{SCHEMA_VERSION}"
            if version < SCHEMA_VERSION
              database.transaction do
                Migration.up(database)
                database[:schema_migrations].insert(:version => SCHEMA_VERSION)
              end
            end
          
            database
          end

          private
          def current_version(db)
            db['SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1'].first[:version].to_i rescue 0
          end
        end
      end
      

      ###############################################################################################


      class Client 
        attr_reader :id, :secret, :display_name, :link, :image_url, :redirect_uri, :scope, :notes, :created_at, :updated_at, :revoked, :tokens_granted, :tokens_revoked

        class << self
          def find(args)
            attrs = table.filter(:id => args).first
            new(attrs) if attrs
          end

          def lookup(field)
            find(field) || find_by_displayname(field) || find_by_link(field)
          end

          def all
            table.order(:display_name).all.map{|e| new(e)}
          end

          def delete(id)
            table.filter(:id => id).delete
          end

          def create(attributes={})
            new(attributes).save
          end

          def table
            Server.database[:clients]
          end

          private
          def find_by_displayname(field)
            attrs = table.filter(:display_name => field).first
            new(attrs) if attrs
          end

          def find_by_link(field)
            attrs = table.filter(:link => field).first
            new(attrs) if attrs
          end
        end

        def initialize(attributes={})
          if attributes
            attributes[:redirect_uri] = Server::Utils.parse_redirect_uri(attributes[:redirect_uri]).to_s if attributes[:redirect_uri]
            attributes.each {|f,v| self.instance_variable_set(:"@#{f}", v)}
          end
          @tokens_granted ||= 0
          @tokens_revoked ||= 0
          @scope = Server::Utils.normalize_scope((attributes[:scope] rescue nil))
        end

        def save
          ds = Client.table.where(:id => @id).first
          if ds
            Client.table.where(:id => @id).update(self.to_hash.merge(:updated_at => Time.now.to_i))            
          else
            @id ||= UUID.generate(:compact)
            @created_at ||= Time.now.to_i
            @updated_at = @created_at
            @secret ||= Server.secure_random
            Client.table.insert(self.to_hash)
          end
          Client.new(Client.table.where(:id => @id).first)
        end

        def revoke!
          @revoked = Time.now.to_i
          save
          [:auth_requests, :access_grants, :access_tokens].each do |relation|
            Server.database[relation].filter(:client_id => id).update(:revoked => revoked)
          end
        end

        def to_hash
          hsh = Client.table.columns.inject({}) do |hsh, field|
            hsh[field] = self.send(field)
            hsh
          end
          hsh[:scope] = @scope.join(' ')
          hsh
        end

        def update_attrs(args)
          sanitize_attributes_update(args)
          save
        end
        
        protected
        def sanitize_attributes_update(args)
          fields = [:display_name, :link, :image_url, :notes].inject({}) { |h,k| v = args[k]; h[k] = v if v; h }
          fields[:redirect_uri] = Server::Utils.parse_redirect_uri(args[:redirect_uri]).to_s if args[:redirect_uri]
          fields.each {|f,v| self.instance_variable_set(:"@#{f}", v)}
        end
        
      end

      ###############################################################################################

      class AccessToken
        attr_reader :token, :identity, :client_id, :scope, :created_at, :updated_at, :expires_at, :revoked, :last_access, :prev_access
        alias :id :token
        
        class << self
          def from_token(token)
            attrs = table.where(:token => token).first
            new(attrs) if attrs 
          end

          def get_token_for(identity, client, scope, expires = nil)
            raise ArgumentError, "Identity must be String or Integer" unless String === identity || Integer === identity
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            attrs = table.filter(:identity => identity, :scope => scope.join(' '), :client_id => client.id, :revoked => nil).first
            token = nil
            token = new(attrs) if attrs
            
            unless token
              expires_at = Time.now.to_i + expires if expires && expires != 0
              attrs = {:token => Server.secure_random, :identity => identity, :scope => scope.join(' '),
                :client_id => client.id, :expires_at => expires_at, :revoked => nil}

              table.insert(attrs)
              token = new(table.where(:token => attrs[:token]).first)
            end
            Client.table.where(:id => client.id).update(:tokens_granted => (client.tokens_granted + 1))

            token
          end

          def from_identity(identity)
            table.filter(:identity => identity).all.map{|o| new(o)}
          end

          def for_client(client_id, offset = 0, limit = 100)
            table.limit(limit, offset).filter(:client_id => client_id).all.map{|o| new(o)}
          end

          def count(filter={})
            select = {}
            if filter[:days]
              now = Time.now.to_i
              range = ((now - filter[:days] * 86400)..now)
              select[ filter[:revoked] ? :revoked : :created_at ] = range
              
            elsif filter.has_key?(:revoked)

              select[:revoked] = filter[:revoked] ? 'IS NOT NULL' : nil
            end
            select[:client_id] = filter[:client_id] if filter[:client_id]

            table.filter(select).count
          end

          def historical(filter={})
            # TODO:
          end

          def table
            Server.database[:access_tokens]
          end
        end

        def initialize(attributes={})
          if attributes
            attributes.each {|f,v| self.instance_variable_set(:"@#{f}", v)}
          end
          @scope = Server::Utils.normalize_scope((attributes[:scope] rescue nil))
        end

        def save
          ds = AccessToken.table.where(:token => token).first
          if ds
            @updated_at = Time.now.to_i
            AccessToken.table.where(:token => token).update(self.to_hash)
          else
            @token = Server.secure_random
            @created_at ||= Time.now.to_i
            AccessToken.table.insert(self.to_hash)
          end
          AccessToken.new(AccessToken.table.where(:token => token).first)
        end

        def to_hash
          hsh = AccessToken.table.columns.inject({}) do |hsh, field|
            hsh[field] = self.send(field)
            hsh
          end
          hsh[:scope] = hsh[:scope].join(' ')
          hsh
        end
        
        def access!
          today = (Time.now.to_i / 3600) * 3600
          if last_access.nil? || last_access < today
            @prev_access = last_access
            @last_access = today
            save
          end
        end

        # Revokes this access token.
        def revoke!
          @revoked = Time.now.to_i
          save
          Client.table.where(:id => client_id).update(:tokens_revoked => (client.tokens_revoked + 1))
        end

        def client
          @client ||= Client.find(client_id)
        end

      end

      ###############################################################################################

      class AccessGrant
        attr_reader :id, :identity, :client_id, :redirect_uri, :scope, :created_at, :updated_at, :granted_at, :expires_at, :access_token, :revoked
        alias :code :id
        
        class << self
          def from_code(code)
            attrs = table.filter(:id => code, :revoked => nil).first
            new(attrs) if attrs
          end

          def create(identity, client, scope, redirect_uri = nil, expires = nil)
            raise ArgumentError, "Identity must be String or Integer" unless String === identity || Integer === identity
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            expires_at = Time.now.to_i + (expires || 300)
            fields = {:identity=>identity, :scope=>scope,
              :client_id=>client.id, :redirect_uri=>client.redirect_uri || redirect_uri,
              :created_at=>Time.now.to_i, :expires_at=>expires_at, :granted_at=>nil,
              :access_token=>nil, :revoked=>nil }

            new(fields).save
          end

          def table
            Server.database[:access_grants]
          end
        end

        def initialize(attributes={})
          if attributes
            attributes.each {|f,v| self.instance_variable_set(:"@#{f}", v)}
          end
          @scope = Server::Utils.normalize_scope((attributes[:scope] rescue nil))
        end

        def save
          ds = AccessGrant.table.where(:id => id).first
          if ds
            @updated_at = Time.now.to_i
            AccessGrant.table.where(:id => id).update(self.to_hash)
          else
            @id= Server.secure_random
            @created_at ||= Time.now.to_i
            @updated_at = @created_at
            AccessGrant.table.insert(self.to_hash)
          end
          AccessGrant.new(AccessGrant.table.where(:id => id).first)
        end

        def to_hash
          hsh = AccessGrant.table.columns.inject({}) do |hsh, field|
            hsh[field] = self.send(field)
            hsh
          end
          hsh[:scope] = hsh[:scope].join(' ')
          hsh
        end
    
        def authorize!(expires_in = nil)
          raise InvalidGrantError, "You can't use the same access grant twice" if access_token || revoked
          raise InvalidGrantError unless client
          
          access_token = AccessToken.get_token_for(identity, client, scope, expires_in)
          @access_token = access_token.token
          @granted_at = Time.now.to_i
          save
          access_token
        end
        
        def revoke!
          @revoked = Time.now.to_i
          save
        end

        def client
          @client ||= Client.find(client_id)
        end

      end

      ###############################################################################################

      class AuthRequest
        attr_reader :id, :client_id, :scope, :redirect_uri, :state, :created_at, :updated_at, :response_type, :grant_code, :access_token, :authorized_at, :revoked
        
        class << self
          def find(id)
            attrs = table.where(:id => id).first
            new(attrs) if attrs
          end

          def create(client, scope, redirect_uri, response_type, state)
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            fields = { :client_id=>client.id, :scope=>scope, :redirect_uri=>client.redirect_uri || redirect_uri,
              :response_type=>response_type, :state=>state,
              :grant_code=>nil, :authorized_at=>nil,
              :created_at=>Time.now.to_i, :revoked=>nil }
            
            new(fields).save
          end

          def table
            Server.database[:auth_requests]
          end
        end

        def initialize(attributes={})
           if attributes
             attributes.each {|f,v| self.instance_variable_set(:"@#{f}", v)}
           end
          @scope = Server::Utils.normalize_scope((attributes[:scope] rescue nil))
        end
        
        def save
          ds = AuthRequest.table.where(:id => id).first
          if ds

            @updated_at = Time.now.to_i
            AuthRequest.table.where(:id => id).update(self.to_hash)
          else

            @created_at ||= Time.now.to_i
            @updated_at = @created_at

            AuthRequest.table.insert(self.to_hash)
          end

          AuthRequest.new(AuthRequest.table.where(self.to_hash).first)
        end

        def to_hash
          hsh = AuthRequest.table.columns.inject({}) do |hsh, field|
            hsh[field] = self.send(field)
            hsh
          end
          hsh.delete(:id)
          hsh[:scope] = hsh[:scope].join(' ')
          hsh
        end
        
        def grant!(identity, expires_in = nil)
          raise ArgumentError, "Must supply a identity" unless identity
          return if revoked
          client = Client.find(client_id) or return

          @authorized_at = Time.now.to_i
          if response_type == "code" # Requested authorization code
            access_grant = AccessGrant.create(identity, client, scope, redirect_uri)
            @grant_code = access_grant.code
            save

          else # Requested access token
            access_token = AccessToken.get_token_for(identity, client, scope, expires_in)
            @access_token = access_token.token
            save
          end
          true
        end

        def deny!
          @authorized_at = Time.now.to_i
          save
        end
      end

      ###############################################################################################

    end
  end
end
