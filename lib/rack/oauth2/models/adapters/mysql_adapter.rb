# -*- coding: utf-8 -*-
require 'active_record'
require 'uuid'

module Rack
  module OAuth2
    class Server

      class Adapter
        SCHEMA_VERSION = 1 unless defined?(SCHEMA_VERSION)

        
        class MysqlMigration < ActiveRecord::Migration
          def self.up
            create_table :clients, :id => false do |t|
              t.string :id
              t.string :secret
              t.string :display_name
              t.string :link
              t.string :image_url
              t.string :redirect_uri
              t.string :scope
              t.text   :notes
              t.integer :revoked
              t.integer :tokens_granted, :default => 0
              t.integer :tokens_revoked, :default => 0
              t.integer :created_at
              t.integer :updated_at
            end
            execute "ALTER TABLE clients ADD PRIMARY KEY (id)"
            add_index(:clients, :display_name)
            add_index(:clients, :link)


            create_table :access_tokens, :id => false do |t|
              t.string :id
              t.string :identity
              t.string :client_id
              t.string :scope
              t.integer :expires_at
              t.integer :last_access
              t.integer :prev_access
              t.integer :revoked
              t.integer :created_at
              t.integer :updated_at
            end
            execute "ALTER TABLE access_tokens ADD PRIMARY KEY (id)"
            add_index(:access_tokens, :client_id)
            add_index(:access_tokens, :identity)

            create_table :access_grants, :id => false do |t|
              t.string :id
              t.string :identity
              t.string :client_id
              t.string :redirect_uri
              t.string :scope
              t.string :access_token
              t.integer :granted_at
              t.integer :expires_at
              t.integer :revoked
              t.integer :created_at
              t.integer :updated_at
            end
            execute "ALTER TABLE access_grants ADD PRIMARY KEY (id)"
            add_index(:access_grants, :client_id)
            
            create_table :auth_requests do |t|
              t.integer :id
              t.string :redirect_uri
              t.string :client_id
              t.string :scope
              t.string :state
              t.string :response_type
              t.string :grant_code
              t.string :access_token
              t.integer :authorized_at
              t.integer :revoked
              t.integer :created_at
              t.integer :updated_at
            end
            add_index(:auth_requests, :client_id)

            create_table :schema_migrations do |t|
              t.string :version
            end
            execute("INSERT INTO schema_migrations (version) VALUES (#{Adapter::SCHEMA_VERSION})")
          end
        end
        
        def self.connect!(uri)
          db_uri = URI.parse(uri)
          ActiveRecord::Base.establish_connection({
                     'adapter'   =>  'mysql2',
                     'encoding'  =>  'utf8',
                     'reconnect' =>  true,
                     'database'  =>  db_uri.path.sub(/\//,''),
                     'pool'      =>  5,
                     'username'  =>  db_uri.user,
                     'password'  =>  db_uri.password
                                                  })
          ActiveRecord::Migration.verbose = true
          puts "current_version: #{ActiveRecord::Migrator.current_version}"
          puts "SCHEMA_VERSION: #{SCHEMA_VERSION}"
          if ActiveRecord::Migrator.current_version < SCHEMA_VERSION
            puts "Running migration"
            MysqlMigration.up
            puts "Migration done"
          end
          
          ActiveRecord::Base.connection
        end
      end
      

      ###############################################################################################


      class Client < ActiveRecord::Base
        set_primary_key :id
        before_create :sanitize_attributes_create
        before_save :serialize_scope

        validates_uniqueness_of :id

        class << self
          def find(args)
            super(args)
          rescue ActiveRecord::RecordNotFound
          end

          def lookup(field)
            self.find(field)
          end

          def all
            self.order('display_name ASC').find(:all)
          end

          def delete(client_id)
            super("id = ?", client_id)
            AuthRequest.delete('client_id', client_id)
            AccessGrant.delete('client_id', client_id)
            AccessToken.delete('client_id', client_id)
          end
        end

        def scope
          s=super
          sc = (s.class == String ? s.split(',') : s)
          sc || []
        end

        def revoke!
          self.revoked = Time.now.to_i
          self.save
          
          request = AuthRequest.where(:client_id => id).first
          request.update_attributes(:revoked => self.revoked) if request

          grant = AccessGrant.where(:client_id => id).first
          grant.update_attributes(:revoked => self.revoked) if grant

          token = AccessToken.where(:client_id => id).first
          token.update_attributes(:revoked => self.revoked) if token
        end

        def update_attrs(args)
          self.update_attributes(sanitize_attributes_update(args))
        end
        
        protected
        def sanitize_attributes_create
          self.id = UUID.generate(:compact)
          self.secret = Server.secure_random unless self.secret
          self.redirect_uri = Server::Utils.parse_redirect_uri(self.redirect_uri).to_s if self.redirect_uri
          
        end

        def serialize_scope
          self.scope = Server::Utils.normalize_scope(self.scope).join(',') if self.scope
          self.created_at = Time.now.to_i unless self.created_at
          self.updated_at = Time.now.to_i
        end

        def sanitize_attributes_update(args)
          fields = [:display_name, :link, :image_url, :notes].inject({}) { |h,k| v = args[k]; h[k] = v if v; h }
          fields[:redirect_uri] = Server::Utils.parse_redirect_uri(args[:redirect_uri]).to_s if args[:redirect_uri]
          fields
        end
      end

      ###############################################################################################

      class AccessToken < ActiveRecord::Base
        set_primary_key :id
        belongs_to :client
        before_create :set_id
        before_save :serialize_scope

        def token
          self.id
        end
        
        class << self
          def from_token(token_)
            self.where(:revoked => nil, :id => token_).first
          end

          def get_token_for(identity, client, scope, expires = nil)
            raise ArgumentError, "Identity must be String or Integer" unless String === identity || Integer === identity
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            token = self.where( :identity=>identity, :scope=>scope.join(','), :client_id=>client.id, :revoked=>nil).first
            unless token
              
              expires_at = Time.now.to_i + expires if expires && expires != 0
              attrs = {  :identity=>identity, :scope=>scope.join(','),
                :client_id=>client.id, :expires_at=>expires_at, :revoked=>nil }

              token = self.create(attrs)
            end
            tokens_granted = client.tokens_granted + 1
            client.update_attributes(:tokens_granted => tokens_granted)

            token
          end

          def from_identity(identity)
            self.where(:identity => identity).all
          end

          def for_client(client_id, offset = 0, limit = 100)
            self.offset(offset).limit(limit).where(:client_id => client_id).all
          end

          alias :ar_count :count
          
          def count(filter={})
            select = {}
            if filter[:days]
              now = Time.now.to_i
#              range = { :$gt=>now - filter[:days] * 86400, :$lte=>now }
              range = ((now - filter[:days] * 86400)..now)
              select[ filter[:revoked] ? :revoked : :created_at ] = range
              
            elsif filter.has_key?(:revoked)
#              select[:revoked] = filter[:revoked] ? { :$ne=>nil } : { :$eq=>nil }
              select[:revoked] = filter[:revoked] ? 'IS NOT NULL' : nil
            end
            select[:client_id] = filter[:client_id] if filter[:client_id]

            #            self.ar_count
          
            self.where(select).ar_count
          end

          def historical(filter={})
            # TODO:
          end
          
        end
        
        def access!
          today = (Time.now.to_i / 3600) * 3600
          if last_access.nil? || last_access < today
            self.update_attributes(:last_access=>today, :prev_access=>last_access)
          end
        end

        # Revokes this access token.
        def revoke!
          self.revoked = Time.now.to_i
          self.save
          tokens_revoked = self.client.tokens_revoked + 1
          self.client.update_attributes(:tokens_revoked => tokens_revoked)
        end

        def scope
          s=super
          sc = (s.class == String ? s.split(',') : s)
          sc || []
        end
        protected
        def serialize_scope
          self.scope = Server::Utils.normalize_scope(self.scope).join(',') if self.scope
          self.created_at = Time.now.to_i unless self.created_at
          self.updated_at = Time.now.to_i
        end
        def set_id
          self.id = Server.secure_random
        end
      end

      ###############################################################################################

      class AccessGrant < ActiveRecord::Base
        set_primary_key :id
        belongs_to :client
        before_create :set_id
        before_save :serialize_scope

        def code
          self.id
        end
        
        class << self
          def from_code(code)
            self.where(:id => code, :revoked => nil).first
          end

          alias :ar_create :create

          def create(identity, client, scope, redirect_uri = nil, expires = nil)
            raise ArgumentError, "Identity must be String or Integer" unless String === identity || Integer === identity
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            expires_at = Time.now.to_i + (expires || 300)
            fields = { :identity=>identity, :scope=>scope,
              :client_id=>client.id, :redirect_uri=>client.redirect_uri || redirect_uri,
              :created_at=>Time.now.to_i, :expires_at=>expires_at, :granted_at=>nil,
              :access_token=>nil, :revoked=>nil }

            ar_create(fields)
          end
        end
    
        def authorize!(expires_in = nil)
          raise InvalidGrantError, "You can't use the same access grant twice" if self.access_token || self.revoked
          raise InvalidGrantError unless client
          
          access_token = AccessToken.get_token_for(identity, client, scope, expires_in)
          self.access_token = access_token.token
          self.granted_at = Time.now.to_i
          self.save
          access_token
        end
        
        def revoke!
          self.revoked = Time.now.to_i
          self.save
        end

        def scope
          s=super
          sc = (s.class == String ? s.split(',') : s)
          sc || []
        end
        protected
        def serialize_scope
          self.scope = Server::Utils.normalize_scope(self.scope).join(',') if self.scope
          self.created_at = Time.now.to_i unless self.created_at
          self.updated_at = Time.now.to_i
        end
        def set_id
          self.id = Server.secure_random
        end
          
      end

      ###############################################################################################

      class AuthRequest < ActiveRecord::Base
        belongs_to :client
        before_save :serialize_scope
        
        class << self
          def find(args)
            super(args)
          rescue ActiveRecord::RecordNotFound
          end
          
          def create(client, scope, redirect_uri, response_type, state)
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            fields = { :client_id=>client.id, :scope=>scope, :redirect_uri=>client.redirect_uri || redirect_uri,
              :response_type=>response_type, :state=>state,
              :grant_code=>nil, :authorized_at=>nil,
              :created_at=>Time.now.to_i, :revoked=>nil }
            super(fields)
          end
        end

        def grant!(identity, expires_in = nil)
          raise ArgumentError, "Must supply a identity" unless identity
          return if self.revoked
          return unless client

          self.authorized_at = Time.now.to_i
          if self.response_type == "code" # Requested authorization code
            access_grant = AccessGrant.create(identity, client, scope, redirect_uri)
            self.grant_code = access_grant.code
            self.save

          else # Requested access token
            access_token = AccessToken.get_token_for(identity, client, scope, expires_in)
            self.access_token = access_token.token
            self.save
          end
          true
        end

        def deny!
          self.authorized_at = Time.now.to_i
          self.save
        end

        def scope
          s=super
          sc = (s.class == String ? s.split(',') : s)
          sc || []
        end
        protected
        def serialize_scope
          self.scope = Server::Utils.normalize_scope(self.scope).join(',') if self.scope
          self.created_at = Time.now.to_i unless self.created_at
          self.updated_at = Time.now.to_i
        end
      end

      ###############################################################################################

    end
  end
end
