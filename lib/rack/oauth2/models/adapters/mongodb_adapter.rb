require 'mongo'

module Rack
  module OAuth2
    class Server

      class Adapter
        def self.connect!(uri)
          begin
            Mongo::Connection.from_uri(uri)
            raise 'This does not quite work yet!!'
          rescue
            db_uri = URI.parse(uri)
            db = Mongo::Connection.new(db_uri.host,db_uri.port).db(db_uri.path.sub(/^\//,''))
            db.authenticate(db_uri.user, db_uri.password) if db_uri.user
            db
          end
        end
      end

      class Client

        class << self
          # Authenticate a client request. This method takes three arguments,
          # Find Client from client identifier.
          def find(client_id)
            id = BSON::ObjectId(client_id.to_s)
            Server.new_instance self, collection.find_one(id)
          rescue BSON::InvalidObjectId
          end

          # Create a new client. Client provides the following properties:
          # # :display_name -- Name to show (e.g. UberClient)
          # # :link -- Link to client Web site (e.g. http://uberclient.dot)
          # # :image_url -- URL of image to show alongside display name
          # # :redirect_uri -- Registered redirect URI.
          # # :scope -- List of names the client is allowed to request.
          # # :notes -- Free form text.
          # 
          # This method does not validate any of these fields, in fact, you're
          # not required to set them, use them, or use them as suggested. Using
          # them as suggested would result in better user experience.  Don't ask
          # how we learned that.
          def create(args)
            redirect_uri = Server::Utils.parse_redirect_uri(args[:redirect_uri]).to_s if args[:redirect_uri]
            scope = Server::Utils.normalize_scope(args[:scope])
            fields =  { :display_name=>args[:display_name], :link=>args[:link],
                        :image_url=>args[:image_url], :redirect_uri=>redirect_uri,
                        :notes=>args[:notes].to_s, :scope=>scope,
                        :created_at=>Time.now.to_i, :revoked=>nil }
            if args[:id] && args[:secret]
              fields[:_id], fields[:secret] = BSON::ObjectId(args[:id].to_s), args[:secret]
              collection.insert(fields, :safe=>true)
            else
              fields[:secret] = Server.secure_random
              fields[:_id] = collection.insert(fields)
            end
            Server.new_instance self, fields
          end

          # Lookup client by ID, display name or URL.
          def lookup(field)
            id = BSON::ObjectId(field.to_s)
            Server.new_instance self, collection.find_one(id)
          rescue BSON::InvalidObjectId
            Server.new_instance self, collection.find_one({ :display_name=>field }) || collection.find_one({ :link=>field })
          end

          # Returns all the clients in the database, sorted alphabetically.
          def all
            collection.find({}, { :sort=>[[:display_name, Mongo::ASCENDING]] }).
              map { |fields| Server.new_instance self, fields }
          end

          # Deletes client with given identifier (also, all related records).
          def delete(client_id)
            id = BSON::ObjectId(client_id.to_s)
            Client.collection.remove({ :_id=>id })
            AuthRequest.collection.remove({ :client_id=>id })
            AccessGrant.collection.remove({ :client_id=>id })
            AccessToken.collection.remove({ :client_id=>id })
          end

          def collection
            prefix = Server.options[:collection_prefix]
            Server.database["#{prefix}.clients"]
          end
        end

        # Client identifier.
        attr_reader :_id
        alias :id :_id
        # Client secret: random, long, and hexy.
        attr_reader :secret
        # User see this.
        attr_reader :display_name
        # Link to client's Web site.
        attr_reader :link
        # Preferred image URL for this icon.
        attr_reader :image_url
        # Redirect URL. Supplied by the client if they want to restrict redirect
        # URLs (better security).
        attr_reader :redirect_uri
        # List of scope the client is allowed to request.
        attr_reader :scope
        # Free form fields for internal use.
        attr_reader :notes
        # Does what it says on the label.
        attr_reader :created_at
        # Timestamp if revoked.
        attr_accessor :revoked
        # Counts how many access tokens were granted.
        attr_reader :tokens_granted
        # Counts how many access tokens were revoked.
        attr_reader :tokens_revoked

        # Revoke all authorization requests, access grants and access tokens for
        # this client. Ward off the evil.
        def revoke!
          self.revoked = Time.now.to_i
          Client.collection.update({ :_id=>id }, { :$set=>{ :revoked=>revoked } })
          AuthRequest.collection.update({ :client_id=>id }, { :$set=>{ :revoked=>revoked } })
          AccessGrant.collection.update({ :client_id=>id }, { :$set=>{ :revoked=>revoked } })
          AccessToken.collection.update({ :client_id=>id }, { :$set=>{ :revoked=>revoked } })
        end

        def update_attrs(args)
          fields = [:display_name, :link, :image_url, :notes].inject({}) { |h,k| v = args[k]; h[k] = v if v; h }
          fields[:redirect_uri] = Server::Utils.parse_redirect_uri(args[:redirect_uri]).to_s if args[:redirect_uri]
          fields[:scope] = Server::Utils.normalize_scope(args[:scope])
          self.class.collection.update({ :_id=>id }, { :$set=>fields })
          self.class.find(id)
        end

        Server.create_indexes do
          # For quickly returning clients sorted by display name, or finding
          # client from a URL.
          collection.create_index [[:display_name, Mongo::ASCENDING]]
          collection.create_index [[:link, Mongo::ASCENDING]]
        end
      end



###############################################################################################


      # Access token. This is what clients use to access resources.
      #
      # An access token is a unique code, associated with a client, an identity
      # and scope. It may be revoked, or expire after a certain period.
      class AccessToken
        class << self

          # Find AccessToken from token. Does not return revoked tokens.
          def from_token(token)
            Server.new_instance self, collection.find_one({ :_id=>token, :revoked=>nil })
          end

          # Get an access token (create new one if necessary).
          #
          # You can set optional expiration in seconds. If zero or nil, token
          # never expires.
          def get_token_for(identity, client, scope, expires = nil)
            raise ArgumentError, "Identity must be String or Integer" unless String === identity || Integer === identity
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            unless token = collection.find_one({ :identity=>identity, :scope=>scope, :client_id=>client.id, :revoked=>nil })
              return create_token_for(client, scope, identity, expires)
            end
            Server.new_instance self, token
          end

          # Creates a new AccessToken for the given client and scope.
          def create_token_for(client, scope, identity = nil, expires = nil)
            expires_at = Time.now.to_i + expires if expires && expires != 0
            token = { :_id=>Server.secure_random, :scope=>scope,
                      :client_id=>client.id, :created_at=>Time.now.to_i,
                      :expires_at=>expires_at, :revoked=>nil }
            token[:identity] = identity if identity
            collection.insert token
            Client.collection.update({ :_id=>client.id }, { :$inc=>{ :tokens_granted=>1 } })
            Server.new_instance self, token
          end

          # Find all AccessTokens for an identity.
          def from_identity(identity)
            collection.find({ :identity=>identity }).map { |fields| Server.new_instance self, fields }
          end

          # Returns all access tokens for a given client, Use limit and offset
          # to return a subset of tokens, sorted by creation date.
          def for_client(client_id, offset = 0, limit = 100)
            client_id = BSON::ObjectId(client_id.to_s)
            collection.find({ :client_id=>client_id }, { :sort=>[[:created_at, Mongo::ASCENDING]], :skip=>offset, :limit=>limit }).
              map { |token| Server.new_instance self, token }
          end

          # Returns count of access tokens.
          #
          # @param [Hash] filter Count only a subset of access tokens
          # @option filter [Integer] days Only count that many days (since now)
          # @option filter [Boolean] revoked Only count revoked (true) or non-revoked (false) tokens; count all tokens if nil
          # @option filter [String, ObjectId] client_id Only tokens grant to this client
          def count(filter = {})
            select = {}
            if filter[:days]
              now = Time.now.to_i
              range = { :$gt=>now - filter[:days] * 86400, :$lte=>now }
              select[ filter[:revoked] ? :revoked : :created_at ] = range
            elsif filter.has_key?(:revoked)
              select[:revoked] = filter[:revoked] ? { :$ne=>nil } : { :$eq=>nil }
            end
            select[:client_id] = BSON::ObjectId(filter[:client_id].to_s) if filter[:client_id]
            collection.find(select).count
          end

          def historical(filter = {})
            days = filter[:days] || 60
            select = { :$gt=> { :created_at=>Time.now - 86400 * days } }
            select = {}
            if filter[:client_id]
              select[:client_id] = BSON::ObjectId(filter[:client_id].to_s)
            end
            raw = Server::AccessToken.collection.group("function (token) { return { ts: Math.floor(token.created_at / 86400) } }",
              select, { :granted=>0 }, "function (token, state) { state.granted++ }")
            raw.sort { |a, b| a["ts"] - b["ts"] }
          end

          def collection
            prefix = Server.options[:collection_prefix]
            Server.database["#{prefix}.access_tokens"]
          end
        end

        # Access token. As unique as they come.
        attr_reader :_id
        alias :token :_id
        # The identity we authorized access to.
        attr_reader :identity
        # Client that was granted this access token.
        attr_reader :client_id
        # The scope granted to this token.
        attr_reader :scope
        # When token was granted.
        attr_reader :created_at
        # When token expires for good.
        attr_reader :expires_at
        # Timestamp if revoked.
        attr_accessor :revoked
        # Timestamp of last access using this token, rounded up to hour.
        attr_accessor :last_access
        # Timestamp of previous access using this token, rounded up to hour.
        attr_accessor :prev_access

        # Updates the last access timestamp.
        def access!
          today = (Time.now.to_i / 3600) * 3600
          if last_access.nil? || last_access < today
            AccessToken.collection.update({ :_id=>token }, { :$set=>{ :last_access=>today, :prev_access=>last_access } })
            self.last_access = today
          end
        end

        # Revokes this access token.
        def revoke!
          self.revoked = Time.now.to_i
          AccessToken.collection.update({ :_id=>token }, { :$set=>{ :revoked=>revoked } })
          Client.collection.update({ :_id=>client_id }, { :$inc=>{ :tokens_revoked=>1 } })
        end

        Server.create_indexes do
          # Used to revoke all pending access grants when revoking client.
          collection.create_index [[:client_id, Mongo::ASCENDING]]
          # Used to get/revoke access tokens for an identity, also to find and
          # return existing access token.
          collection.create_index [[:identity, Mongo::ASCENDING]]
        end
      end


###############################################################################################


      # Authorization request. Represents request on behalf of client to access
      # particular scope. Use this to keep state from incoming authorization
      # request to grant/deny redirect.
      class AuthRequest
        class << self
          # Find AuthRequest from identifier.
          def find(request_id)
            id = BSON::ObjectId(request_id.to_s)
            Server.new_instance self, collection.find_one(id)
          rescue BSON::InvalidObjectId
          end

          # Create a new authorization request. This holds state, so in addition
          # to client ID and scope, we need to know the URL to redirect back to
          # and any state value to pass back in that redirect.
          def create(client, scope, redirect_uri, response_type, state)
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            fields = { :client_id=>client.id, :scope=>scope, :redirect_uri=>client.redirect_uri || redirect_uri,
                       :response_type=>response_type, :state=>state,
                       :grant_code=>nil, :authorized_at=>nil,
                       :created_at=>Time.now.to_i, :revoked=>nil }
            fields[:_id] = collection.insert(fields)
            Server.new_instance self, fields
          end

          def collection
            prefix = Server.options[:collection_prefix]
            Server.database["#{prefix}.auth_requests"]
          end
        end

        # Request identifier. We let the database pick this one out.
        attr_reader :_id
        alias :id :_id
        # Client making this request.
        attr_reader :client_id
        # scope of this request: array of names.
        attr_reader :scope
        # Redirect back to this URL.
        attr_reader :redirect_uri
        # Client requested we return state on redirect.
        attr_reader :state
        # Does what it says on the label.
        attr_reader :created_at
        # Response type: either code or token.
        attr_reader :response_type
        # If granted, the access grant code.
        attr_accessor :grant_code
        # If granted, the access token.
        attr_accessor :access_token
        # Keeping track of things.
        attr_accessor :authorized_at
        # Timestamp if revoked.
        attr_accessor :revoked

        # Grant access to the specified identity.
        def grant!(identity, expires_in = nil)
          raise ArgumentError, "Must supply a identity" unless identity
          return if revoked
          client = Client.find(client_id) or return
          self.authorized_at = Time.now.to_i
          if response_type == "code" # Requested authorization code
            access_grant = AccessGrant.create(identity, client, scope, redirect_uri)
            self.grant_code = access_grant.code
            self.class.collection.update({ :_id=>id, :revoked=>nil }, { :$set=>{ :grant_code=>access_grant.code, :authorized_at=>authorized_at } })
          else # Requested access token
            access_token = AccessToken.get_token_for(identity, client, scope, expires_in)
            self.access_token = access_token.token
            self.class.collection.update({ :_id=>id, :revoked=>nil, :access_token=>nil }, { :$set=>{ :access_token=>access_token.token, :authorized_at=>authorized_at } })
          end
          true
        end

        # Deny access.
        def deny!
          self.authorized_at = Time.now.to_i
          self.class.collection.update({ :_id=>id }, { :$set=>{ :authorized_at=>authorized_at } })
        end

        Server.create_indexes do
          # Used to revoke all pending access grants when revoking client.
          collection.create_index [[:client_id, Mongo::ASCENDING]]
        end

      end


###############################################################################################


      # The access grant is a nonce, new grant created each time we need it and
      # good for redeeming one access token.
      class AccessGrant
        class << self
          # Find AccessGrant from authentication code.
          def from_code(code)
            Server.new_instance self, collection.find_one({ :_id=>code, :revoked=>nil })
          end

          # Create a new access grant.
          def create(identity, client, scope, redirect_uri = nil, expires = nil)
            raise ArgumentError, "Identity must be String or Integer" unless String === identity || Integer === identity
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            expires_at = Time.now.to_i + (expires || 300)
            fields = { :_id=>Server.secure_random, :identity=>identity, :scope=>scope,
                       :client_id=>client.id, :redirect_uri=>client.redirect_uri || redirect_uri,
                       :created_at=>Time.now.to_i, :expires_at=>expires_at, :granted_at=>nil,
                       :access_token=>nil, :revoked=>nil }
            collection.insert fields
            Server.new_instance self, fields
          end

          def collection
            prefix = Server.options[:collection_prefix]
            Server.database["#{prefix}.access_grants"]
          end
        end

        # Authorization code. We are nothing without it.
        attr_reader :_id
        alias :code :_id
        # The identity we authorized access to.
        attr_reader :identity
        # Client that was granted this access token.
        attr_reader :client_id
        # Redirect URI for this grant.
        attr_reader :redirect_uri
        # The scope requested in this grant.
        attr_reader :scope
        # Does what it says on the label.
        attr_reader :created_at
        # Tells us when (and if) access token was created.
        attr_accessor :granted_at
        # Tells us when this grant expires.
        attr_accessor :expires_at
        # Access token created from this grant. Set and spent.
        attr_accessor :access_token
        # Timestamp if revoked.
        attr_accessor :revoked

        # Authorize access and return new access token.
        #
        # Access grant can only be redeemed once, but client can make multiple
        # requests to obtain it, so we need to make sure only first request is
        # successful in returning access token, futher requests raise
        # InvalidGrantError.
        def authorize!(expires_in = nil)
          raise InvalidGrantError, "You can't use the same access grant twice" if self.access_token || self.revoked
          client = Client.find(client_id) or raise InvalidGrantError
          access_token = AccessToken.get_token_for(identity, client, scope, expires_in)
          self.access_token = access_token.token
          self.granted_at = Time.now.to_i
          self.class.collection.update({ :_id=>code, :access_token=>nil, :revoked=>nil }, { :$set=>{ :granted_at=>granted_at, :access_token=>access_token.token } }, :safe=>true)
          reload = self.class.collection.find_one({ :_id=>code, :revoked=>nil }, { :fields=>%w{access_token} })
          raise InvalidGrantError unless reload && reload["access_token"] == access_token.token
          return access_token
        end

        def revoke!
          self.revoked = Time.now.to_i
          self.class.collection.update({ :_id=>code, :revoked=>nil }, { :$set=>{ :revoked=>revoked } })
        end

        Server.create_indexes do
          # Used to revoke all pending access grants when revoking client.
          collection.create_index [[:client_id, Mongo::ASCENDING]]
        end
      end


      
    end
  end
end
