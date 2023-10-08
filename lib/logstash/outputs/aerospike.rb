# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"

require 'aerospike'

require_relative "util/aerospike_config"

class LogStash::Outputs::Aerospike < LogStash::Outputs::Base

  include Aerospike
  config_name "aerospike"

  #Aerospike server in the form "host:port"
  config :aerospike_server,     :validate => :string,           :default => ""
  #Namespace is a Database name in Aerospike
  config :aerospike_namespace,  :validate => :string,           :default => "malware"
  #Set in Aerospike is similar to table in a relational database.
  config :aerospike_set,        :validate => :string,           :default => "hashScores"
  # Key that is going to be stored
  config :key_field,            :validate => :string,           :default => "[hash]"
  #List of keys to store in Aerospike
  config :list_of_keys,                                                                    :required => true

  concurrency :single

  public
  def register
    # Add instance variables
    begin
      @aerospike_server = AerospikeConfig::servers if @aerospike_server.empty?
      host,port = @aerospike_server.split(":")
      @aerospike = Client.new(Host.new(host, port))

    rescue Aerospike::Exceptions::Aerospike => ex
      @logger.error(ex.message)
    end
  end # def register

  public
  def multi_receive(events)
    events.each do |event|
      begin
        hash = event.get(@key_field)
        key = Key.new(@aerospike_namespace,@aerospike_set,hash)
        bins = []

        @list_of_keys.each do |k|
          v = event.get(k)
          bins.push(Bin.new(k, v))
        end

        @aerospike.put(key,bins,WritePolicy.new) unless bins.empty?

      rescue Aerospike::Exceptions::Aerospike => ex
        @logger.error(ex.message)
      end

    end
  end  # def filter(event)
end # class LogStash::Filters::Aerospike
