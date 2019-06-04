#
# Copyright (c) 2019 Rodrigo Nardi, for NetDEF, Inc.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
require 'grpc'
require 'date'
require 'fileutils'
require 'json'

module GRPC
  module FRR
    class Northbound
      def initialize(host, options, security = :this_channel_is_insecure)
        create_northbound
        require_relative '../../../grpc/ruby/frr-northbound_pb'
        require_relative "../../../grpc/ruby/frr-northbound_services_pb"
        @stub = Frr::Northbound::Stub.new(host, security, options)
      end

      def login_message(message)
        request = Frr::GetRequest.new
        request.type = :STATE
        request.encoding = :JSON
        request.path.push(push)
      end

      def get(push)
        request = Frr::GetRequest.new
        request.type = :STATE
        request.encoding = :JSON
        request.path.push(push)

        @stub.get(request).each do |r|
          puts "  timestamp: #{r.timestamp} (#{Time.at(r.timestamp).to_datetime})"
          print_datatree(r.data)
        end
      end

      def lock_config
        begin
          @stub.lock_config(Frr::LockConfigRequest.new)
        rescue GRPC::FailedPrecondition
          puts "Running configuration is locked already"
        end
      end

      def unlock_config
        begin
          @stub.unlock_config(Frr::UnlockConfigRequest.new)
        rescue GRPC::FailedPrecondition
          puts "Failed to unlock the running configuration"
        end
      end

      private

      #
      # Creates northbound GEM in grpc/ruby and loaded relative from this directory
      #
      def create_northbound
        dir = File.expand_path(File.dirname(__FILE__)) + "/../../../"
        unless File.exist? dir + "grpc/ruby"
          FileUtils.mkdir(dir + "grpc/ruby")
        end
        $LOAD_PATH.unshift(dir + "grpc/ruby") unless $LOAD_PATH.include?(dir + "grpc/ruby")
        %x(cd #{dir + "grpc"}; grpc_tools_ruby_protoc --ruby_out=./ruby --grpc_out=./ruby frr-northbound.proto)
      end

      def print_datatree(dt)
        puts "  encoding: #{dt.encoding}"
        puts dt.inspect
        dt.data.each_line { |line| puts "  #{line}" }
      end
    end
  end
end
