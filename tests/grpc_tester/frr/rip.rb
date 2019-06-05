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
require_relative '../../../tests/grpc_tester/frr/northbound'

module GRPC
  module FRR
    class Rip < Northbound
      def initialize(host, options, security = :this_channel_is_insecure)
        @push = "/frr-ripd:ripd"
        super
      end

      def get
        request = Frr::GetRequest.new
        request.type = :STATE
        request.encoding = :JSON
        request.path.push(@push)

        @stub.get(request).each do |r|
          puts "  timestamp: #{r.timestamp} (#{Time.at(r.timestamp).to_datetime})"
          print_datatree(r.data)
        end
      end

      def execute(path)
         request = Frr::ExecuteRequest.new
         request.path = path
         response = @stub.execute(request)
         response.output.each do |o|
           puts "  #{o.path}: #{o.value}"
         end
      end

      def transactions
        response = @stub.list_transactions(Frr::ListTransactionsRequest.new)
        response.map do |t|
          puts "  #{t.id} | #{t.client} | #{t.date} | #{t.comment}"
        end
      end

      def transaction(id)
        req = Frr::GetTransactionRequest.new(transaction_id: id, encoding: :JSON, with_defaults: false)
        response = @stub.get_transaction(req)
        print_datatree(response.config)
      end

      def create_candidate
        response = @stub.create_candidate(Frr::CreateCandidateRequest.new)
        response.candidate_id
      end

      def update_candidate(id)
        begin
          req      = Frr::UpdateCandidateRequest.new(candidate_id: id)
          @stub.update_candidate(req)
        rescue GRPC::NotFound
          puts "Candidate configuration not found"
        end
      end

      def delete_candidate(id)
        begin
          req = Frr::DeleteCandidateRequest.new(candidate_id: id)
          @stub.delete_candidate(req)
        rescue GRPC::NotFound
          puts "Candidate configuration not found"
        end
      end

      def enable_ecmp(candidate_id, vrf="default")
        request = set_request_candidate(candidate_id)
        request.update.push(Frr::PathValue.new(path: "/frr-ripd:ripd/instance[vrf='#{vrf}']/allow-ecmp",
                                               value: "true"))
        edit(request)
      end

      def disable_ecmp(candidate_id, vrf="default")
        request = set_request_candidate(candidate_id)
        request.update.push(Frr::PathValue.new(path: "/frr-ripd:ripd/instance[vrf='#{vrf}']/allow-ecmp",
                                               value: "false"))
        edit(request)
      end

      def explicit_neighbor(candidate_id, neighbor, vrf="default")
        request = set_request_candidate(candidate_id)
        request.update.push(Frr::PathValue.new(path: "/frr-ripd:ripd/instance[vrf='#{vrf}']/explicit-neighbor",
                                               value: neighbor))
        edit(request)
      end

      def load_2_candidate(candidate_id, data, mode)
        request               = Frr::LoadToCandidateRequest.new
        request.candidate_id  = candidate_id
        request.type          = mode

        config                = Frr::DataTree.new
        config.encoding       = :JSON
        config.data           = data.to_json

        request.config = config

        puts request.inspect

        @stub.load_to_candidate(request)
      end

      def commit(candidate_id, comment, phase = :ALL)
        begin
          request              = Frr::CommitRequest.new
          request.candidate_id = candidate_id
          request.phase        = phase
          request.comment      = comment

          response = @stub.commit(request)
          puts "  transaction_id: #{response.transaction_id}"
          response.transaction_id
        rescue GRPC::Aborted
          puts "No configuration changes detected"
        end
      end

      def enable_information_originate(candidate_id, vrf='default')
        request = set_request_candidate(candidate_id)
        request.
            update.
            push(Frr::PathValue.new(path: "/frr-ripd:ripd/instance[vrf='#{vrf}']/default-information-originate",
                                    value: "true"))
        edit(request)
      end

      def disable_information_originate(candidate_id, vrf='default')
        request = set_request_candidate(candidate_id)
        request.
            update.
            push(Frr::PathValue.new(path: "/frr-ripd:ripd/instance[vrf='#{vrf}']/default-information-originate",
                                    value: "false"))
        edit(request)
      end

      def metric(candidate_id, value, vrf='default')
        unless (1..16).include? value.to_i
          raise "Invalid value range. Expected a value between 1 to 255."
        end
        request = set_request_candidate(candidate_id)
        request.update.push(Frr::PathValue.new(path: "/frr-ripd:ripd/instance[vrf='#{vrf}']/default-metric",
                                               value: value.to_s))
        edit(request)
      end

      def distance(candidate_id, value, vrf='default')
        unless (1..255).include? value.to_i
          raise "Invalid value range. Expected a value between 1 to 255."
        end
        request = set_request_candidate(candidate_id)
        request.update.push(Frr::PathValue.new(path: "/frr-ripd:ripd/instance[vrf='#{vrf}']/distance",
                                               value: value.to_s))
        edit(request)
      end

      private

      def edit(request)
        @stub.edit_candidate(request)
      end

      def set_request_candidate(id)
        request = Frr::EditCandidateRequest.new
        request.candidate_id = id
        request
      end
    end

    class RipConfig < Northbound
      def initialize(candidate_id)
        @candidate_id = candidate_id
      end
    end
  end
end
