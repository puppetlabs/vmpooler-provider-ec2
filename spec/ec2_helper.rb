# frozen_string_literal: true

# this file is used to Mock the GCE objects, for example the main ComputeService object
MockResult = Struct.new(
  # https://googleapis.dev/ruby/google-api-client/latest/Google/Apis/ComputeV1/Operation.html
  :client_operation_id, :creation_timestamp, :description, :end_time, :error, :http_error_message,
  :http_error_status_code, :id, :insert_time, :kind, :name, :operation_type, :progress, :region,
  :self_link, :start_time, :status, :status_message, :target_id, :target_link, :user, :warnings, :zone,
  keyword_init: true
)

MockOperationError = [].freeze

MockOperationErrorError = Struct.new(
  # https://googleapis.dev/ruby/google-api-client/latest/Google/Apis/ComputeV1/Operation/Error/Error.html
  :code, :location, :message,
  keyword_init: true
)

MockInstance = Struct.new(
  # https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/EC2/Instance.html
  :instance_type, :launch_time, :private_ip_address, :state, :tags, :zone, :private_dns_name,
  keyword_init: true
)

MockTag = Struct.new(
  :key, :value,
  keyword_init: true
)

MockInstanceList = Struct.new(
  # https://googleapis.dev/ruby/google-api-client/latest/Google/Apis/ComputeV1/InstanceList.html
  :id, :items, :kind, :next_page_token, :self_link, :warning,
  keyword_init: true
)

MockDiskList = Struct.new(
  # https://googleapis.dev/ruby/google-api-client/latest/Google/Apis/ComputeV1/DiskList.html
  :id, :items, :kind, :next_page_token, :self_link, :warning,
  keyword_init: true
)

MockDisk = Struct.new(
  # https://googleapis.dev/ruby/google-api-client/latest/Google/Apis/ComputeV1/Disk.html
  :creation_timestamp, :description, :disk_encryption_key, :guest_os_features, :id, :kind, :label_fingerprint, :labels,
  :last_attach_timestamp, :last_detach_timestamp, :license_codes, :licenses, :name, :options,
  :physical_block_size_bytes, :region, :replica_zones, :resource_policies, :self_link, :size_gb, :source_disk,
  :source_disk_id, :source_image, :source_image_encryption_key, :source_image_id, :source_snapshot,
  :source_snapshot_encryption_key, :source_snapshot_id, :status, :type, :users, :zone,
  keyword_init: true
)

MockSnapshotList = Struct.new(
  # https://googleapis.dev/ruby/google-api-client/latest/Google/Apis/ComputeV1/DiskList.html
  :id, :items, :kind, :next_page_token, :self_link, :warning,
  keyword_init: true
)

MockSnapshot = Struct.new(
  # https://googleapis.dev/ruby/google-api-client/latest/Google/Apis/ComputeV1/Snapshot.html
  :auto_created, :chain_name, :creation_timestamp, :description, :disk_size_gb, :download_bytes, :id, :kind,
  :label_fingerprint, :labels, :license_codes, :licenses, :name, :self_link, :snapshot_encryption_key, :source_disk,
  :source_disk_encryption_key, :source_disk_id, :status, :storage_bytes, :storage_bytes_status, :storage_locations,
  keyword_init: true
)

MockAttachedDisk = Struct.new(
  # https://googleapis.dev/ruby/google-api-client/latest/Google/Apis/ComputeV1/AttachedDisk.html
  :auto_delete, :boot, :device_name, :disk_encryption_key, :disk_size_gb, :guest_os_features, :index,
  :initialize_params, :interface, :kind, :licenses, :mode, :shielded_instance_initial_state, :source, :type,
  keyword_init: true
)

# --------------------
# Main ComputeService Object
# --------------------
MockComputeServiceConnection = Struct.new(
  # https://googleapis.dev/ruby/google-api-client/latest/Google/Apis/ComputeV1/ComputeService.html
  :key, :quota_user, :user_ip
) do
  # Onlly methods we use are listed here
  def get_instance
    MockInstance.new
  end

  # Alias to serviceContent.propertyCollector
  def insert_instance
    MockResult.new
  end
end

# -------------------------------------------------------------------------------------------------------------
# Mocking Methods
# -------------------------------------------------------------------------------------------------------------

# def mock_RbVmomi_VIM_ClusterComputeResource(options = {})
#   options[:name]  = 'Cluster' + rand(65536).to_s if options[:name].nil?
#
#   mock = MockClusterComputeResource.new()
#
#   mock.name = options[:name]
#   # All cluster compute resources have a root Resource Pool
#   mock.resourcePool = mock_RbVmomi_VIM_ResourcePool({:name => options[:name]})
#
#   allow(mock).to receive(:is_a?) do |expected_type|
#     expected_type == RbVmomi::VIM::ClusterComputeResource
#   end
#
#   mock
# end
