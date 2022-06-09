# vmpooler-provider-aws

This is a provider for [VMPooler](https://github.com/puppetlabs/vmpooler) allows using aws to create instances, disks,
snapshots, or destroy instances for specific pools.

## Usage

Include this gem in the same Gemfile that you use to install VMPooler itself and then define one or more pools with the `provider` key set to `aws`. VMPooler will take care of the rest.
See what configuration is needed for this provider in the [example file](https://github.com/puppetlabs/vmpooler-provider-aws/blob/main/vmpooler.yaml.example).

Examples of deploying VMPooler with extra providers can be found in the [puppetlabs/vmpooler-deployment](https://github.com/puppetlabs/vmpooler-deployment) repository.

aws authorization is handled via two required ENV vars

1. ABS_AWS_ACCESS_KEY
2. ABS_AWS_SECRET_KEY

### Provisioning the new nodes

When you add the pool config `provision: true` to a pool, the new VMs will also get initialized with extra steps to setup the sshd config via NET:SSH
These steps expect two environment vars
1. ROOT_KEYS_SCRIPT: (optional) the URI location of a script (eg https in github) that will be run to setup keys. If not set, this will be skipped
2. KEY_FILE_LOCATION: (required) the location on local disk where the ssh key resides for VMPooler to connect via SSH to the AWS node

### DNS
AWS will setup a private ip and private dns hostname for the VM once running. Optionally we can setup a human readable DNS entry to resolve the VMPooler provider `spicy-proton` fqdn

DNS is integrated via Google's CloudDNS service. To enable, a CloudDNS zone name must be provided in the config (see the example yaml file dns_zone_resource_name)

An A record is then created in that zone upon instance creation with the VM's internal IP, and deleted when the instance is destroyed.

### Labels
This provider adds tags to all resources that are managed

|resource|labels|note|
|---|---|---|
|instance|vm=$vm_name, pool=$pool_name|for example vm=foo-bar, pool=pool1|
|disk|vm=$vm_name, pool=$pool_name|for example vm=foo-bar and pool=pool1|
|snapshot|snapshot_name=$snapshot_name, vm=$vm_name, pool=$pool_name| for example snapshot_name=snap1, vm=foo-bar, pool=pool1|

Also see the usage of vmpooler's optional purge_unconfigured_resources, which is used to delete any resource found that
do not have the pool label, and can be configured to allow a specific list of unconfigured pool names. 

### Pre-requisite

- An IAM user must exist in the target AWS account with permissions to create, delete vms etc
- if using DNS, a DNS zone needs to be created in CloudDNS, and configured in the provider's config section with the name of that zone (dns_zone_resource_name). When not specified, the DNS setup and teardown is skipped.


## License

vmpooler-provider-aws is distributed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0.html). See the [LICENSE](LICENSE) file for more details.