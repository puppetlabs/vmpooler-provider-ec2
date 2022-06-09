# vmpooler-provider-gce

This is a provider for [VMPooler](https://github.com/puppetlabs/vmpooler) allows using GCE to create instances, disks,
snapshots, or destroy instances for specific pools.

## Usage

Include this gem in the same Gemfile that you use to install VMPooler itself and then define one or more pools with the `provider` key set to `gce`. VMPooler will take care of the rest.
See what configuration is needed for this provider in the [example file](https://github.com/puppetlabs/vmpooler-provider-gce/blob/main/vmpooler.yaml.example).

Examples of deploying VMPooler with extra providers can be found in the [puppetlabs/vmpooler-deployment](https://github.com/puppetlabs/vmpooler-deployment) repository.

GCE authorization is handled via a service account (or personal account) private key (json format) and can be configured via

1. GOOGLE_APPLICATION_CREDENTIALS environment variable eg GOOGLE_APPLICATION_CREDENTIALS=/my/home/directory/my_account_key.json

### DNS
DNS is integrated via Google's CloudDNS service. To enable, a CloudDNS zone name must be provided in the config (see the example yaml file dns_zone_resource_name)

An A record is then created in that zone upon instance creation with the VM's internal IP, and deleted when the instance is destroyed.

### Labels
This provider adds labels to all resources that are managed

|resource|labels|note|
|---|---|---|
|instance|vm=$vm_name, pool=$pool_name|for example vm=foo-bar, pool=pool1|
|disk|vm=$vm_name, pool=$pool_name|for example vm=foo-bar and pool=pool1|
|snapshot|snapshot_name=$snapshot_name, vm=$vm_name, pool=$pool_name| for example snapshot_name=snap1, vm=foo-bar, pool=pool1|

Also see the usage of vmpooler's optional purge_unconfigured_resources, which is used to delete any resource found that
do not have the pool label, and can be configured to allow a specific list of unconfigured pool names. 

### Pre-requisite

- A service account needs to be created and a private json key generated (see usage section)
- The service account needs to be given permissions to the project (broad permissions would be compute v1 admin and dns admin). A yaml file is provided that lists the least-privilege permissions needed
- if using DNS, a DNS zone needs to be created in CloudDNS, and configured in the provider's config section with the name of that zone (dns_zone_resource_name). When not specified, the DNS setup and teardown is skipped.


## License

vmpooler-provider-gce is distributed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0.html). See the [LICENSE](LICENSE) file for more details.